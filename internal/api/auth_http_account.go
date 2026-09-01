package api

// The self-service account surface: profile, password, credentials, linked
// identities, backup codes, sessions, and deletion. Shapes mirror kagi's
// /auth/account/* contract the UI consumes.

import (
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/storage"
)

// identityMethods are the external identities the account surface manages.
var identityMethods = []iam.Method{iam.MethodOIDC, iam.MethodOAuth2, iam.MethodSAML}

// accountSession is one live session of the account. ID is the hex token
// hash, the value sessions/remove takes.
type accountSession struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Method     string     `json:"method"`
	Binding    string     `json:"binding,omitempty"`
	Current    bool       `json:"current"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	LastSeenAt *time.Time `json:"lastSeenAt,omitempty"`
}

// principal returns the signed-in user principal of the request.
func (a *authAPI) principal(r *http.Request) iam.Principal {
	p, _ := iam.PrincipalFromContext(r.Context())
	return p
}

func (a *authAPI) getAccount(w http.ResponseWriter, r *http.Request) {
	u, err := a.cfg.IAM.GetUser(r.Context(), a.principal(r).ID)
	if err != nil {
		iam.WriteError(w, http.StatusNotFound, "not_found", "account not found")
		return
	}
	iam.WriteJSON(w, http.StatusOK, u)
}

type updateAccountRequest struct {
	DisplayName          *string `json:"displayName"`
	Picture              *string `json:"picture"`
	DisablePasswordReset *bool   `json:"disablePasswordReset"`
}

func (a *authAPI) updateAccount(w http.ResponseWriter, r *http.Request) {
	var req updateAccountRequest
	if err := iam.ReadJSON(r, &req); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	if req.DisplayName != nil && len(*req.DisplayName) > maxNameLength {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}

	u, err := a.cfg.IAM.UpdateUser(r.Context(), a.principal(r).ID, iam.UpdateUserPatch{
		Name:                 req.DisplayName,
		Picture:              req.Picture,
		DisablePasswordReset: req.DisablePasswordReset,
	})
	if err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	iam.WriteJSON(w, http.StatusOK, u)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (a *authAPI) changePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := iam.ReadJSON(r, &req); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	if len(req.NewPassword) < 8 || len(req.NewPassword) > maxPasswordLength {
		iam.WriteError(
			w,
			http.StatusBadRequest,
			"password_too_short",
			"password must be at least 8 characters",
		)
		return
	}

	p := a.principal(r)
	// A passwordless account sets its first password without a current-
	// password check; with a password present, the check is mandatory.
	has, err := a.cfg.IAM.Password.HasPassword(r.Context(), p.ID)
	if err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	if has {
		if err := a.cfg.IAM.Password.CheckPassword(
			r.Context(),
			p.ID,
			req.CurrentPassword,
		); err != nil {
			iam.WriteError(
				w,
				http.StatusBadRequest,
				"bad_credentials",
				"current password is incorrect",
			)
			return
		}
	}

	// Replace the hash and revoke the other sessions: the current session
	// survives a deliberate password change, everything else dies (NIST
	// 800-63B).
	if err := a.cfg.IAM.Password.Store(r.Context(), p.ID, req.NewPassword); err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	current, _ := iam.CurrentSession(r.Context())
	_, _ = a.cfg.IAM.Sessions.RevokeOtherSessions(
		r.Context(),
		p.ID,
		iam.SessionHash(current.TokenHash),
	)
	iam.WriteOK(w)
}

func (a *authAPI) removePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := iam.ReadJSON(r, &req); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}

	p := a.principal(r)
	if err := a.cfg.IAM.Password.CheckPassword(r.Context(), p.ID, req.CurrentPassword); err != nil {
		iam.WriteError(w, http.StatusBadRequest, "bad_credentials", "current password is incorrect")
		return
	}
	// Removing the password must leave the account reachable: a passkey or a
	// linked identity has to remain.
	if !a.requireRemovable(w, r, p.ID, iam.MethodPassword) {
		return
	}
	if err := a.cfg.IAM.Password.DeletePassword(r.Context(), p.ID); err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	iam.WriteOK(w)
}

// requireRemovable reports whether removing one login method keeps the
// account reachable: a password needs a passkey or an identity left, a
// passkey needs a password or an identity. Backup codes are recovery, not a
// way in, and never satisfy it.
func (a *authAPI) requireRemovable(
	w http.ResponseWriter,
	r *http.Request,
	userID string,
	rm iam.Method,
) bool {
	has := func(m iam.Method) bool {
		creds, err := a.cfg.IAM.ListCredentialsByType(r.Context(), userID, m)
		return err == nil && len(creds) > 0
	}
	hasIdentity := func() bool {
		return slices.ContainsFunc(identityMethods, has)
	}

	var ok bool
	switch rm {
	case iam.MethodPassword:
		ok = has(iam.MethodPasskey) || hasIdentity()
	case iam.MethodPasskey:
		ok = has(iam.MethodPassword) || hasIdentity()
	case iam.MethodOIDC, iam.MethodOAuth2, iam.MethodSAML, iam.MethodBackupCode, iam.MethodDevice:
		ok = has(iam.MethodPassword) || has(iam.MethodPasskey)
	default:
		ok = has(iam.MethodPassword) || has(iam.MethodPasskey)
	}
	if !ok {
		iam.WriteError(
			w,
			http.StatusPreconditionFailed,
			"last_login_method",
			"add another login method before removing this one",
		)
		return false
	}
	return true
}

func (a *authAPI) getCredentials(w http.ResponseWriter, r *http.Request) {
	types := append(
		[]iam.Method{iam.MethodPassword, iam.MethodPasskey, iam.MethodBackupCode},
		identityMethods...)
	out := []db.Credential{}
	for _, typ := range types {
		creds, err := a.cfg.IAM.ListCredentialsByType(r.Context(), a.principal(r).ID, typ)
		if err != nil {
			iam.WriteError(
				w,
				http.StatusInternalServerError,
				"internal_error",
				"something went wrong",
			)
			return
		}
		for _, c := range creds {
			out = append(out, db.Credential{
				ID:        c.ID,
				Type:      c.Type,
				Provider:  c.Provider,
				Subject:   c.Subject,
				Label:     c.Label,
				CreatedAt: c.CreatedAt,
			})
		}
	}
	iam.WriteJSON(w, http.StatusOK, map[string]any{"credentials": out})
}

type renameCredentialRequest struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

func (a *authAPI) renameCredential(w http.ResponseWriter, r *http.Request) {
	var req renameCredentialRequest
	if err := iam.ReadJSON(r, &req); err != nil || req.ID == "" || len(req.Label) > maxNameLength {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	err := a.cfg.IAM.RenameCredential(r.Context(), a.principal(r).ID, req.ID, req.Label)
	if err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	iam.WriteOK(w)
}

type removeCredentialRequest struct {
	ID string `json:"id"`
}

func (a *authAPI) removeCredential(w http.ResponseWriter, r *http.Request) {
	var req removeCredentialRequest
	if err := iam.ReadJSON(r, &req); err != nil || req.ID == "" {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	p := a.principal(r)

	cred, err := a.cfg.IAM.GetCredential(r.Context(), p.ID, req.ID)
	if err != nil {
		iam.WriteError(w, http.StatusNotFound, "not_found", "credential not found")
		return
	}
	// Passkeys need a fallback way in; the password and backup codes have
	// their own endpoints.
	if iam.Method(cred.Type) == iam.MethodPasskey {
		if !a.requireRemovable(w, r, p.ID, iam.MethodPasskey) {
			return
		}
	}
	if err := a.cfg.IAM.DeleteCredential(r.Context(), p.ID, req.ID); err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	iam.WriteOK(w)
}

type removeIdentityRequest struct {
	Provider string `json:"provider"`
}

func (a *authAPI) removeIdentity(w http.ResponseWriter, r *http.Request) {
	var req removeIdentityRequest
	if err := iam.ReadJSON(r, &req); err != nil || req.Provider == "" {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	p := a.principal(r)
	if !a.requireRemovable(w, r, p.ID, iam.MethodOAuth2) {
		return
	}
	for _, m := range identityMethods {
		if _, err := a.cfg.IAM.DeleteCredentialsByProvider(
			r.Context(),
			p.ID,
			m,
			req.Provider,
		); err != nil {
			iam.WriteError(
				w,
				http.StatusInternalServerError,
				"internal_error",
				"something went wrong",
			)
			return
		}
	}
	iam.WriteOK(w)
}

func (a *authAPI) listBackupCodes(w http.ResponseWriter, r *http.Request) {
	creds, err := a.cfg.IAM.ListBackupCodes(r.Context(), a.principal(r).ID)
	if err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	codes := []db.Credential{}
	for _, c := range creds {
		codes = append(codes, db.Credential{ID: c.ID, Type: c.Type, CreatedAt: c.CreatedAt})
	}
	iam.WriteJSON(w, http.StatusOK, map[string]any{"codes": codes})
}

func (a *authAPI) rotateBackupCodes(w http.ResponseWriter, r *http.Request) {
	codes, err := a.cfg.IAM.RotateBackupCodes(r.Context(), a.principal(r).ID)
	if err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	iam.WriteJSON(w, http.StatusOK, map[string]any{"codes": codes})
}

func (a *authAPI) removeBackupCodes(w http.ResponseWriter, r *http.Request) {
	if err := a.cfg.IAM.DeleteBackupCodes(r.Context(), a.principal(r).ID); err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	iam.WriteOK(w)
}

func (a *authAPI) listSessions(w http.ResponseWriter, r *http.Request) {
	p := a.principal(r)
	current, _ := iam.CurrentSession(r.Context())
	sessions, err := a.cfg.IAM.Sessions.List(r.Context(), p.ID)
	if err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	out := []accountSession{}
	for _, s := range sessions {
		out = append(out, accountSession{
			ID:         string(s.TokenHash),
			Kind:       s.Kind,
			Method:     s.Method,
			Binding:    s.Binding,
			Current:    s.TokenHash == current.TokenHash,
			ExpiresAt:  s.ExpiresAt,
			LastSeenAt: s.LastSeenAt,
		})
	}
	iam.WriteJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

type removeSessionRequest struct {
	ID string `json:"id"`
}

func (a *authAPI) removeSession(w http.ResponseWriter, r *http.Request) {
	var req removeSessionRequest
	if err := iam.ReadJSON(r, &req); err != nil || req.ID == "" {
		iam.WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	current, _ := iam.CurrentSession(r.Context())
	if req.ID == string(current.TokenHash) {
		iam.WriteError(
			w,
			http.StatusConflict,
			"current_session",
			"use logout to end the current session",
		)
		return
	}
	if err := a.cfg.IAM.Sessions.DeleteSessionByHash(
		r.Context(),
		iam.SessionHash(req.ID),
	); err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	iam.WriteOK(w)
}

func (a *authAPI) deleteAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := a.principal(r)
	u, err := a.cfg.IAM.GetUser(ctx, p.ID)
	if err != nil {
		iam.WriteError(w, http.StatusNotFound, "not_found", "account not found")
		return
	}

	if err := a.cfg.Storage.Delete(ctx, storage.AvatarPath(u.ID)); err != nil {
		slog.Warn("failed to delete avatar", "error", err)
	}

	if err := a.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		workspaceIDs, err := q.GetWorkspacesByOwner(ctx, u.ID)
		if err != nil {
			return err
		}
		for _, workspaceID := range workspaceIDs {
			if !a.cfg.Billing.Enabled() {
				break
			}
			if err := a.cfg.Billing.Cancel(ctx, workspaceID, true, ""); err != nil {
				slog.Warn("failed to cancel subscription", "error", err)
			}
		}
		return q.DeleteWorkspacesByOwner(ctx, u.ID)
	}); err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}

	if err := a.cfg.IAM.DeleteUser(ctx, u.ID); err != nil {
		iam.WriteError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
		return
	}
	http.SetCookie(w, a.cfg.IAM.ClearSessionCookie())
	iam.WriteOK(w)
}

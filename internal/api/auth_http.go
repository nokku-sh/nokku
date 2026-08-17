package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
	"github.com/nokku-sh/nokku/internal/meta"
)

// oneTimeTokenTTL is how long email verification and reset links stay valid.
const oneTimeTokenTTL = 15 * time.Minute

// Auth HTTP handlers ---------------------------------------------------------
//
// Credential flows (password/backup-code login, registration, logout, and the
// email verification/reset round trips) are plain HTTP handlers, not
// connectrpc RPCs. They set a cookie on the response and read the session from
// the request, which kagi's SessionManager already models over [net/http];
// the connectrpc adapter adds nothing but glue here.

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type backupCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type registerRequest struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type emailRequest struct {
	Email string `json:"email"`
}

type tokenRequest struct {
	Token string `json:"token"`
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "please check your input and try again")
		return
	}
	ctx := r.Context()
	meta.SetAuditEmail(ctx, req.Email)

	user, err := s.cfg.Conn.Q.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil || !user.IsActive || !user.EmailVerified {
		writeAuthError(w, ErrBadCredentials)
		return
	}
	if err := checkSSOEnforced(ctx, s.cfg, req.Email); err != nil {
		writeAuthError(w, err)
		return
	}
	if err := s.cfg.Auth.Passwords.CheckPassword(ctx, "", user.ID, req.Password); err != nil {
		writeAuthError(w, ErrBadCredentials)
		return
	}
	if err := s.issueSession(w, r, user, kagi.MethodPassword); err != nil {
		writeAuthError(w, ErrInternal)
		return
	}
	meta.SetAuditUserID(ctx, user.ID)
	writeJSONOK(w)
}

func (s *Server) handleLoginWithBackupCode(w http.ResponseWriter, r *http.Request) {
	var req backupCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "please check your input and try again")
		return
	}
	ctx := r.Context()
	meta.SetAuditEmail(ctx, req.Email)

	user, err := s.cfg.Conn.Q.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil || !user.IsActive || !user.EmailVerified {
		writeAuthError(w, ErrBadCredentials)
		return
	}
	if err := checkSSOEnforced(ctx, s.cfg, req.Email); err != nil {
		writeAuthError(w, err)
		return
	}
	if _, err := s.cfg.Auth.BackupCodes.Consume(ctx, "", user.ID, req.Code); err != nil {
		writeAuthError(w, ErrBadCredentials)
		return
	}
	if err := s.issueSession(w, r, user, kagi.MethodBackupCode); err != nil {
		writeAuthError(w, ErrInternal)
		return
	}
	meta.SetAuditUserID(ctx, user.ID)
	writeJSONOK(w)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "please check your input and try again")
		return
	}
	ctx := r.Context()
	meta.SetAuditEmail(ctx, req.Email)

	if req.Email == "" || req.Password == "" {
		writeAuthError(w, ErrFieldMissing)
		return
	}
	if len(req.Password) < 8 {
		writeAuthError(w, ErrPasswordShort)
		return
	}
	if err := email.Verify(req.Email); err != nil {
		writeAuthError(w, ErrEmailInvalid)
		return
	}
	if err := checkSSOEnforced(ctx, s.cfg, req.Email); err != nil {
		writeAuthError(w, err)
		return
	}

	found, err := s.cfg.Conn.Q.EmailExists(ctx, req.Email)
	if err != nil {
		writeAuthError(w, ErrInternal)
		return
	}
	if found {
		writeAuthError(w, ErrEmailTaken)
		return
	}

	name := req.Name
	if name == "" {
		name = auth.UsernameFromEmail(req.Email)
	}
	user, err := s.cfg.Auth.Passwords.Register(ctx, "", req.Email, name, req.Password)
	if err != nil {
		writeAuthError(w, ErrInternal)
		return
	}

	token, err := s.cfg.Auth.Tokens.Issue(ctx, user.ID, auth.PurposeVerify)
	if err != nil {
		writeAuthError(w, ErrInternal)
		return
	}
	verifyURL := s.cfg.FullURL() + "/verify?token=" + token
	if err := s.cfg.Email.SendWelcomeEmail(
		ctx, user.ID, user.Email, auth.UsernameFromEmail(user.Email), verifyURL,
		oneTimeTokenTTL.String(),
	); err != nil {
		slog.Error("failed to send welcome email", "error", err)
	}
	meta.SetAuditUserID(ctx, user.ID)
	writeJSONOK(w)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.cfg.Auth.Kagi.Sessions.ClearSession(r.Context(), w, r)
	writeJSONOK(w)
}

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req emailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "please check your input and try again")
		return
	}
	ctx := r.Context()
	meta.SetAuditEmail(ctx, req.Email)

	user, err := s.cfg.Conn.Q.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil || !user.EnableEmailRecovery {
		writeJSONOK(w)
		return
	}

	token, err := s.cfg.Auth.Tokens.Issue(ctx, user.ID, auth.PurposeReset)
	if err != nil {
		writeAuthError(w, ErrInternal)
		return
	}
	recoveryURL := s.cfg.FullURL() + "/reset?token=" + token
	if err := s.cfg.Email.SendRecoveryEmail(
		ctx, user.ID, user.Email, recoveryURL, oneTimeTokenTTL.String(),
	); err != nil {
		slog.Error("failed to send recovery email", "error", err)
	}
	writeJSONOK(w)
}

func (s *Server) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	var req emailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "please check your input and try again")
		return
	}
	ctx := r.Context()
	meta.SetAuditEmail(ctx, req.Email)

	user, err := s.cfg.Conn.Q.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		writeJSONOK(w)
		return
	}

	token, err := s.cfg.Auth.Tokens.Issue(ctx, user.ID, auth.PurposeVerify)
	if err != nil {
		writeAuthError(w, ErrInternal)
		return
	}
	verifyURL := s.cfg.FullURL() + "/verify?token=" + token
	if err := s.cfg.Email.SendVerificationEmail(
		ctx, user.ID, user.Email, verifyURL, oneTimeTokenTTL.String(),
	); err != nil {
		slog.Error("failed to send verification email", "error", err)
	}
	writeJSONOK(w)
}

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "please check your input and try again")
		return
	}
	ctx := r.Context()

	userID, purpose, err := s.cfg.Auth.Tokens.Consume(ctx, req.Token)
	if err != nil || purpose != auth.PurposeVerify {
		writeAuthError(w, ErrTokenInvalid)
		return
	}
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, userID)
	if err != nil {
		writeAuthError(w, ErrInternal)
		return
	}
	if err := s.cfg.Conn.Q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
		UserID: userID,
		Email:  user.Email,
	}); err != nil {
		writeAuthError(w, ErrInternal)
		return
	}
	meta.SetAuditUserID(ctx, userID)
	meta.SetAuditEmail(ctx, user.Email)
	writeJSONOK(w)
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "please check your input and try again")
		return
	}
	ctx := r.Context()

	userID, purpose, err := s.cfg.Auth.Tokens.Consume(ctx, req.Token)
	if err != nil || purpose != auth.PurposeReset {
		writeAuthError(w, ErrTokenInvalid)
		return
	}
	if err := s.cfg.Auth.Passwords.SetPassword(ctx, "", userID, req.NewPassword); err != nil {
		writeAuthError(w, ErrInternal)
		return
	}
	// A password change revokes every session for the subject.
	_ = s.cfg.Auth.Kagi.RevokeSubjectSessions(ctx, "", userID)
	meta.SetAuditUserID(ctx, userID)
	writeJSONOK(w)
}

// issueSession issues a kagi session for the user and sets the session cookie.
func (s *Server) issueSession(
	w http.ResponseWriter,
	r *http.Request,
	user *db.User,
	method kagi.Method,
) error {
	_, err := s.cfg.Auth.Kagi.Sessions.Issue(
		r.Context(),
		w,
		"",
		kagi.User{ID: user.ID, Email: user.Email, DisplayName: user.Name},
		method,
	)
	return err
}

func writeAuthError(w http.ResponseWriter, err error) {
	writeJSONError(w, connectCodeToHTTP(connect.CodeOf(err)), err.Error())
}

func writeJSONOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// _ = json.NewEncoder(w).Encode(v)
}

// connectCodeToHTTP maps a connect code to the HTTP status the frontend's
// error parser recognizes (see httpStatusToCode in web/ui).
func connectCodeToHTTP(code connect.Code) int {
	//nolint:exhaustive // only need some partial codes
	switch code {
	case connect.CodeCanceled:
		return 499
	case connect.CodeInvalidArgument:
		return http.StatusBadRequest
	case connect.CodeNotFound:
		return http.StatusNotFound
	case connect.CodeAlreadyExists, connect.CodeAborted:
		return http.StatusConflict
	case connect.CodePermissionDenied:
		return http.StatusForbidden
	case connect.CodeResourceExhausted:
		return http.StatusTooManyRequests
	case connect.CodeFailedPrecondition:
		return http.StatusPreconditionFailed
	case connect.CodeUnimplemented:
		return http.StatusNotImplemented
	case connect.CodeUnavailable:
		return http.StatusServiceUnavailable
	case connect.CodeUnauthenticated:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

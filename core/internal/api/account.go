package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"

	"connectrpc.com/connect"

	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

type accountService struct {
	cfg *config.Config
}

func (s *accountService) GetAccount(
	ctx context.Context,
	_ *nokkuv1.GetAccountRequest,
) (*nokkuv1.GetAccountResponse, error) {
	u, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, errAccountNotFound
	}
	user := u.ToProto()
	if pending := s.cfg.IAM.PendingEmail(ctx, u.ID); pending != "" {
		user.PendingEmail = &pending
	}
	return &nokkuv1.GetAccountResponse{User: user}, nil
}

func (s *accountService) UpdateAccount(
	ctx context.Context,
	req *nokkuv1.UpdateAccountRequest,
) (*nokkuv1.UpdateAccountResponse, error) {
	u, err := s.cfg.IAM.UpdateSelf(ctx, req.Name)
	if err != nil {
		return nil, errInternal
	}
	return &nokkuv1.UpdateAccountResponse{User: u.ToProto()}, nil
}

// SetAvatar keeps the picture in the database and points users.picture at it, by a URL that changes with it.
func (s *accountService) SetAvatar(
	ctx context.Context,
	req *nokkuv1.SetAvatarRequest,
) (*nokkuv1.SetAvatarResponse, error) {
	userID := actor.UserIDFromContext(ctx)
	var image []byte
	var etag, picture string
	if len(req.GetImage()) > 0 {
		var err error
		if image, err = avatarJPEG(req.GetImage()); err != nil {
			return nil, newError(connect.CodeInvalidArgument, err.Error())
		}
		sum := sha256.Sum256(image)
		etag = hex.EncodeToString(sum[:8])
		picture = "/avatars/" + userID + "?v=" + etag
	}

	var u *db.User
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if image == nil {
			err = q.DeleteAvatar(ctx, userID)
		} else {
			err = q.PutAvatar(ctx, &db.PutAvatarParams{UserID: userID, Image: image, Etag: etag})
		}
		if err != nil {
			return err
		}
		u, err = q.UpdateUser(ctx, &db.UpdateUserParams{ID: userID, Picture: &picture})
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.SetAvatarResponse{User: u.ToProto()}, nil
}

// RequestEmailChange mails the confirm link to the new address and a cancel link to the current one.
func (s *accountService) RequestEmailChange(
	ctx context.Context,
	req *nokkuv1.RequestEmailChangeRequest,
) (*nokkuv1.RequestEmailChangeResponse, error) {
	u, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, errAccountNotFound
	}
	if err := s.cfg.IAM.RequireRecentSignIn(ctx); err != nil {
		// The web app reads Unauthenticated as a session to sign in again, and comes back here after.
		if ci, ok := connect.CallInfoForHandlerContext(ctx); ok {
			setCookie(ci, s.cfg.IAM.ClearSessionCookie())
		}
		return nil, newError(connect.CodeUnauthenticated, "sign in again to change your email")
	}
	if !s.cfg.Email.HasSMTP() {
		return nil, newError(connect.CodeUnimplemented, "this server sends no mail, ask your administrator")
	}
	// Asked first, a refused request must not replace the pending change.
	if s.cfg.Email.EmailChangeOnCooldown(u.ID) {
		return nil, newError(connect.CodeResourceExhausted, "you asked for a change a moment ago, try again later")
	}
	confirm, cancel, err := s.cfg.IAM.RequestEmailChange(ctx, u, req.GetNewEmail())
	switch {
	case errors.Is(err, iam.ErrSameEmail):
		return nil, newError(connect.CodeInvalidArgument, "this is already your email address")
	case errors.Is(err, iam.ErrEmailTaken):
		return nil, newError(connect.CodeAlreadyExists, "an account with this email already exists")
	case errors.Is(err, iam.ErrEmailRejected):
		return nil, newError(connect.CodeInvalidArgument, "please enter a valid email address")
	case errors.Is(err, iam.ErrManagedAccount):
		return nil, errEmailManaged
	case err != nil:
		return nil, errInternal
	}

	ws, _ := actor.WorkspaceFromContext(ctx)
	base := ws.BaseURL + "/email-change?"
	newEmail := strings.ToLower(strings.TrimSpace(req.GetNewEmail()))
	err = s.cfg.Email.SendEmailChangeConfirm(ctx, u.ID, newEmail, base+"token="+confirm, iam.EmailChangeTTL)
	if err == nil {
		err = s.cfg.Email.SendEmailChangeNotice(
			ctx,
			u.ID,
			u.Email,
			newEmail,
			base+"cancel=1&token="+cancel,
			iam.EmailRevertTTL,
		)
	}
	if err != nil {
		// Without both mails the change must not stay pending.
		slog.Error("send email change mails", "error", err)
		_ = s.cfg.IAM.DropEmailChange(ctx, u.ID)
		return nil, errMailNotSent
	}
	return &nokkuv1.RequestEmailChangeResponse{}, nil
}

func (s *accountService) ListCredentials(
	ctx context.Context,
	_ *nokkuv1.ListCredentialsRequest,
) (*nokkuv1.ListCredentialsResponse, error) {
	creds, err := s.cfg.IAM.ListCredentials(ctx)
	if err != nil {
		return nil, errInternal
	}
	credentials := make([]*nokkuv1.AccountCredential, 0, len(creds))
	for _, c := range creds {
		credentials = append(credentials, c.ToProto())
	}
	return &nokkuv1.ListCredentialsResponse{Credentials: credentials}, nil
}

func (s *accountService) RenameCredential(
	ctx context.Context,
	req *nokkuv1.RenameCredentialRequest,
) (*nokkuv1.RenameCredentialResponse, error) {
	if err := s.cfg.IAM.RenameCredential(ctx, req.GetId(), req.GetLabel()); err != nil {
		return nil, errInternal
	}
	return &nokkuv1.RenameCredentialResponse{}, nil
}

func (s *accountService) RemoveCredential(
	ctx context.Context,
	req *nokkuv1.RemoveCredentialRequest,
) (*nokkuv1.RemoveCredentialResponse, error) {
	err := s.cfg.IAM.DeleteCredential(ctx, req.GetId())
	switch {
	case errors.Is(err, iam.ErrNotFound):
		return nil, errNotFound
	case errors.Is(err, iam.ErrLastCredential):
		return nil, errLastLoginMethod
	case err != nil:
		return nil, errInternal
	}
	return &nokkuv1.RemoveCredentialResponse{}, nil
}

func (s *accountService) ListAccountSessions(
	ctx context.Context,
	_ *nokkuv1.ListAccountSessionsRequest,
) (*nokkuv1.ListAccountSessionsResponse, error) {
	current, _ := iam.CurrentToken(ctx)
	sessions, err := s.cfg.IAM.ListSessions(ctx)
	if err != nil {
		return nil, errInternal
	}
	out := make([]*nokkuv1.AccountSession, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, &nokkuv1.AccountSession{
			Id:         new(sess.ID),
			Kind:       new(sess.Kind),
			Method:     new(sess.Method),
			Binding:    new(sess.Binding),
			Current:    new(sess.ID == current.ID),
			ExpiresAt:  db.SafeTimestamp(sess.ExpiresAt),
			LastSeenAt: db.SafeTimestamp(sess.LastSeenAt),
			UserAgent:  new(sess.UserAgent),
			Ip:         new(sess.Ip),
		})
	}
	// The list also shows where the account is remembered. Those rows are no sessions.
	devices, err := s.cfg.IAM.ListDevices(ctx)
	if err != nil {
		return nil, errInternal
	}
	for _, d := range devices {
		out = append(out, &nokkuv1.AccountSession{
			Id:         new(d.ID),
			Kind:       new("device"),
			Method:     new(string(iam.MethodDevice)),
			Binding:    new(""),
			Current:    new(false),
			ExpiresAt:  timestamppb.New(d.ExpiresAt),
			LastSeenAt: timestamppb.New(d.LastSeenAt),
			UserAgent:  new(d.UserAgent),
			Ip:         new(d.Ip),
		})
	}
	return &nokkuv1.ListAccountSessionsResponse{Sessions: out}, nil
}

func (s *accountService) RemoveSession(
	ctx context.Context,
	req *nokkuv1.RemoveSessionRequest,
) (*nokkuv1.RemoveSessionResponse, error) {
	current, _ := iam.CurrentToken(ctx)
	if req.GetId() == current.ID {
		return nil, errCurrentSession
	}
	// The id names a session or a remembered device, the list mixes both.
	if err := s.cfg.IAM.DeleteOwnSession(ctx, req.GetId()); err != nil {
		return nil, errInternal
	}
	if err := s.cfg.IAM.ForgetDevice(ctx, req.GetId()); err != nil {
		return nil, errInternal
	}
	return &nokkuv1.RemoveSessionResponse{}, nil
}

// DeleteAccount is refused for the owner, who hands the workspace on first.
func (s *accountService) DeleteAccount(
	ctx context.Context,
	_ *nokkuv1.DeleteAccountRequest,
) (*nokkuv1.DeleteAccountResponse, error) {
	err := s.cfg.IAM.DeleteSelf(ctx)
	switch {
	case errors.Is(err, iam.ErrOwner):
		return nil, errOwnerAccount
	case errors.Is(err, iam.ErrNotFound):
		return nil, errAccountNotFound
	case err != nil:
		return nil, errInternal
	}
	// The session cookie is HttpOnly, only a server response can clear it.
	if ci, ok := connect.CallInfoForHandlerContext(ctx); ok {
		setCookie(ci, s.cfg.IAM.ClearSessionCookie())
	}
	return &nokkuv1.DeleteAccountResponse{}, nil
}

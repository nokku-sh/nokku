package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/ssh"
	"github.com/nokku-sh/nokku/core/internal/tenant"
)

var (
	errInternal = connect.NewError(
		connect.CodeInternal,
		"something went wrong, please try again",
	)
	errNotFound = connect.NewError(
		connect.CodeNotFound,
		"the requested resource was not found",
	)
	errTimeout = connect.NewError(
		connect.CodeDeadlineExceeded,
		"the request took too long, please try again",
	)
	errPermissionDenied = connect.NewError(
		connect.CodePermissionDenied,
		"you don't have permission to do that",
	)
	errInviteInvalid = connect.NewError(
		connect.CodeFailedPrecondition,
		"invalid or expired invitation",
	)
	errInvalidInput = connect.NewError(
		connect.CodeInvalidArgument,
		"please check your input and try again",
	)
	errInvalidValue = connect.NewError(
		connect.CodeInvalidArgument,
		"a value is missing, too long or not valid",
	)
	errSingleWorkspace = connect.NewError(
		connect.CodeFailedPrecondition,
		"a self-hosted server keeps its workspace",
	)
)

// errTooManyUploads is not ResourceExhausted, a daemon waits an hour on that.
var errTooManyUploads = connect.NewError(
	connect.CodeUnavailable,
	"the core is holding too many recording uploads, try again",
)

// errRecordingStorageFull is not InvalidArgument, a daemon gives up on that.
var errRecordingStorageFull = connect.NewError(
	connect.CodeResourceExhausted,
	"the recording storage of this workspace is full",
)

// errMailNotSent is not Unavailable, clients read that as the server gone.
var errMailNotSent = connect.NewError(
	connect.CodeFailedPrecondition,
	"the email could not be sent, try again in a few minutes",
)

var (
	// errLinkInvalid is Unauthenticated, the client skips its generic toast.
	errLinkInvalid = connect.NewError(
		connect.CodeUnauthenticated,
		"this link is invalid or expired",
	)
	errAccountInactive = connect.NewError(
		connect.CodeFailedPrecondition,
		"this account has been deactivated",
	)
	errSSORequired = connect.NewError(
		connect.CodeFailedPrecondition,
		"this workspace requires single sign-on",
	)
	errSeatLimit = connect.NewError(
		connect.CodeResourceExhausted,
		"this workspace has no seats left",
	)
	errNoWorkspace = connect.NewError(
		connect.CodeNotFound,
		"no such workspace",
	)
	// Every refused exchange. The failed check goes to logs, not the caller.
	errWorkloadRefused = connect.NewError(
		connect.CodeUnauthenticated,
		"this job can't sign in as this service account. Check its name and the issuer of its rules, "+
			"the audit log says why for a token its issuer signed",
	)
)

var (
	errAccountNotFound = connect.NewError(
		connect.CodeNotFound,
		"account not found",
	)
	errEmailManaged = connect.NewError(
		connect.CodeFailedPrecondition,
		"this account signs in through an identity provider, change the email address there",
	)
	errLastLoginMethod = connect.NewError(
		connect.CodeFailedPrecondition,
		"add another way to sign in before removing this one",
	)
	errCurrentSession = connect.NewError(
		connect.CodeFailedPrecondition,
		"use logout to end the current session",
	)
	errOwnerAccount = connect.NewError(
		connect.CodeFailedPrecondition,
		"transfer ownership of the workspace before deleting your account",
	)
)

// errorInterceptor sits inside audit, so audit sees the final code.
func errorInterceptor(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		return toConnectError(ctx, next(ctx, spec, stream))
	}
}

// toConnectError maps an error to a code a client can act on. The rest is
// internal, logged here and never shown. Connect errors pass through.
func toConnectError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	// Before the pass-through, a seat refusal carries the plan's connect error.
	switch {
	case errors.Is(err, iam.ErrSeatLimit):
		return errSeatLimit
	case errors.Is(err, iam.ErrSSORequired):
		return errSSORequired
	case errors.Is(err, iam.ErrInviteSpent):
		return errInviteInvalid
	case errors.Is(err, iam.ErrLastSSOProvider):
		return connect.NewError(connect.CodeFailedPrecondition,
			"this is the last provider that can sign people in, turn off required single sign-on first")
	}
	if refused, ok := errors.AsType[*ssh.RefusedError](err); ok {
		return connect.NewError(connect.CodeInvalidArgument, refused.Reason)
	}
	if _, ok := errors.AsType[*connect.Error](err); ok {
		return err
	}
	var code string
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		code = pgErr.Code
	}

	switch {
	case errors.Is(err, db.ErrPermissionDenied):
		return errPermissionDenied
	case errors.Is(err, db.ErrWorkspaceNotPinned), errors.Is(err, tenant.ErrUnknownWorkspace):
		return errNoWorkspace
	case errors.Is(err, pgx.ErrNoRows):
		return errNotFound
	case code == pgerrcode.UniqueViolation, code == pgerrcode.ExclusionViolation:
		return connect.NewError(connect.CodeAlreadyExists, "a record with this value already exists")
	case code == pgerrcode.ForeignKeyViolation, code == pgerrcode.RestrictViolation:
		return connect.NewError(connect.CodeFailedPrecondition, "a related record is missing or still in use")
	case code == pgerrcode.NotNullViolation, code == pgerrcode.CheckViolation, pgerrcode.IsDataException(code):
		return errInvalidValue
	case code == pgerrcode.SerializationFailure, code == pgerrcode.DeadlockDetected:
		return connect.NewError(connect.CodeAborted, "the operation conflicted with another, please retry")
	case errors.Is(err, context.Canceled), code == pgerrcode.QueryCanceled:
		return connect.NewError(connect.CodeCanceled, "the request was canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return errTimeout
	}

	var procedure string
	if ci, ok := connect.CallInfoForServerContext(ctx); ok {
		procedure = ci.Spec.Procedure
	}
	slog.ErrorContext(ctx, "internal error", "procedure", procedure, "pg_code", code, "error", err)
	return errInternal
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	iam.WriteJSON(w, status, map[string]any{"code": status, "message": message})
}

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
	errBillingDisabled = connect.NewError(
		connect.CodeUnimplemented,
		"billing is disabled",
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

// errTooManyUploads is not ResourceExhausted, a daemon waits an hour on that and this frees up in seconds.
var errTooManyUploads = connect.NewError(
	connect.CodeUnavailable,
	"this daemon has too many recording uploads open, try again",
)

// errRecordingStorageFull is not InvalidArgument, a daemon gives up on that.
var errRecordingStorageFull = connect.NewError(
	connect.CodeResourceExhausted,
	"the recording storage of this workspace is full",
)

// errMailNotSent is not Unavailable, the client reads that as the server being gone.
var errMailNotSent = connect.NewError(
	connect.CodeFailedPrecondition,
	"the email could not be sent, try again in a few minutes",
)

// errLinkInvalid is Unauthenticated, the client skips its generic toast for that code.
var (
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

func newError(code connect.Code, msg string) error {
	return connect.NewError(code, msg)
}

// errorInterceptor maps every handler error onto a connect error. It sits inside audit so that sees the final code.
func errorInterceptor(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		return toConnectError(ctx, next(ctx, spec, stream))
	}
}

// toConnectError sorts an error into six groups a client can act on. Anything else is internal, and logged here
// once with what the client never sees. Connect errors pass through, so handlers can return domain failures.
func toConnectError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	// Before the pass-through, a seat refusal carries the plan's own connect error.
	switch {
	case errors.Is(err, iam.ErrSeatLimit):
		return errSeatLimit
	case errors.Is(err, iam.ErrSSORequired):
		return errSSORequired
	case errors.Is(err, iam.ErrInviteSpent):
		return errInviteInvalid
	}
	if refused, ok := errors.AsType[*ssh.RefusedError](err); ok {
		return newError(connect.CodeInvalidArgument, refused.Reason)
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
		return newError(connect.CodeAlreadyExists, "a record with this value already exists")
	case code == pgerrcode.ForeignKeyViolation, code == pgerrcode.RestrictViolation:
		return newError(connect.CodeFailedPrecondition, "a related record is missing or still in use")
	case code == pgerrcode.NotNullViolation, code == pgerrcode.CheckViolation, pgerrcode.IsDataException(code):
		return errInvalidValue
	case code == pgerrcode.SerializationFailure, code == pgerrcode.DeadlockDetected:
		return newError(connect.CodeAborted, "the operation conflicted with another, please retry")
	case errors.Is(err, context.Canceled), code == pgerrcode.QueryCanceled:
		return newError(connect.CodeCanceled, "the request was canceled")
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

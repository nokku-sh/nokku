package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/tenant"
)

var (
	errInternal = connect.NewError(
		connect.CodeInternal,
		errors.New("something went wrong, please try again"),
	)
	errNotFound = connect.NewError(
		connect.CodeNotFound,
		errors.New("the requested resource was not found"),
	)
	errTimeout = connect.NewError(
		connect.CodeDeadlineExceeded,
		errors.New("the request took too long, please try again"),
	)
	errPermissionDenied = connect.NewError(
		connect.CodePermissionDenied,
		errors.New("you don't have permission to do that"),
	)
	errBillingDisabled = connect.NewError(
		connect.CodeUnimplemented,
		errors.New("billing is disabled"),
	)
	errInviteInvalid = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("invalid or expired invitation"),
	)
	errInvalidInput = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("please check your input and try again"),
	)
	errSingleWorkspace = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("a self-hosted server keeps its workspace"),
	)
)

// errRecordingStorageFull is not InvalidArgument, a daemon gives up on that.
var errRecordingStorageFull = connect.NewError(
	connect.CodeResourceExhausted,
	errors.New("the recording storage of this workspace is full"),
)

// errNotSSHCA answers for an X.509 CA, which sits in the same table.
var errNotSSHCA = connect.NewError(
	connect.CodeInvalidArgument,
	errors.New("certificate authority is not an SSH CA"),
)

// errMailNotSent is not Unavailable, the client reads that as the server
// being gone.
var errMailNotSent = connect.NewError(
	connect.CodeFailedPrecondition,
	errors.New("the email could not be sent, try again in a few minutes"),
)

// errLinkInvalid is Unauthenticated because the client skips its generic
// toast for that code and the login page shows its own.
var (
	errLinkInvalid = connect.NewError(
		connect.CodeUnauthenticated,
		errors.New("this link is invalid or expired"),
	)
	errAccountInactive = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("this account has been deactivated"),
	)
	errSSORequired = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("this workspace requires single sign-on"),
	)
	errNoWorkspace = connect.NewError(
		connect.CodeNotFound,
		errors.New("no such workspace"),
	)
)

var (
	errAccountNotFound = connect.NewError(
		connect.CodeNotFound,
		errors.New("account not found"),
	)
	errEmailManaged = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("this account signs in through an identity provider, change the email address there"),
	)
	errLastLoginMethod = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("add another way to sign in before removing this one"),
	)
	errCurrentSession = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("use logout to end the current session"),
	)
	errOwnerAccount = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("transfer ownership of the workspace before deleting your account"),
	)
)

func newError(code connect.Code, msg string) error {
	return connect.NewError(code, errors.New(msg))
}

// errorInterceptor maps every handler error onto a connect error, so handlers
// return database errors as they come. It sits inside audit and logging so
// both see the final code.
type errorInterceptor struct{}

func (errorInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		if err != nil {
			return nil, toConnectError(err)
		}
		return res, nil
	}
}

func (errorInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (errorInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return toConnectError(next(ctx, conn))
	}
}

// toConnectError passes connect errors through, so handlers can return domain
// failures from a tx closure.
func toConnectError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*connect.Error](err); ok {
		return err
	}

	switch {
	case errors.Is(err, db.ErrPermissionDenied):
		return errPermissionDenied
	case errors.Is(err, db.ErrWorkspaceNotPinned), errors.Is(err, tenant.ErrUnknownWorkspace):
		return errNoWorkspace
	case errors.Is(err, pgx.ErrNoRows):
		return errNotFound
	case errors.Is(err, context.Canceled):
		return newError(connect.CodeCanceled, "the request was canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return errTimeout
	}

	pgConnErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		slog.Warn("unmapped database error", "error", err, "error_type", fmt.Sprintf("%T", err))
		return errInternal
	}

	switch pgConnErr.Code {
	case pgerrcode.UniqueViolation, pgerrcode.ExclusionViolation:
		return newError(connect.CodeAlreadyExists, "a record with this value already exists")
	case pgerrcode.ForeignKeyViolation, pgerrcode.RestrictViolation:
		return newError(
			connect.CodeFailedPrecondition,
			"a related record is missing or still in use",
		)
	case pgerrcode.NotNullViolation, pgerrcode.CheckViolation:
		return newError(
			connect.CodeInvalidArgument,
			"a required field is missing or contains invalid data",
		)
	case pgerrcode.StringDataRightTruncationDataException:
		return newError(connect.CodeInvalidArgument, "a provided value is too long")
	case pgerrcode.InvalidTextRepresentation,
		pgerrcode.NumericValueOutOfRange,
		pgerrcode.InvalidParameterValue:
		return newError(connect.CodeInvalidArgument, "a provided identifier or value is not valid")
	case pgerrcode.SerializationFailure,
		pgerrcode.DeadlockDetected,
		pgerrcode.InvalidTransactionState,
		pgerrcode.InFailedSQLTransaction,
		pgerrcode.ActiveSQLTransaction:
		return newError(connect.CodeAborted, "the operation conflicted with another, please retry")
	case pgerrcode.QueryCanceled:
		return newError(connect.CodeCanceled, "the request was canceled")
	case pgerrcode.LockNotAvailable,
		pgerrcode.ObjectInUse,
		pgerrcode.ObjectNotInPrerequisiteState,
		pgerrcode.CantChangeRuntimeParam:
		return newError(
			connect.CodeFailedPrecondition,
			"the resource is not available in its current state",
		)
	case pgerrcode.TooManyConnections:
		return newError(
			connect.CodeResourceExhausted,
			"the database is busy, please try again later",
		)
	case pgerrcode.InsufficientResources,
		pgerrcode.DiskFull,
		pgerrcode.OutOfMemory,
		pgerrcode.ProgramLimitExceeded:
		return newError(
			connect.CodeResourceExhausted,
			"the database ran out of resources, please try again later",
		)
	case pgerrcode.ConnectionException,
		pgerrcode.ConnectionDoesNotExist,
		pgerrcode.ConnectionFailure,
		pgerrcode.AdminShutdown,
		pgerrcode.CrashShutdown,
		pgerrcode.CannotConnectNow:
		return newError(
			connect.CodeUnavailable,
			"the service is temporarily unavailable, please try again",
		)
	default:
		return errInternal
	}
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	iam.WriteJSON(w, status, map[string]any{"code": status, "message": message})
}

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
)

// Generic errors

var (
	ErrInternal = connect.NewError(
		connect.CodeInternal,
		errors.New("something went wrong, please try again"),
	)
	ErrNotFound = connect.NewError(
		connect.CodeNotFound,
		errors.New("the requested resource was not found"),
	)
	ErrTimeout = connect.NewError(
		connect.CodeDeadlineExceeded,
		errors.New("the request took too long, please try again"),
	)
	ErrPermissionDenied = connect.NewError(
		connect.CodePermissionDenied,
		errors.New("you don't have permission to do that"),
	)
	ErrBillingDisabled = connect.NewError(
		connect.CodeUnimplemented,
		errors.New("billing is disabled"),
	)
)

// Validation errors

var ErrInvalidInput = connect.NewError(
	connect.CodeInvalidArgument,
	errors.New("please check your input and try again"),
)

// Auth errors

var ErrBadCredentials = connect.NewError(
	connect.CodeInvalidArgument,
	errors.New("incorrect email or password"),
)

// Login flow errors. Bad credentials answers Unauthenticated: the client
// suppresses the generic toast for that code (the login page shows its own
// inline affordances), matching the previous 401 JSON surface.
var (
	ErrLoginFailed = connect.NewError(
		connect.CodeUnauthenticated,
		errors.New("invalid email or password"),
	)
	ErrAccountInactive = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("this account has been deactivated"),
	)
	ErrEmailUnverified = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("verify your email address before signing in"),
	)
	ErrSSORequired = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("your organization requires single sign-on"),
	)
)

// Account errors

var (
	ErrAccountNotFound = connect.NewError(
		connect.CodeNotFound,
		errors.New("account not found"),
	)
	ErrCurrentPassword = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("current password is incorrect"),
	)
	ErrPasswordTooShort = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("password must be at least 8 characters"),
	)
	ErrLastLoginMethod = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("add another login method before removing this one"),
	)
	ErrCurrentSession = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("use logout to end the current session"),
	)
)

func NewError(code connect.Code, msg string) error {
	return connect.NewError(code, errors.New(msg))
}

// DBError maps a pgx or postgres error to a connect error with a message that
// fits the underlying failure. It returns nil only when err is nil. Errors
// that are already connect errors pass through unchanged, so handlers can
// map a domain failure inside a transaction closure.
func DBError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*connect.Error](err); ok {
		return err
	}

	switch {
	case errors.Is(err, db.ErrPermissionDenied), errors.Is(err, db.ErrWorkspaceNotPinned):
		return ErrPermissionDenied
	case errors.Is(err, db.ErrWorkspaceNotAccessible):
		return ErrPermissionDenied
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case errors.Is(err, context.Canceled):
		return NewError(connect.CodeCanceled, "the request was canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return ErrTimeout
	}

	pgConnErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		slog.Warn("unmapped database error", "error", err, "error_type", fmt.Sprintf("%T", err))
		return ErrInternal
	}

	switch pgConnErr.Code {
	case pgerrcode.UniqueViolation, pgerrcode.ExclusionViolation:
		return NewError(connect.CodeAlreadyExists, "a record with this value already exists")
	case pgerrcode.ForeignKeyViolation, pgerrcode.RestrictViolation:
		return NewError(
			connect.CodeFailedPrecondition,
			"a related record is missing or still in use",
		)
	case pgerrcode.NotNullViolation, pgerrcode.CheckViolation:
		return NewError(
			connect.CodeInvalidArgument,
			"a required field is missing or contains invalid data",
		)
	case pgerrcode.StringDataRightTruncationDataException:
		return NewError(connect.CodeInvalidArgument, "a provided value is too long")
	case pgerrcode.InvalidTextRepresentation,
		pgerrcode.NumericValueOutOfRange,
		pgerrcode.InvalidParameterValue:
		return NewError(connect.CodeInvalidArgument, "a provided identifier or value is not valid")
	case pgerrcode.SerializationFailure,
		pgerrcode.DeadlockDetected,
		pgerrcode.InvalidTransactionState,
		pgerrcode.InFailedSQLTransaction,
		pgerrcode.ActiveSQLTransaction:
		return NewError(connect.CodeAborted, "the operation conflicted with another, please retry")
	case pgerrcode.QueryCanceled:
		return NewError(connect.CodeCanceled, "the request was canceled")
	case pgerrcode.LockNotAvailable,
		pgerrcode.ObjectInUse,
		pgerrcode.ObjectNotInPrerequisiteState,
		pgerrcode.CantChangeRuntimeParam:
		return NewError(
			connect.CodeFailedPrecondition,
			"the resource is not available in its current state",
		)
	case pgerrcode.TooManyConnections:
		return NewError(
			connect.CodeResourceExhausted,
			"the database is busy, please try again later",
		)
	case pgerrcode.InsufficientResources,
		pgerrcode.DiskFull,
		pgerrcode.OutOfMemory,
		pgerrcode.ProgramLimitExceeded:
		return NewError(
			connect.CodeResourceExhausted,
			"the database ran out of resources, please try again later",
		)
	case pgerrcode.ConnectionException,
		pgerrcode.ConnectionDoesNotExist,
		pgerrcode.ConnectionFailure,
		pgerrcode.AdminShutdown,
		pgerrcode.CrashShutdown,
		pgerrcode.CannotConnectNow:
		return NewError(
			connect.CodeUnavailable,
			"the service is temporarily unavailable, please try again",
		)
	default:
		return ErrInternal
	}
}

// Http errors

// writeJSONError writes the plain-JSON error body the HTTP surfaces (avatar
// upload, terminal) parse: {"code": <status>, "message": ...}. It shares
// iam's JSON encoder so the wire shape stays identical everywhere.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	iam.WriteJSON(w, status, map[string]any{"code": status, "message": message})
}

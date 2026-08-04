package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"connectrpc.com/connect"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Generic errors

var (
	ErrInternal = connect.NewError(
		connect.CodeInternal,
		errors.New("something went wrong, please try again"),
	)
	ErrUnauthorized = connect.NewError(
		connect.CodeUnauthenticated,
		errors.New("please sign in to continue"),
	)
	ErrNotFound = connect.NewError(
		connect.CodeNotFound,
		errors.New("the requested resource was not found"),
	)
	ErrTimeout = connect.NewError(
		connect.CodeDeadlineExceeded,
		errors.New("the request took too long, please try again"),
	)
	ErrRateLimited = connect.NewError(
		connect.CodeResourceExhausted,
		errors.New("too many requests, please try again later"),
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

var (
	ErrInvalidInput = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("please check your input and try again"),
	)
	ErrEmailInvalid = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("please enter a valid email address"),
	)
	ErrPasswordShort = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("password must be at least 8 characters"),
	)
	ErrFieldMissing = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("please fill in all required fields"),
	)
)

// Auth errors

var (
	ErrBadCredentials = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("incorrect email or password"),
	)
	ErrSSORequired = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("single sign-on is required for your account"),
	)
	ErrTokenInvalid = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("the link has expired or is no longer valid"),
	)
	ErrSessionExpired = connect.NewError(
		connect.CodeUnauthenticated,
		errors.New("your session has expired, please sign in again"),
	)
	ErrEmailTaken = connect.NewError(
		connect.CodeAlreadyExists,
		errors.New("an account with this email already exists"),
	)
	ErrBackupCodeInvalid = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("invalid or already used backup code"),
	)
	ErrPasswordMismatch = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("the password you entered is incorrect"),
	)
	ErrCLILoginCodeBad = connect.NewError(
		connect.CodeNotFound,
		errors.New("the login code is invalid or has expired"),
	)
)

// SSO errors

var (
	ErrSSOProviderInactive = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("activate the provider or add a verified domain first"),
	)
	ErrSSOEnforceWithoutActive = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("enable the provider before enforcing SSO"),
	)
)

// Workspace errors

var ErrWorkspaceLimit = connect.NewError(
	connect.CodeResourceExhausted,
	errors.New("you've reached the maximum number of workspaces"),
)

// Invitation errors

var (
	ErrInvitationExpired = connect.NewError(
		connect.CodeFailedPrecondition,
		errors.New("this invitation has expired"),
	)
	ErrInvitationInvalid = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("the invitation link is invalid"),
	)
	ErrInvitationAlreadyJoin = connect.NewError(
		connect.CodeAlreadyExists,
		errors.New("you're already a member of this workspace"),
	)
)

// Certificate errors

var (
	ErrCertExtensionInvalid = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("please provide valid certificate extensions"),
	)
	ErrCertCriticalInvalid = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("please provide valid critical options"),
	)
	ErrCertKeyMalformed = connect.NewError(
		connect.CodeInvalidArgument,
		errors.New("the public key format is not recognized"),
	)
	ErrCertTargetAccess = connect.NewError(
		connect.CodePermissionDenied,
		errors.New("you don't have access to this target"),
	)
)

func NewError(code connect.Code, msg string) error {
	return connect.NewError(code, errors.New(msg))
}

// DBError maps a pgx or postgres error to a connect error with a message that
// fits the underlying failure. It returns nil only when err is nil.
func DBError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case errors.Is(err, context.Canceled):
		return NewError(connect.CodeCanceled, "the request was canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return ErrTimeout
	}

	pgConnErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
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

type httpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(httpError{
		Code:    status,
		Message: message,
	})
}

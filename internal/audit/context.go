package audit

import "context"

type ctxKey string

const stateKey ctxKey = "audit-state"

// State carries the per-request audit annotations that outlive the request
// context. The kagi auth server and individual handlers populate it; logAudit
// reads it when writing the event.
type State struct {
	WorkspaceID string
	UserID      string
	Email       string
}

// WithState places an audit state on the context.
func WithState(ctx context.Context, state *State) context.Context {
	return context.WithValue(ctx, stateKey, state)
}

// StateFromContext returns the audit state on the context, if any.
func StateFromContext(ctx context.Context) *State {
	val, _ := ctx.Value(stateKey).(*State)
	return val
}

// SetWorkspaceID annotates the in-flight audit state with the workspace the
// request acts in.
func SetWorkspaceID(ctx context.Context, workspaceID string) {
	if s := StateFromContext(ctx); s != nil {
		s.WorkspaceID = workspaceID
	}
}

// SetEmail annotates the in-flight audit state with the acting user's email.
func SetEmail(ctx context.Context, email string) {
	if s := StateFromContext(ctx); s != nil {
		s.Email = email
	}
}

// SetUserID annotates the in-flight audit state with the acting user's id.
func SetUserID(ctx context.Context, userID string) {
	if s := StateFromContext(ctx); s != nil {
		s.UserID = userID
	}
}

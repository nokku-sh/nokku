package api

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"uuid"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/testdb"
)

// TestMain keeps a developer's shell env from pointing the test server at
// real Redis, Stripe, KMS, S3, SMTP, or social providers.
func TestMain(m *testing.M) {
	for _, key := range []string{
		"NOKKU_BASE_URL",
		"NOKKU_REDIS_URL",
		"NOKKU_LICENSE_KEY",
		"NOKKU_STORAGE",
		"NOKKU_SMTP_HOST",
		"NOKKU_ADMIN_EMAIL",
		"NOKKU_ADMIN_PASSWORD",
		"KMS_URI",
		"STRIPE_SECRET_KEY",
		"GOOGLE_CLIENT_ID",
		"GITHUB_CLIENT_ID",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
	} {
		os.Unsetenv(key)
	}
	testdb.Setup("api")
	os.Exit(m.Run())
}

// newTestAPI wires the real config and serves every connect service with the
// production interceptors. The HTTP middleware chain is left out.
func newTestAPI(t *testing.T) (*config.Config, *httptest.Server) {
	t.Helper()
	if _, err := db.NewConnection(t.Context()); err != nil {
		t.Skipf("no test database: %v", err)
	}
	t.Setenv("NOKKU_SECRET", "test-secret")
	t.Setenv("NOKKU_LOCAL_STORAGE_PATH", t.TempDir())
	cfg, err := config.New(t.Context(), nil)
	require.NoError(t, err)

	s := New(cfg)
	require.NoError(t, s.registerServices(t.Context()))
	srv := httptest.NewServer(s.mux)
	t.Cleanup(srv.Close)
	return cfg, srv
}

func seedWorkspace(t *testing.T, cfg *config.Config) string {
	t.Helper()
	var workspaceID string
	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) error {
		u, err := q.CreateUser(
			t.Context(),
			&db.CreateUserParams{Email: uuid.New().String() + "@api.test", Name: "owner"},
		)
		if err != nil {
			return err
		}
		ws, err := q.CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{Name: "api", CreatedBy: u.ID})
		if err != nil {
			return err
		}
		workspaceID = ws.ID
		return nil
	}))
	return workspaceID
}

// seedMember adds a user with role to the workspace and returns a session
// token for them.
func seedMember(t *testing.T, cfg *config.Config, workspaceID string, role db.Role) string {
	t.Helper()
	var userID string
	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) error {
		u, err := q.CreateUser(
			t.Context(),
			&db.CreateUserParams{Email: uuid.New().String() + "@api.test", Name: string(role)},
		)
		if err != nil {
			return err
		}
		userID = u.ID
		return q.EnsureWorkspaceMember(t.Context(), &db.EnsureWorkspaceMemberParams{
			WorkspaceID: workspaceID,
			UserID:      u.ID,
			RoleName:    string(role),
		})
	}))
	_, token, err := cfg.IAM.IssueSession(t.Context(), iam.SessionParams{
		SubjectID: userID,
		Kind:      actor.KindUser,
		Method:    iam.MethodPassword,
	})
	require.NoError(t, err)
	return token
}

func bearer(token string) connect.ClientOption {
	return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Authorization", "Bearer "+token)
			return next(ctx, req)
		}
	}))
}

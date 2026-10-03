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

// Built once per package, every config.New also alters the cluster-wide
// nokku_app role and collides with other test packages doing the same.
var (
	testCfg    *config.Config
	testServer *httptest.Server
	errTestAPI error
)

// TestMain keeps a developer's shell env from pointing the test server at
// real Stripe, KMS, S3, SMTP, or social providers.
func TestMain(m *testing.M) {
	for _, key := range []string{
		"NOKKU_BASE_URL",
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
	storage, _ := os.MkdirTemp("", "nokku-api-test")
	os.Setenv("NOKKU_SECRET", "test-secret-0123456789-0123456789")
	os.Setenv("NOKKU_LOCAL_STORAGE_PATH", storage)

	ctx, cancel := context.WithCancel(context.Background())
	testCfg, errTestAPI = config.New(ctx, nil)
	if errTestAPI == nil {
		s := New(testCfg)
		errTestAPI = s.registerServices(ctx)
		// Bidi streams need HTTP/2.
		testServer = httptest.NewUnstartedServer(s.mux)
		testServer.EnableHTTP2 = true
		testServer.StartTLS()
	}
	code := m.Run()
	cancel()
	if testServer != nil {
		testServer.Close()
	}
	_ = os.RemoveAll(storage)
	os.Exit(code)
}

// newTestAPI returns the real config and a server running every connect
// service with the production interceptors. The HTTP middleware chain is
// left out.
func newTestAPI(t *testing.T) (*config.Config, *httptest.Server) {
	t.Helper()
	if errTestAPI != nil {
		t.Skipf("no test API, is the test database up? %v", errTestAPI)
	}
	return testCfg, testServer
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

func header(key, value string) connect.ClientOption {
	return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set(key, value)
			return next(ctx, req)
		}
	}))
}

package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"uuid"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/tenant"
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
// real Stripe, KMS, S3, SMTP, or identity providers.
func TestMain(m *testing.M) {
	for _, key := range []string{
		"NOKKU_BASE_URL",
		"NOKKU_LICENSE_KEY",
		"NOKKU_STORAGE",
		"NOKKU_SMTP_HOST",
		"NOKKU_ADMIN_EMAIL",
		"NOKKU_ADMIN_NAME",
		"NOKKU_WORKSPACE_NAME",
		"KMS_URI",
		"STRIPE_SECRET_KEY",
		"GOOGLE_CLIENT_ID",
		"MICROSOFT_CLIENT_ID",
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
		s.registerServices(ctx)
		// Self-host mode: every request lands in the one workspace the boot
		// made, whatever the host. Bidi streams need HTTP/2.
		testServer = httptest.NewUnstartedServer(s.withTenant(s.mux))
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
// left out, except for the tenant resolver.
func newTestAPI(t *testing.T) (*config.Config, *httptest.Server) {
	t.Helper()
	if errTestAPI != nil {
		t.Skipf("no test API, is the test database up? %v", errTestAPI)
	}
	return testCfg, testServer
}

// seedWorkspace is the one workspace the test server serves. Tests share it
// and tell their rows apart by fresh ids.
func seedWorkspace(t *testing.T, cfg *config.Config) string {
	t.Helper()
	return cfg.Tenant.Single().ID
}

// seedOtherWorkspace makes a workspace no request can reach. What lives in
// it must never show up through the API.
func seedOtherWorkspace(t *testing.T, cfg *config.Config) string {
	t.Helper()
	var id string
	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) error {
		ws, err := tenant.Create(t.Context(), q, uuid.NewV7().String(), "other")
		if err != nil {
			return err
		}
		id = ws.ID
		return nil
	}))
	return id
}

// wsCtx is a request context on the host of the test workspace.
func wsCtx(t *testing.T, cfg *config.Config) context.Context {
	t.Helper()
	return actor.WithWorkspace(t.Context(), cfg.Tenant.Single())
}

func seedUser(t *testing.T, cfg *config.Config, workspaceID string, role db.Role) *db.User {
	t.Helper()
	u, err := cfg.Conn.Sys().CreateUser(t.Context(), &db.CreateUserParams{
		WorkspaceID: workspaceID,
		Email:       strings.ReplaceAll(uuid.New().String(), "-", "") + "@api.test",
		Name:        string(role),
		Role:        string(role),
	})
	require.NoError(t, err)
	return u
}

// seedOwner is the owner of the test workspace, made on first use.
func seedOwner(t *testing.T, cfg *config.Config) *db.User {
	t.Helper()
	owner, err := cfg.Conn.Sys().GetOwner(t.Context(), cfg.Tenant.Single().ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return seedUser(t, cfg, cfg.Tenant.Single().ID, db.RoleOwner)
	}
	require.NoError(t, err)
	return owner
}

// sessionFor signs the user in and returns the session token.
func sessionFor(t *testing.T, cfg *config.Config, u *db.User) string {
	t.Helper()
	_, token, err := cfg.IAM.IssueSession(wsCtx(t, cfg), iam.SessionParams{
		SubjectID: u.ID,
		Kind:      actor.KindUser,
		Method:    iam.MethodPasskey,
	})
	require.NoError(t, err)
	return token
}

// seedMember adds a user with role to the workspace and returns a session
// token for them. The owner is shared, there is only one.
func seedMember(t *testing.T, cfg *config.Config, workspaceID string, role db.Role) string {
	t.Helper()
	if role == db.RoleOwner {
		return sessionFor(t, cfg, seedOwner(t, cfg))
	}
	return sessionFor(t, cfg, seedUser(t, cfg, workspaceID, role))
}

// uniq is a name no other test used, names are unique per workspace.
func uniq(prefix string) string {
	return prefix + "-" + uuid.New().String()[:8]
}

func header(key, value string) connect.ClientOption {
	return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set(key, value)
			return next(ctx, req)
		}
	}))
}

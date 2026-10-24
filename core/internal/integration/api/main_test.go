//go:build integration

package api_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"uuid"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"connectrpc.com/connect"
	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
	"github.com/nokku-sh/nokku/core/internal/tenant"
)

// What a client sees of the limits and codes of the server.
const (
	maxMessageBytes    = 4 << 20
	maxUploadBytes     = 64 << 20
	quotaCheckInterval = 1 << 20

	wsShellExited websocket.StatusCode = 4000
)

// One server for the package, the tests share its workspace.
var (
	testCfg    *config.Config
	testServer *httptest.Server
	// storageDir is where the test server keeps recordings.
	storageDir string
)

// TestMain keeps a developer's shell env from pointing the test server at real Stripe, KMS, S3, SMTP or providers.
func TestMain(m *testing.M) {
	for _, key := range []string{
		"NOKKU_BASE_URL",
		"NOKKU_TLS_CA",
		"NOKKU_TRUSTED_PROXIES",
		"NOKKU_LICENSE_KEY",
		"NOKKU_STORAGE_URL",
		"NOKKU_SMTP_HOST",
		"NOKKU_ADMIN_EMAIL",
		"NOKKU_ADMIN_NAME",
		"NOKKU_WORKSPACE_NAME",
		"KMS_URI",
		"NOKKU_SAAS",
		"STRIPE_SECRET_KEY",
		"STRIPE_WEBHOOK_SECRET",
		"STRIPE_PRO_MONTHLY_PRICE_ID",
		"STRIPE_PRO_YEARLY_PRICE_ID",
		"GOOGLE_CLIENT_ID",
		"MICROSOFT_CLIENT_ID",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
	} {
		os.Unsetenv(key)
	}
	stop := testenv.Postgres()
	storageDir, _ = os.MkdirTemp("", "nokku-api-test")
	os.Setenv("NOKKU_SECRET", "test-secret-0123456789-0123456789")
	os.Setenv("NOKKU_STORAGE_URL", "file://"+storageDir)
	// A test that holds a license key must not ask the real license worker for a new one.
	os.Setenv("NOKKU_LICENSE_OFFLINE", "true")
	// Saving a provider fetches its discovery document, and the test issuers listen on loopback.
	os.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")

	ctx, cancel := context.WithCancel(context.Background())
	var err error
	testCfg, err = config.New(ctx, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "boot the test server: %v\n", err)
		stop()
		os.Exit(1)
	}
	// Self-host mode: every request lands in the one workspace, whatever the host. Bidi streams need HTTP/2.
	testServer = httptest.NewUnstartedServer(api.New(testCfg).Handler(ctx))
	testServer.EnableHTTP2 = true
	testServer.StartTLS()

	code := m.Run()
	cancel()
	testServer.Close()
	_ = os.RemoveAll(storageDir)
	stop()
	os.Exit(code)
}

// newTestAPI returns the real config and a server with every route behind the production middleware.
func newTestAPI(t *testing.T) (*config.Config, *httptest.Server) {
	t.Helper()
	return testCfg, testServer
}

func workspaceName(ctx context.Context, conn *db.Connection) (string, error) {
	ws, err := conn.Tenant().GetWorkspace(ctx)
	if err != nil {
		return "", err
	}
	return ws.Name, nil
}

// seedWorkspace is the one workspace the test server serves. Tests tell their rows apart by fresh ids.
func seedWorkspace(t *testing.T, cfg *config.Config) string {
	t.Helper()
	return cfg.Tenant.Single().ID
}

// seedOtherWorkspace makes a workspace no request can reach. What lives in it must never show up through the API.
func seedOtherWorkspace(t *testing.T, cfg *config.Config) string {
	t.Helper()
	ws, err := tenant.Create(t.Context(), cfg.Conn, uuid.NewV7().String(), "other")
	require.NoError(t, err)
	return ws.ID
}

// inWorkspace runs fn the way a request does: nokku_app, pinned to the workspace.
func inWorkspace(t *testing.T, cfg *config.Config, workspaceID string, fn func(q *db.Queries) error) {
	t.Helper()
	ctx := actor.WithWorkspace(t.Context(), actor.Workspace{ID: workspaceID})
	require.NoError(t, cfg.Conn.TenantTx(ctx, fn))
}

// wsCtx is a request context on the host of the test workspace.
func wsCtx(t *testing.T, cfg *config.Config) context.Context {
	t.Helper()
	return actor.WithWorkspace(t.Context(), cfg.Tenant.Single())
}

func seedUser(t *testing.T, cfg *config.Config, workspaceID string, role nokkuv1.WorkspaceRole) *db.User {
	t.Helper()
	var u *db.User
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) (err error) {
		u, err = q.CreateUser(t.Context(), &db.CreateUserParams{
			Email: strings.ReplaceAll(uuid.New().String(), "-", "") + "@api.test",
			Name:  db.RoleLabel(role),
			Role:  role,
		})
		return err
	})
	return u
}

// seedOwner is the owner of the test workspace, made on first use.
func seedOwner(t *testing.T, cfg *config.Config) *db.User {
	t.Helper()
	var owner *db.User
	err := cfg.Conn.TenantTx(wsCtx(t, cfg), func(q *db.Queries) (err error) {
		owner, err = q.GetOwner(t.Context())
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return seedUser(t, cfg, cfg.Tenant.Single().ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)
	}
	require.NoError(t, err)
	return owner
}

func sessionFor(t *testing.T, cfg *config.Config, u *db.User) string {
	t.Helper()
	_, token, err := cfg.IAM.IssueToken(wsCtx(t, cfg), iam.TokenParams{
		SubjectID: u.ID,
		Kind:      actor.KindUser,
		Method:    iam.MethodPasskey,
	})
	require.NoError(t, err)
	return token
}

// seedMember adds a user with role and returns a session token for them.
func seedMember(t *testing.T, cfg *config.Config, workspaceID string, role nokkuv1.WorkspaceRole) string {
	t.Helper()
	if role == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER {
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

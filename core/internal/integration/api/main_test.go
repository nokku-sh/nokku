//go:build integration

package api_test

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uuid"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
	"github.com/nokku-sh/nokku/core/internal/tenant"
)

// What a client sees of the limits and codes of the server.
const (
	maxMessageBytes = 4 << 20
	maxUploadBytes  = 64 << 20
	maxOpenUploads  = 64

	wsShellExited websocket.StatusCode = 4000
)

// accessTokens is every kind, for a test that takes whichever it got.
var accessTokens = []crypto.TokenKind{
	crypto.TokenSession, crypto.TokenCLI, crypto.TokenDaemon, crypto.TokenServiceAccount, crypto.TokenSCIM,
}

// One server for the package, the tests share its workspace.
var (
	testCfg       *config.Config
	testServer    *httptest.Server
	testHandler   http.Handler
	testWorkspace actor.Workspace
	storageDir    string
)

// TestMain boots the one test server. testenv scrubs the developer's env.
func TestMain(m *testing.M) {
	storageDir, _ = os.MkdirTemp("", "nokku-api-test")
	if err := trustHTTPTest(); err != nil {
		fmt.Fprintf(os.Stderr, "write the test roots: %v\n", err)
		os.Exit(1)
	}
	stop := testenv.Postgres()
	stopKMS := func() {}
	if hosted {
		stopKMS = testenv.KMS(storageDir)
		os.Setenv("NOKKU_SAAS", "true")
		os.Setenv("NOKKU_BASE_URL", hostedBase)
		os.Setenv("STRIPE_SECRET_KEY", "sk_test_never_called")
		os.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
		os.Setenv("STRIPE_PRO_MONTHLY_PRICE_ID", "price_monthly")
		os.Setenv("STRIPE_PRO_YEARLY_PRICE_ID", "price_yearly")
	} else {
		os.Setenv("NOKKU_SECRET", "test-secret-0123456789-0123456789")
	}
	os.Setenv("NOKKU_STORAGE_URL", "file://"+storageDir)
	// A test with a license key must not ask the real worker for a new one.
	os.Setenv("NOKKU_LICENSE_OFFLINE", "true")
	// Saving a provider fetches discovery from an issuer on loopback.
	os.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")

	ctx, cancel := context.WithCancel(context.Background())
	var err error
	testCfg, err = config.New(ctx, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "boot the test server: %v\n", err)
		stop()
		os.Exit(1)
	}
	testWorkspace = testCfg.Tenant.Single()
	if hosted {
		if testWorkspace, err = hostedWorkspace(ctx, testCfg); err != nil {
			fmt.Fprintf(os.Stderr, "make the hosted workspace: %v\n", err)
			stopKMS()
			stop()
			os.Exit(1)
		}
	}
	// Self-hosted ignores the host, hosted reads the one serving sets.
	// Bidi streams need HTTP/2.
	testHandler = api.New(testCfg).Handler(ctx)
	testServer = httptest.NewUnstartedServer(serving(testHandler))
	testServer.EnableHTTP2 = true
	testServer.StartTLS()

	code := m.Run()
	cancel()
	testServer.Close()
	_ = os.RemoveAll(storageDir)
	stopKMS()
	stop()
	os.Exit(code)
}

// trustHTTPTest must beat a Docker client on TLS, Go loads the roots once.
func trustHTTPTest() error {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	roots := filepath.Join(storageDir, "httptest-roots.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(roots, block, 0o600); err != nil {
		return err
	}
	return os.Setenv("SSL_CERT_FILE", roots)
}

// newTestAPI is the real config and a server behind the real middleware.
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

// seedOtherWorkspace makes a workspace no request can reach or see.
func seedOtherWorkspace(t *testing.T, cfg *config.Config) string {
	t.Helper()
	ws, err := tenant.Create(t.Context(), cfg.Conn, cfg.Keyset, uuid.NewV7().String(), "other")
	require.NoError(t, err)
	return ws.ID
}

// workspaceCA reads the shared CA. A test that changes it uses setCA.
func workspaceCA(t *testing.T, cfg *config.Config) *nokkuv1.CertificateAuthority {
	t.Helper()
	var ca *db.SSHCA
	inWorkspace(t, cfg, testWorkspace.ID, func(q *db.Queries) (err error) {
		ca, err = q.GetWorkspaceCA(t.Context())
		return err
	})
	return ca.ToProto()
}

// inWorkspace runs fn like a request does: nokku_app, pinned to the workspace.
func inWorkspace(t *testing.T, cfg *config.Config, workspaceID string, fn func(q *db.Queries) error) {
	t.Helper()
	ctx := actor.WithWorkspace(t.Context(), actor.Workspace{ID: workspaceID})
	require.NoError(t, cfg.Conn.TenantTx(ctx, fn))
}

// wsCtx is a request context on the host of the test workspace.
func wsCtx(t *testing.T) context.Context {
	t.Helper()
	return actor.WithWorkspace(t.Context(), testWorkspace)
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
	err := cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) (err error) {
		owner, err = q.GetOwner(t.Context())
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)
	}
	require.NoError(t, err)
	return owner
}

func sessionFor(t *testing.T, cfg *config.Config, u *db.User) string {
	t.Helper()
	_, token, err := cfg.IAM.IssueSignIn(
		wsCtx(t),
		u,
		iam.TokenParams{Kind: actor.KindUser, Method: iam.MethodPasskey},
	)
	require.NoError(t, err)
	return token
}

// cliSessionFor is an nk session with no key bound, so no proof is asked.
func cliSessionFor(t *testing.T, cfg *config.Config, u *db.User) string {
	t.Helper()
	_, token, err := cfg.IAM.IssueSignIn(
		wsCtx(t),
		u,
		iam.TokenParams{Kind: actor.KindCLI, Method: iam.MethodPasskey},
	)
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

func clientOn(srv *httptest.Server, auth ...connect.ClientInterceptor) *connect.Client {
	return connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), auth...)
}

// header applies to unary calls, stream tests set theirs on the client context.
func header(key, value string) connect.ClientInterceptor {
	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
			if info, ok := connect.CallInfoForClientContext(ctx); ok && spec.StreamType == connect.StreamTypeUnary {
				info.RequestHeader().Set(key, value)
			}
			return next(ctx, spec)
		}
	}
}

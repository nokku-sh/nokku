//go:build integration

// Package testenv starts what the integration tests run against, each service a container on a random port.
package testenv

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Pinned, a new upstream release must not fail the tests on its own. compose.dev.yml runs the same versions.
const (
	postgresImage = "docker.io/postgres:18-alpine"
	keycloakImage = "quay.io/keycloak/keycloak:26.8.0"
	vaultImage    = "docker.io/hashicorp/vault:2.1.2"

	// VaultToken is the root token of the server Vault starts.
	VaultToken = "root"

	startAttempts = 4
)

// run starts a container, and starts another when the host port of the first was taken. Docker picks that port
// without asking, and a rootless one cannot even see what the host has bound. The test binaries of the other
// packages open sockets at the same time, so now and then it picks one of theirs.
func run(
	ctx context.Context,
	image string,
	opts ...testcontainers.ContainerCustomizer,
) (*testcontainers.DockerContainer, error) {
	for attempt := 1; ; attempt++ {
		c, err := testcontainers.Run(ctx, image, opts...)
		if err == nil || attempt == startAttempts || !strings.Contains(err.Error(), "address already in use") {
			return c, err
		}
		// Run hands the container back even when it did not come up.
		_ = testcontainers.TerminateContainer(c)
	}
}

// Postgres starts an empty server and points the PG* environment at it. Call it from TestMain, run stop after.
func Postgres() (stop func()) {
	ctx := context.Background()
	c, err := run(ctx, postgresImage,
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_USER":     "postgres",
			"POSTGRES_PASSWORD": "postgres",
			"POSTGRES_DB":       "nokku",
			"PGDATA":            "/inmemory-db",
		}),
		testcontainers.WithTmpfs(map[string]string{"/inmemory-db": "rw"}),
		testcontainers.WithExposedPorts("5432/tcp"),
		// The image starts the server twice, the first one only runs the init scripts.
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
			wait.ForListeningPort("5432/tcp"),
		),
	)
	// The container comes back even when it did not come up.
	stop = func() { _ = testcontainers.TerminateContainer(c) }
	if err == nil {
		err = pointEnvAt(ctx, c)
	}
	if err != nil {
		stop()
		// A TestMain has no t to fail.
		fmt.Fprintf(os.Stderr, "testenv: start postgres: %v\n", err)
		os.Exit(1)
	}
	return stop
}

func pointEnvAt(ctx context.Context, c *testcontainers.DockerContainer) error {
	endpoint, err := c.PortEndpoint(ctx, "5432/tcp", "")
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return err
	}
	// Set, never defaulted. A developer's shell must not send the tests to another server.
	for key, value := range map[string]string{
		"PGHOST":     host,
		"PGPORT":     port,
		"PGUSER":     "postgres",
		"PGPASSWORD": "postgres",
		"PGDATABASE": "nokku",
		"PGSSLMODE":  "disable",
	} {
		_ = os.Setenv(key, value)
	}
	return nil
}

// Keycloak starts a dev server for the test and returns its root URL. The admin is admin with the password admin.
func Keycloak(t *testing.T) string {
	t.Helper()
	c, err := run(t.Context(), keycloakImage,
		testcontainers.WithCmd("start-dev"),
		testcontainers.WithEnv(map[string]string{
			"KEYCLOAK_ADMIN":          "admin",
			"KEYCLOAK_ADMIN_PASSWORD": "admin",
		}),
		testcontainers.WithExposedPorts("8080/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForHTTP("/realms/master").WithPort("8080/tcp").WithStartupTimeout(3*time.Minute),
		),
	)
	testcontainers.CleanupContainer(t, c)
	require.NoError(t, err, "start keycloak")
	root, err := c.PortEndpoint(t.Context(), "8080/tcp", "http")
	require.NoError(t, err)
	return root
}

// Vault starts a dev server and returns its host and port. It serves TLS, nokku only talks https to Vault.
func Vault(t *testing.T) string {
	t.Helper()
	c, err := run(t.Context(), vaultImage,
		testcontainers.WithCmd("server", "-dev", "-dev-tls"),
		testcontainers.WithEnv(map[string]string{"VAULT_DEV_ROOT_TOKEN_ID": VaultToken}),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			hc.CapAdd = append(hc.CapAdd, "IPC_LOCK")
		}),
		testcontainers.WithExposedPorts("8200/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp").WithTLS(true).WithAllowInsecure(true),
		),
	)
	testcontainers.CleanupContainer(t, c)
	require.NoError(t, err, "start vault")
	addr, err := c.PortEndpoint(t.Context(), "8200/tcp", "")
	require.NoError(t, err)
	return addr
}

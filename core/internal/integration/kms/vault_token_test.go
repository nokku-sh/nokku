//go:build integration

package kms_test

import (
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// logBuffer holds what the loops of the core log while a test watches.
type logBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) has(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Contains(l.buf.String(), s)
}

func captureLogs(t *testing.T) *logBuffer {
	t.Helper()
	logs := &logBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logs
}

// docToken holds only the policy SECURITY.md gives, that has to be enough.
func docToken(t *testing.T, root *api.Client, kek, period string) string {
	t.Helper()
	require.NoError(t, root.Sys().PutPolicyWithContext(t.Context(), "nokku-core", docPolicy(t, kek)))
	token, err := root.Auth().Token().CreateWithContext(t.Context(), &api.TokenCreateRequest{
		Policies:        []string{"nokku-core"},
		NoDefaultPolicy: true,
		Period:          period,
	})
	require.NoError(t, err)
	return token.Auth.ClientToken
}

// Of two periodic tokens only the core's outlives its period, and a restart
// still opens the keyset with it.
func TestCoreKeepsAPeriodicVaultTokenAlive(t *testing.T) {
	logs := captureLogs(t)
	conn := freshDB(t)
	root, kek, kekURI := testVaultKey(t)

	unrenewed, err := root.Clone()
	require.NoError(t, err)
	unrenewed.SetToken(docToken(t, root, kek, "5s"))

	t.Setenv("VAULT_TOKEN", docToken(t, root, kek, "5s"))
	t.Setenv("KMS_URI", kekURI)
	keys, err := openKeyset(t, conn, "")
	require.NoError(t, err)
	go keys.VaultTokenLoop(t.Context())

	require.Eventually(t, func() bool {
		_, err := unrenewed.Auth().Token().LookupSelfWithContext(t.Context())
		return err != nil
	}, 15*time.Second, 200*time.Millisecond, "a token nobody renews has to end, or this test proves nothing")

	_, err = openKeyset(t, conn, "")
	require.NoError(t, err, "a restart can't open the keyset, the core's token ended")
	assert.False(t, logs.has("not renewed"), "a renewal failed")
	assert.False(t, logs.has("not periodic"), "a periodic token was called not periodic")
}

func TestCoreWarnsAboutAVaultTokenThatEnds(t *testing.T) {
	logs := captureLogs(t)
	conn := freshDB(t)
	root, kek, kekURI := testVaultKey(t)
	t.Setenv("VAULT_TOKEN", docToken(t, root, kek, ""))
	t.Setenv("KMS_URI", kekURI)
	keys, err := openKeyset(t, conn, "")
	require.NoError(t, err)

	go keys.VaultTokenLoop(t.Context())
	require.Eventually(t, func() bool { return logs.has("not periodic") }, 5*time.Second, 50*time.Millisecond)
}

// A root token never ends and can't be renewed, that is no failure.
func TestCoreLeavesARootVaultTokenAlone(t *testing.T) {
	logs := captureLogs(t)
	conn := freshDB(t)
	_, _, kekURI := testVaultKey(t)
	t.Setenv("KMS_URI", kekURI)
	keys, err := openKeyset(t, conn, "")
	require.NoError(t, err)

	go keys.VaultTokenLoop(t.Context())
	assert.Never(t, func() bool { return logs.has("VAULT_TOKEN") }, time.Second, 50*time.Millisecond)
}

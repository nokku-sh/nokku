//go:build integration

package kms_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
	"github.com/nokku-sh/nokku/core/internal/recording"
	"github.com/nokku-sh/nokku/core/internal/ssh"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

// sealedOverride is the sqlc.yaml entry of a sealed column.
var sealedOverride = regexp.MustCompile(
	`- column: "([a-z_]+\.[a-z_]+)"\s+go_type:\s+import: "[^"]+"\s+type: "Sealed"`,
)

// sealedValue is one secret in a sealed column, and how the server reads it.
type sealedValue struct {
	table, column string
	// where picks its row, a table may hold more than one secret.
	where string
	// plaintext must not be in the stored bytes. A CA key leaves the server
	// never, so it has none here.
	plaintext []byte
	// read goes the way the server does, with the keyset the server runs with.
	read func(t *testing.T, keys *kms.Keyset)
}

// recordingLimits keeps every recording, the sweeper never takes the one here.
type recordingLimits struct{}

func (recordingLimits) RecordingRetentionDays(context.Context, string) (int64, error) {
	return 365, nil
}

func (recordingLimits) RecordingStorageBytes(context.Context, string) (int64, error) {
	return math.MaxInt64, nil
}

// Each sealed column reads back the same and is rewritten after rotate-secrets
// to a new secret, Vault and back.
func TestEverySealedColumnSurvivesRotation(t *testing.T) {
	columns := sqlcSealedColumns(t)
	conn := freshDB(t)
	wipe(t.Context(), t, columns)
	// t.Context is already canceled when cleanups run.
	t.Cleanup(func() { wipe(context.WithoutCancel(t.Context()), t, columns) })
	_, _, vaultURI := testVaultKey(t)

	key := "secret:" + secretA
	keys := boot(t, conn, key)

	values := seedEverySealedColumn(t, conn, keys)
	var seeded []string
	for _, v := range values {
		seeded = append(seeded, v.table+"."+v.column)
	}
	slices.Sort(seeded)
	require.ElementsMatch(t, columns, slices.Compact(seeded),
		"every column sqlc.yaml seals needs a seed and a read in this test")

	stored := checkEveryColumn(t, "first boot", keys, values, nil)
	// One ciphertext per data key ever had, oldest first. Tink lists no keys.
	var made [][]byte
	for _, step := range []struct{ name, key string }{
		{"to a new secret", "secret:" + secretB},
		{"into vault", "kms:" + vaultURI},
		{"back to a secret", "secret:" + secretA},
	} {
		made = append(made, seal(t, keys, "made before "+step.name))
		keys = rotateSecrets(t, conn, key, step.key)
		stored = checkEveryColumn(t, step.name, keys, values, stored)
		checkAtMostTwoKeys(t, step.name, keys, made)
		key = step.key
	}
}

// A secret copied into another workspace's stream, whose URL that one picked.
func TestASealedSecretOpensOnlyInItsRow(t *testing.T) {
	conn := freshDB(t)
	t.Cleanup(func() { wipe(context.WithoutCancel(t.Context()), t, []string{"audit_streams.secret"}) })
	keys := boot(t, conn, "secret:"+secretA)
	got := make(chan string, 2)
	siem := splunk(t, got)
	stream := func(secret string) *db.AuditStream {
		ws := seedWorkspace(t, conn)
		id := seedAuditStream(t, conn, keys, ws, siem.URL, secret)
		st, err := conn.Tenant().GetAuditStream(testenv.Pinned(t, ws), id)
		require.NoError(t, err)
		return st
	}
	victim, thief := stream("victim-hec-token"), stream("thief-hec-token")

	admin, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = admin.Close(t.Context()) }()
	_, err = admin.Exec(
		t.Context(),
		"UPDATE audit_streams SET secret = $1 WHERE id = $2",
		[]byte(victim.Secret),
		thief.ID,
	)
	require.NoError(t, err)
	thief, err = conn.Tenant().GetAuditStream(testenv.Pinned(t, thief.WorkspaceID), thief.ID)
	require.NoError(t, err)

	streams := auditService(t, conn, keys)
	require.Error(t, streams.TestStream(t.Context(), thief), "the copied secret opened in the other row")
	require.NoError(t, streams.TestStream(t.Context(), victim))
	assert.Equal(t, "victim-hec-token", <-got, "only the victim's stream sends, with its own secret")
	assert.Empty(t, got, "the thief's stream sent something")
}

func sqlcSealedColumns(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../../sqlc.yaml")
	require.NoError(t, err)
	var columns []string
	for _, m := range sealedOverride.FindAllStringSubmatch(string(raw), -1) {
		columns = append(columns, m[1])
	}
	require.NotEmpty(t, columns, "sqlc.yaml has no Sealed override")
	return columns
}

// wipe empties the tables of columns. A ciphertext under a keyset another test
// replaced fails every rotation.
func wipe(ctx context.Context, t *testing.T, columns []string) {
	t.Helper()
	admin, err := pgx.Connect(ctx, "")
	require.NoError(t, err)
	defer func() { _ = admin.Close(ctx) }()
	for _, column := range columns {
		table, _, _ := strings.Cut(column, ".")
		_, err := admin.Exec(ctx, "DELETE FROM "+pgx.Identifier{table}.Sanitize())
		require.NoError(t, err)
	}
}

// boot loads the keyset like the server, key in the form rotate-secrets takes.
func boot(t *testing.T, conn *db.Connection, key string) *kms.Keyset {
	t.Helper()
	scheme, value, _ := strings.Cut(key, ":")
	kmsURI, secret := "", value
	if scheme == "kms" {
		kmsURI, secret = value, ""
	}
	t.Setenv("KMS_URI", kmsURI)
	keys, err := openKeyset(t, conn, secret)
	require.NoError(t, err, "boot with %s", scheme)
	return keys
}

// rotateSecrets is nokku rotate-secrets, then a server start on the new key.
func rotateSecrets(t *testing.T, conn *db.Connection, current, next string) *kms.Keyset {
	t.Helper()
	require.NoError(t, boot(t, conn, current).Rotate(t.Context(), next))
	return boot(t, conn, next)
}

// checkEveryColumn reads each value through the server, returns what is stored.
func checkEveryColumn(
	t *testing.T,
	step string,
	keys *kms.Keyset,
	values map[string]sealedValue,
	before map[string][]byte,
) map[string][]byte {
	t.Helper()
	probe := seal(t, keys, "probe")
	stored := make(map[string][]byte, len(values))
	for name, v := range values {
		v.read(t, keys)
		raw := storedValue(t, v)
		require.Greater(t, len(raw), len(keyID(probe)), "%s: %s is empty", step, name)
		if v.plaintext != nil {
			assert.False(t, bytes.Contains(raw, v.plaintext), "%s: %s is stored in the clear", step, name)
		} else {
			_, err := x509.ParsePKCS8PrivateKey(raw)
			require.Error(t, err, "%s: %s is a private key in the clear", step, name)
		}
		assert.Equal(t, keyID(probe), keyID(raw), "%s: %s is not under the current key", step, name)
		if before != nil {
			assert.NotEqual(t, before[name], raw, "%s: %s was not re-encrypted", step, name)
		}
		stored[name] = raw
	}
	return stored
}

// checkAtMostTwoKeys counts keys by what still opens. Only the last of made,
// from the replaced key, may.
func checkAtMostTwoKeys(t *testing.T, step string, keys *kms.Keyset, made [][]byte) {
	t.Helper()
	assert.NotEqual(t, keyID(made[len(made)-1]), keyID(seal(t, keys, "x")), "%s: no new data key", step)
	for i, older := range made[:len(made)-1] {
		_, err := keys.Open(detached, older)
		assert.Error(t, err, "%s: the key of generation %d is still in the keyset", step, i)
	}
}

// seal is a ciphertext of the keyset the server runs with, stored nowhere.
func seal(t *testing.T, keys *kms.Keyset, plaintext string) []byte {
	t.Helper()
	out, err := keys.Seal(detached, []byte(plaintext))
	require.NoError(t, err)
	return out
}

// storedValue is the ciphertext of v, read as the superuser past the app.
func storedValue(t *testing.T, v sealedValue) []byte {
	t.Helper()
	admin, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = admin.Close(t.Context()) }()
	rows, err := admin.Query(t.Context(), fmt.Sprintf("SELECT %s FROM %s WHERE %s",
		pgx.Identifier{v.column}.Sanitize(), pgx.Identifier{v.table}.Sanitize(), v.where))
	require.NoError(t, err)
	values, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	require.NoError(t, err)
	require.Len(t, values, 1, "%s holds rows this test did not make", v.table)
	return values[0]
}

func seedWorkspace(t *testing.T, conn *db.Connection) string {
	t.Helper()
	ws := uuid.NewV7().String()
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, ws), func(q *db.Queries) error {
		_, err := q.CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{
			ID: ws, Slug: ws, Name: "rotation", Settings: &nokkuv1.WorkspaceSettings{},
		})
		return err
	}))
	return ws
}

func seedEverySealedColumn(t *testing.T, conn *db.Connection, keys *kms.Keyset) map[string]sealedValue {
	t.Helper()
	ws := seedWorkspace(t, conn)
	values := seedSSHCA(t, conn, keys, ws)
	maps.Copy(values, seedSSOProvider(t, conn, keys, ws))
	maps.Copy(values, seedStream(t, conn, keys, ws))
	maps.Copy(values, seedRecording(t, conn, keys, ws))
	return values
}

// seedSSHCA reads each key back by signing a login and a host certificate.
func seedSSHCA(t *testing.T, conn *db.Connection, keys *kms.Keyset, ws string) map[string]sealedValue {
	t.Helper()
	var ca *db.SSHCA
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, ws), func(q *db.Queries) (err error) {
		ca, err = ssh.CreateCA(t.Context(), q, keys, ssh.NewCA())
		return err
	}))

	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	login, err := ssh.MarshalPubKey(public)
	require.NoError(t, err)
	sign := func(certType uint32, principal, authority string) func(*testing.T, *kms.Keyset) {
		return func(t *testing.T, keys *kms.Keyset) {
			t.Helper()
			var signer gossh.Signer
			require.NoError(t, conn.TenantTx(testenv.Pinned(t, ws), func(q *db.Queries) (err error) {
				signer, err = ssh.CASigner(t.Context(), q, keys, ca.ID, certType)
				return err
			}), "the CA does not sign")
			cert, err := ssh.SignCertificate(
				ca, signer, login, []string{principal}, "rotation", time.Hour, certType, ssh.Limits{},
			)
			require.NoError(t, err)
			assert.Equal(t, authority, ssh.MarshalKey(cert.SignatureKey), "signed with the wrong key")
			require.NoError(t, new(gossh.CertChecker).CheckCert(principal, cert), "the certificate does not verify")
		}
	}
	return map[string]sealedValue{
		"ssh_ca_keys.private_key of the user key": {
			table: "ssh_ca_keys", column: "private_key", where: "kind = 'user'",
			read: sign(gossh.UserCert, "deploy", ca.PublicKey),
		},
		"ssh_ca_keys.private_key of the host key": {
			table: "ssh_ca_keys", column: "private_key", where: "kind = 'host'",
			read: sign(gossh.HostCert, "web-1.example.com", ca.HostPublicKey),
		},
	}
}

func seedSSOProvider(t *testing.T, conn *db.Connection, keys *kms.Keyset, ws string) map[string]sealedValue {
	t.Helper()
	providers := func(keys *kms.Keyset) *iam.Service {
		svc, err := iam.New(t.Context(), iam.Deps{Conn: conn, Keyset: keys})
		require.NoError(t, err)
		return svc
	}
	oidc := iam.OIDCProvider{
		IssuerURL:    "https://idp.example.com/realms/nokku",
		ClientID:     "nokku",
		ClientSecret: "sso-client-secret-" + uuid.New().String(),
		Scopes:       []string{"openid", "email"},
	}
	_, err := providers(keys).PutSSOProvider(testenv.Pinned(t, ws), iam.SSOProvider{
		ProviderID: "okta", Name: "Okta", Enabled: true, OIDC: oidc,
	})
	require.NoError(t, err)
	return map[string]sealedValue{"sso_providers.config": {
		table: "sso_providers", column: "config", where: "TRUE",
		plaintext: []byte(oidc.ClientSecret),
		read: func(t *testing.T, keys *kms.Keyset) {
			t.Helper()
			p, err := providers(keys).GetSSOProvider(testenv.Pinned(t, ws), "okta")
			require.NoError(t, err)
			assert.Equal(t, oidc, p.OIDC)
		},
	}}
}

// seedStream reads the secret off what a test send puts on the wire.
func seedStream(t *testing.T, conn *db.Connection, keys *kms.Keyset, ws string) map[string]sealedValue {
	t.Helper()
	got := make(chan string, 1)
	siem := splunk(t, got)
	secret := "hec-token-" + uuid.New().String()
	id := seedAuditStream(t, conn, keys, ws, siem.URL, secret)
	return map[string]sealedValue{"audit_streams.secret": {
		table: "audit_streams", column: "secret", where: "TRUE",
		plaintext: []byte(secret),
		read: func(t *testing.T, keys *kms.Keyset) {
			t.Helper()
			st, err := conn.Tenant().GetAuditStream(testenv.Pinned(t, ws), id)
			require.NoError(t, err)
			require.NoError(t, auditService(t, conn, keys).TestStream(t.Context(), st))
			assert.Equal(t, secret, <-got, "the stream sends another secret")
		},
	}}
}

// seedAuditStream seals the secret like CreateAuditStream. The stream stays
// off, no delivery loop takes it.
func seedAuditStream(t *testing.T, conn *db.Connection, keys *kms.Keyset, ws, url, secret string) string {
	t.Helper()
	id := uuid.NewV7().String()
	sealed, err := keys.Seal(audit.SecretAAD(ws, id), []byte(secret))
	require.NoError(t, err)
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, ws), func(q *db.Queries) error {
		if _, err := q.CreateAuditStream(t.Context(), &db.CreateAuditStreamParams{
			ID: id, Kind: audit.StreamSplunk, URL: url, Secret: sealed,
		}); err != nil {
			return err
		}
		_, err := q.UpdateAuditStream(t.Context(), &db.UpdateAuditStreamParams{ID: id, Enabled: new(false)})
		return err
	}))
	return id
}

// splunk is a HEC endpoint that hands over the token of every request.
func splunk(t *testing.T, got chan<- string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got <- strings.TrimPrefix(r.Header.Get("Authorization"), "Splunk ")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func auditService(t *testing.T, conn *db.Connection, keys *kms.Keyset) *audit.Service {
	t.Helper()
	// The destination listens on loopback.
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")
	plans, err := entitlement.New(t.Context(), conn, "", false)
	require.NoError(t, err)
	svc, err := audit.New(t.Context(), conn, keys, plans)
	require.NoError(t, err)
	return svc
}

// seedRecording stores a session under its key, and reads it back by playing.
func seedRecording(t *testing.T, conn *db.Connection, keys *kms.Keyset, ws string) map[string]sealedValue {
	t.Helper()
	t.Setenv("NOKKU_STORAGE_URL", "file://"+t.TempDir())
	store, err := storage.New(t.Context())
	require.NoError(t, err)
	recorder := func(keys *kms.Keyset) *recording.Service {
		return recording.New(t.Context(), conn, keys, store, recordingLimits{}, nil)
	}

	key := recording.NewKey()
	id := uuid.NewV7().String()
	sealed, err := keys.Seal(recording.KeyAAD(ws, id), key)
	require.NoError(t, err)
	var rec *db.Recording
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, ws), func(q *db.Queries) error {
		d, err := q.CreateDaemon(t.Context(), &db.CreateDaemonParams{
			Status:        nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED,
			Config:        &nokkuv1.DaemonConfig{},
			KeyThumbprint: new(uuid.New().String()),
		})
		if err != nil {
			return err
		}
		_, err = q.CreateDaemonTarget(t.Context(), &db.CreateDaemonTargetParams{DaemonID: &d.ID, Name: "rotation"})
		if err != nil {
			return err
		}
		rec, err = q.CreateRecording(t.Context(), &db.CreateRecordingParams{
			ID: id, DaemonID: d.ID, Username: "deploy", Key: sealed,
		})
		return err
	}))
	session := bytes.Repeat([]byte("$ uptime\r\n 12:00:00 up 1 day, load average: 0.00\r\n"), 200)
	objectID := uuid.NewV7().String()
	w, err := recorder(keys).NewWriter(t.Context(), rec, objectID)
	require.NoError(t, err)
	require.NoError(t, w.WriteChunk(session))
	require.NoError(t, w.Close())
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, ws), func(q *db.Queries) error {
		_, err := q.FinishRecordingUpload(t.Context(), &db.FinishRecordingUploadParams{
			ID: rec.ID, ObjectID: &objectID, SizeBytes: int64(len(session)),
		})
		return err
	}))

	return map[string]sealedValue{"recordings.key": {
		table: "recordings", column: "key", where: "TRUE",
		plaintext: key,
		read: func(t *testing.T, keys *kms.Keyset) {
			t.Helper()
			got, err := conn.Tenant().GetRecording(testenv.Pinned(t, ws), rec.ID)
			require.NoError(t, err)
			r, err := recorder(keys).OpenReader(t.Context(), got)
			require.NoError(t, err)
			defer func() { _ = r.Close() }()
			played, err := io.ReadAll(r)
			require.NoError(t, err, "the session does not decrypt with the stored key")
			assert.Equal(t, session, played)
		},
	}}
}

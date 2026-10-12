//go:build integration

package webpki_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
	"github.com/nokku-sh/nokku/core/internal/webpki"
)

const host = "nokku.test"

func TestMain(m *testing.M) {
	for _, key := range []string{"KMS_URI", "NOKKU_TLS_CA"} {
		os.Unsetenv(key)
	}
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}

// freshConn returns a connection to a database that has no CA yet.
func freshConn(t *testing.T) *db.Connection {
	t.Helper()
	conn, err := db.NewConnection(t.Context())
	require.NoError(t, err)
	enc, err := kms.New(t.Context(), conn, "test-secret-0123456789-0123456789")
	require.NoError(t, err)
	require.NoError(t, crypto.SetEncryptor(enc))
	exec(t, "DELETE FROM web_ca")
	return conn
}

func exec(t *testing.T, sql string) {
	t.Helper()
	admin, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = admin.Close(context.Background()) }()
	_, err = admin.Exec(t.Context(), sql)
	require.NoError(t, err)
}

func start(t *testing.T, conn *db.Connection, name string) *webpki.Identity {
	t.Helper()
	id, err := webpki.New(t.Context(), conn, name)
	require.NoError(t, err)
	return id
}

// direct is a client that connects to the server itself, the one the built-in CA is for.
var direct = actor.RequestMeta{TLS: true}

// advertised is the CA the way a client gets it.
func advertised(t *testing.T, id *webpki.Identity) *x509.Certificate {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, webpki.Path, nil)
	req.TLS = &tls.ConnectionState{}
	id.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	block, rest := pem.Decode(rec.Body.Bytes())
	require.NotNil(t, block)
	require.Empty(t, rest, "the built-in CA is one certificate")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// A restart must not change what clients pinned and installed.
func TestInternalCAIsKeptAcrossStarts(t *testing.T) {
	conn := freshConn(t)
	first := start(t, conn, host)
	second := start(t, conn, host)

	require.NotEmpty(t, first.Pin(direct))
	assert.Equal(t, first.Pin(direct), second.Pin(direct))
	assert.Equal(t, advertised(t, first).Raw, advertised(t, second).Raw)
}

// The root only signs for the host name it was made for, so a new name gets a new root. The key and the pin stay.
func TestInternalCAFollowsANewHostName(t *testing.T) {
	conn := freshConn(t)
	before := start(t, conn, host)
	after := start(t, conn, "moved.test")

	assert.Equal(t, before.Pin(direct), after.Pin(direct))
	assert.Equal(t, []string{"moved.test"}, advertised(t, after).PermittedDNSDomains)

	again := start(t, conn, "moved.test")
	assert.Equal(t, advertised(t, after).Raw, advertised(t, again).Raw, "the new root is stored")
}

// Whoever reads the database must not be able to sign for the server.
func TestInternalCAKeyIsEncryptedAtRest(t *testing.T) {
	conn := freshConn(t)
	start(t, conn, host)

	admin, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = admin.Close(context.Background()) }()
	var raw []byte
	require.NoError(t, admin.QueryRow(t.Context(), "SELECT private_key FROM web_ca").Scan(&raw))
	require.NotEmpty(t, raw)
	_, err = x509.ParsePKCS8PrivateKey(raw)
	require.Error(t, err, "the key sits in the database in the clear")
}

// The steps of nk and nokkud: read the CA unverified, compare it to the pin, then connect with it as the only root.
func TestClientReachesTheServerThroughThePin(t *testing.T) {
	conn := freshConn(t)
	id := start(t, conn, host)

	mux := http.NewServeMux()
	mux.Handle("GET "+webpki.Path, id)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = id.Listener(srv.Listener)
	srv.Start()
	defer srv.Close()

	// The test server listens on an address, the name is nokku.test.
	client := func(conf *tls.Config) *http.Client {
		conf.ServerName = host
		return &http.Client{Transport: &http.Transport{
			TLSClientConfig:   conf,
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
			},
		}}
	}

	// Unverified on purpose, the pin check follows.
	res, err := client(&tls.Config{InsecureSkipVerify: true}).Get("https://" + host + webpki.Path)
	require.NoError(t, err)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	_ = res.Body.Close()
	block, _ := pem.Decode(body)
	require.NotNil(t, block)
	ca, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	sum := sha256.Sum256(ca.RawSubjectPublicKeyInfo)
	require.Equal(t, id.Pin(direct), "sha256:"+hex.EncodeToString(sum[:]))

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	res, err = client(&tls.Config{RootCAs: roots}).Get("https://" + host + "/healthz")
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, 2, res.ProtoMajor, "the daemon streams need HTTP/2")
	assert.EqualValues(t, tls.VersionTLS13, res.TLS.Version)

	_, err = client(&tls.Config{}).Get("https://" + host + "/healthz")
	require.Error(t, err, "without the CA the server is not trusted")
}

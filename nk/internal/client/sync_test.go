package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/nk/internal/paths"
	"github.com/nokku-sh/nokku/nk/internal/ssh"
	"github.com/nokku-sh/nokku/nk/internal/state"
)

// fakeBackend implements the two connect services the CLI syncs against:
// GetMyAccess for the snapshot and SignSSHCertificate for issuance.
type fakeBackend struct {
	nokkuv1connect.UnimplementedTargetServiceHandler
	nokkuv1connect.UnimplementedCertificateServiceHandler

	access    *nokkuv1.GetMyAccessResponse
	accessErr error
	test      *testing.T
	sign      func(t *testing.T, req *nokkuv1.SignSSHCertificateRequest) (*nokkuv1.SignSSHCertificateResponse, error)
}

func (f *fakeBackend) GetMyAccess(
	context.Context,
	*nokkuv1.GetMyAccessRequest,
) (*nokkuv1.GetMyAccessResponse, error) {
	return f.access, f.accessErr
}

func (f *fakeBackend) SignSSHCertificate(
	_ context.Context,
	req *nokkuv1.SignSSHCertificateRequest,
) (*nokkuv1.SignSSHCertificateResponse, error) {
	if f.sign == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, assert.AnError)
	}
	return f.sign(f.test, req)
}

// fakeCA signs test SSH certificates and exposes its public key in
// authorized_keys form, like the backend CAs do.
type fakeCA struct {
	signer cryptossh.Signer
	pubKey string
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := cryptossh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return &fakeCA{
		signer: signer,
		pubKey: string(cryptossh.MarshalAuthorizedKey(signer.PublicKey())),
	}
}

// signCert signs the given key into a user certificate valid from an hour
// ago until validFor from now.
func (f *fakeCA) signCert(t *testing.T, key cryptossh.PublicKey, validFor time.Duration) string {
	t.Helper()
	cert := &cryptossh.Certificate{
		Key:         key,
		CertType:    cryptossh.UserCert,
		ValidAfter:  uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore: uint64(time.Now().Add(validFor).Unix()),
	}
	require.NoError(t, cert.SignCert(rand.Reader, f.signer))
	return string(cryptossh.MarshalAuthorizedKey(cert))
}

// signRequest signs the public key carried by an issuance request.
func (f *fakeCA) signRequest(t *testing.T, req *nokkuv1.SignSSHCertificateRequest) string {
	t.Helper()
	pub, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(req.GetPublicKey()))
	require.NoError(t, err, "issuance request carries an unparsable public key")
	return f.signCert(t, pub, time.Hour)
}

const (
	caID     = "0199a0a0-0000-7000-8000-000000000002"
	targetID = "0199a0a0-0000-7000-8000-000000000003"
)

// setTestDirs points home at a fresh temp dir and creates what EnsureDirs
// would create at startup.
func setTestDirs(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsureDirs())
}

func newSyncTestClient(t *testing.T, backend *fakeBackend) *Client {
	t.Helper()
	backend.test = t
	mux := http.NewServeMux()
	targetPath, targetHandler := nokkuv1connect.NewTargetServiceHandler(backend)
	certPath, certHandler := nokkuv1connect.NewCertificateServiceHandler(backend)
	mux.Handle(targetPath, targetHandler)
	mux.Handle(certPath, certHandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := &Client{State: &state.State{APIURL: srv.URL, SessionToken: "sess-token"}, httpc: srv.Client()}
	c.certs = nokkuv1connect.NewCertificateServiceClient(srv.Client(), srv.URL)
	c.targets = nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL)
	return c
}

func accessResponse(caPubKey string) *nokkuv1.GetMyAccessResponse {
	return &nokkuv1.GetMyAccessResponse{
		Subject: &nokkuv1.GetMyAccessResponse_User{
			User: &nokkuv1.User{Id: new("user-1"), Name: new("alice")},
		},
		Targets: []*nokkuv1.Target{{
			Id:        new(targetID),
			Name:      new("prod"),
			CaId:      new(caID),
			Usernames: []string{"alice"},
		}},
		CertificateAuthorities: []*nokkuv1.CertificateAuthority{{
			Id:        new(caID),
			Name:      new("Production CA"),
			PublicKey: new(caPubKey),
		}},
	}
}

func TestSyncCommitsAccessSnapshot(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	backend := &fakeBackend{access: accessResponse(ca.pubKey)}
	c := newSyncTestClient(t, backend)

	c.State.FailedAt = time.Now()
	require.NoError(t, c.Sync(t.Context(), false))
	assert.False(t, c.State.SyncFailedWithin(time.Minute), "a sync that worked ends the outage")

	assert.Equal(t, "user-1", c.State.User.ID)
	require.Len(t, c.State.Targets, 1)
	assert.Equal(t, "prod", c.State.Targets[0].Name)
	require.Len(t, c.State.CAs, 1)
	assert.Equal(t, ca.pubKey, c.State.CAs[0].PublicKey)

	// The snapshot is committed to disk for offline use.
	assert.NotNil(t, state.Load().User)

	// And the derived SSH config was regenerated.
	content, err := os.ReadFile(paths.SSHConfigFile())
	require.NoError(t, err)
	assert.Contains(t, string(content), "Host prod\n")
}

func TestSyncUnauthenticatedNonInteractive(t *testing.T) {
	setTestDirs(t)
	backend := &fakeBackend{
		accessErr: connect.NewError(connect.CodeUnauthenticated, assert.AnError),
	}
	c := newSyncTestClient(t, backend)

	err := c.Sync(t.Context(), false)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err),
		"a session rejection must surface as Unauthenticated so interactive callers re-login")
}

func TestSyncOrCacheFallsBackToCache(t *testing.T) {
	setTestDirs(t)

	st := &state.State{APIURL: "http://127.0.0.1:1", SessionToken: "sess-token"}
	st.Targets = []state.Target{{ID: "t-1", Name: "prod"}}
	st.User = &state.User{ID: "user-1"}
	require.NoError(t, st.Save())

	c := &Client{State: st}
	c.certs = nokkuv1connect.NewCertificateServiceClient(&http.Client{}, st.APIURL)
	c.targets = nokkuv1connect.NewTargetServiceClient(&http.Client{}, st.APIURL)
	err := c.SyncOrCache(t.Context(), false)
	require.NoError(t, err, "unreachable backend must fall back to cached data")
	assert.True(t, st.HasCachedData())
	assert.True(t, state.Load().SyncFailedWithin(time.Minute),
		"the outage must be on disk, the next ssh is another process")
}

// nk --api b with server a's snapshot on disk and b out of reach.
func TestSyncOrCacheNeverFallsBackToAnotherServer(t *testing.T) {
	setTestDirs(t)
	require.NoError(t, (&state.State{
		APIURL: "https://a.example", SessionToken: "sess-a",
		Server:  "https://a.example",
		User:    &state.User{ID: "user-1"},
		Targets: []state.Target{{ID: "t-1", Name: "a-prod"}},
	}).Save())

	st := &state.State{APIURL: "http://127.0.0.1:1"}
	c := &Client{State: st}
	c.targets = nokkuv1connect.NewTargetServiceClient(&http.Client{}, st.APIURL)
	err := c.SyncOrCache(t.Context(), false)
	require.ErrorContains(t, err, "nothing is cached yet")
	assert.Empty(t, st.Targets)
}

func TestSyncOrCacheWithoutCacheFails(t *testing.T) {
	setTestDirs(t)

	st := &state.State{APIURL: "http://127.0.0.1:1", SessionToken: "sess-token"}
	c := &Client{State: st}
	c.certs = nokkuv1connect.NewCertificateServiceClient(&http.Client{}, st.APIURL)
	c.targets = nokkuv1connect.NewTargetServiceClient(&http.Client{}, st.APIURL)
	err := c.SyncOrCache(t.Context(), false)
	assert.ErrorContains(t, err, "nothing is cached yet")
}

func TestEnsureCertFreshIsNoOp(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	require.NoError(t, ssh.SetupKey(false))
	cliPub, err := ssh.PubKey()
	require.NoError(t, err)

	pub, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(cliPub))
	require.NoError(t, err)
	fresh := ca.signCert(t, pub, 2*time.Hour)
	certPath := paths.SSHCertificate(targetID)
	require.NoError(t, os.WriteFile(certPath, []byte(fresh), 0o600))

	c := &Client{State: &state.State{APIURL: "http://127.0.0.1:1", SessionToken: "sess-token"}}
	err = c.EnsureCert(t.Context(), state.Target{ID: targetID}, state.CA{
		ID: caID, PublicKey: ca.pubKey,
	})
	require.NoError(t, err, "a fresh certificate must not trigger a re-sign")
}

func TestEnsureCertSignsAndWritesCert(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	require.NoError(t, ssh.SetupKey(false))

	backend := &fakeBackend{
		sign: func(t *testing.T, req *nokkuv1.SignSSHCertificateRequest) (*nokkuv1.SignSSHCertificateResponse, error) {
			assert.Equal(t, targetID, req.GetTargetId(), "a certificate is asked for one server")
			return &nokkuv1.SignSSHCertificateResponse{
				CaId:              new(caID),
				SignedCertificate: new(ca.signRequest(t, req)),
			}, nil
		},
	}
	c := newSyncTestClient(t, backend)

	err := c.EnsureCert(t.Context(), state.Target{ID: targetID}, state.CA{ID: caID, PublicKey: ca.pubKey})
	require.NoError(t, err)

	certPath := paths.SSHCertificate(targetID)
	signed, err := os.ReadFile(certPath)
	require.NoError(t, err)
	require.NoError(t, ssh.CheckCert(signed, ca.pubKey, 0),
		"the written certificate must pass local validation")
}

// A certificate past half of its life is renewed while it still works, so a
// backend outage never finds it about to expire. When signing fails the old
// one stays.
func TestEnsureCertRenewsPastHalfLife(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	require.NoError(t, ssh.SetupKey(false))
	cliPub, err := ssh.PubKey()
	require.NoError(t, err)
	pub, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(cliPub))
	require.NoError(t, err)

	// Issued an hour ago with half an hour left.
	aging := ca.signCert(t, pub, 30*time.Minute)
	certPath := paths.SSHCertificate(targetID)
	require.NoError(t, os.WriteFile(certPath, []byte(aging), 0o600))
	target := state.Target{ID: targetID}
	authority := state.CA{ID: caID, PublicKey: ca.pubKey}
	require.True(t, ssh.CertValid(target, authority, 0))

	backend := &fakeBackend{}
	c := newSyncTestClient(t, backend)
	require.Error(t, c.EnsureCert(t.Context(), target, authority), "the backend refused to sign")
	kept, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, aging, string(kept), "a failed renewal must leave the working certificate")

	backend.sign = func(t *testing.T, _ *nokkuv1.SignSSHCertificateRequest) (*nokkuv1.SignSSHCertificateResponse, error) {
		return &nokkuv1.SignSSHCertificateResponse{
			SignedCertificate: new(ca.signCert(t, pub, 3*time.Hour)),
		}, nil
	}
	require.NoError(t, c.EnsureCert(t.Context(), target, authority))
	renewed, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.NotEqual(t, aging, string(renewed), "the aging certificate was not renewed")
	assert.True(t, ssh.CertFresh(target, authority))
}

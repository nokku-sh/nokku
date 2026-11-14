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

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

const (
	targetID = "0199a0a0-0000-7000-8000-000000000003"
)

// fakeCore serves the two calls the CLI syncs against.
type fakeCore struct {
	nokkuv1connect.UnimplementedTargetServiceHandler
	nokkuv1connect.UnimplementedCertificateServiceHandler

	access    *nokkuv1.GetSubjectAccessResponse
	accessErr error
	sign      func(*nokkuv1.SignSSHCertificateRequest) (*nokkuv1.SignSSHCertificateResponse, error)
}

// fakeCA shows its key in authorized_keys form, like a core CA.
type fakeCA struct {
	signer cryptossh.Signer
	pubKey string
}

func (f *fakeCore) GetSubjectAccess(
	context.Context,
	*nokkuv1.GetSubjectAccessRequest,
) (*nokkuv1.GetSubjectAccessResponse, error) {
	return f.access, f.accessErr
}

func (f *fakeCore) SignSSHCertificate(
	_ context.Context,
	req *nokkuv1.SignSSHCertificateRequest,
) (*nokkuv1.SignSSHCertificateResponse, error) {
	if f.sign == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, assert.AnError.Error()).WithCause(assert.AnError)
	}
	return f.sign(req)
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

// signCert's certificate is valid from an hour ago until validFor from now.
func (f *fakeCA) signCert(t *testing.T, key cryptossh.PublicKey, validFor time.Duration) string {
	t.Helper()
	cert := &cryptossh.Certificate{
		Key:             key,
		CertType:        cryptossh.UserCert,
		ValidPrincipals: []string{"subject@target:deploy"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(validFor).Unix()),
	}
	require.NoError(t, cert.SignCert(rand.Reader, f.signer))
	return string(cryptossh.MarshalAuthorizedKey(cert))
}

func setTestDirs(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsureDirs())
}

func setupKey(t *testing.T) {
	t.Helper()
	require.NoError(t, ssh.SetupKey(&state.State{}))
}

func newSyncTestClient(t *testing.T, core *fakeCore) *Client {
	t.Helper()
	mux := http.NewServeMux()
	server := connect.NewServer()
	nokkuv1connect.RegisterTargetServiceHandler(server, core)
	nokkuv1connect.RegisterCertificateServiceHandler(server, core)
	connecthttp.Mount(mux, server)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := &Client{State: &state.State{APIURL: srv.URL, SessionToken: "sess-token"}, httpc: srv.Client()}
	c.certs = nokkuv1connect.NewCertificateServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)),
	)
	c.targets = nokkuv1connect.NewTargetServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)),
	)
	return c
}

func accessResponse(caPubKey string) *nokkuv1.GetSubjectAccessResponse {
	return &nokkuv1.GetSubjectAccessResponse{
		Subject: &nokkuv1.GetSubjectAccessResponse_User{
			User: &nokkuv1.User{Id: new("user-1"), Name: new("alice")},
		},
		Targets: []*nokkuv1.Target{{
			Id:        new(targetID),
			Name:      new("prod"),
			Usernames: []string{"alice"},
		}},
		CertificateAuthority: &nokkuv1.CertificateAuthority{UserPublicKey: new(caPubKey)},
	}
}

func TestSyncCommitsAccessSnapshot(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	core := &fakeCore{access: accessResponse(ca.pubKey)}
	c := newSyncTestClient(t, core)

	c.State.FailedAt = time.Now()
	require.NoError(t, c.Sync(t.Context(), false))
	assert.False(t, c.State.SyncFailedWithin(time.Minute), "a sync that worked ends the outage")

	assert.Equal(t, "user-1", c.State.User.ID)
	require.Len(t, c.State.Targets, 1)
	assert.Equal(t, "prod", c.State.Targets[0].Name)
	require.NotNil(t, c.State.CA)
	assert.Equal(t, ca.pubKey, c.State.CA.UserPublicKey)

	// The snapshot is committed to disk for offline use.
	assert.NotNil(t, state.Load().User)

	content, err := os.ReadFile(paths.SSHConfigFile())
	require.NoError(t, err)
	assert.Contains(t, string(content), "Host prod\n")
}

func TestSyncDropsCertificatesOfAnotherSubject(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	c := newSyncTestClient(t, &fakeCore{access: accessResponse(ca.pubKey)})
	certPath := paths.SSHCertificate(targetID)

	c.State.User = &state.User{ID: "user-1"}
	require.NoError(t, os.WriteFile(certPath, []byte("cert"), 0o600))
	require.NoError(t, c.Sync(t.Context(), false))
	assert.FileExists(t, certPath, "the same subject keeps its certificates")

	c.State.User = &state.User{ID: "user-2"}
	require.NoError(t, c.Sync(t.Context(), false))
	assert.NoFileExists(t, certPath, "the next user signed in on this account must not use them")
}

func TestSyncUnauthenticatedNonInteractive(t *testing.T) {
	setTestDirs(t)
	core := &fakeCore{
		accessErr: connect.NewError(connect.CodeUnauthenticated, assert.AnError.Error()).WithCause(assert.AnError),
	}
	c := newSyncTestClient(t, core)

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
	c.certs = nokkuv1connect.NewCertificateServiceClient(
		connect.NewClient(connecthttp.NewTransport(&http.Client{}, st.APIURL)),
	)
	c.targets = nokkuv1connect.NewTargetServiceClient(
		connect.NewClient(connecthttp.NewTransport(&http.Client{}, st.APIURL)),
	)
	err := c.SyncOrCache(t.Context(), false)
	require.NoError(t, err, "unreachable core must fall back to cached data")
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
	c.targets = nokkuv1connect.NewTargetServiceClient(
		connect.NewClient(connecthttp.NewTransport(&http.Client{}, st.APIURL)),
	)
	err := c.SyncOrCache(t.Context(), false)
	require.ErrorContains(t, err, "nothing is cached yet")
	assert.Empty(t, st.Targets)
}

func TestSyncOrCacheWithoutCacheFails(t *testing.T) {
	setTestDirs(t)

	st := &state.State{APIURL: "http://127.0.0.1:1", SessionToken: "sess-token"}
	c := &Client{State: st}
	c.certs = nokkuv1connect.NewCertificateServiceClient(
		connect.NewClient(connecthttp.NewTransport(&http.Client{}, st.APIURL)),
	)
	c.targets = nokkuv1connect.NewTargetServiceClient(
		connect.NewClient(connecthttp.NewTransport(&http.Client{}, st.APIURL)),
	)
	err := c.SyncOrCache(t.Context(), false)
	assert.ErrorContains(t, err, "nothing is cached yet")
}

func TestEnsureCertFreshIsNoOp(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	setupKey(t)
	cliPub, err := ssh.PubKey()
	require.NoError(t, err)

	pub, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(cliPub))
	require.NoError(t, err)
	fresh := ca.signCert(t, pub, 2*time.Hour)
	certPath := paths.SSHCertificate(targetID)
	require.NoError(t, os.WriteFile(certPath, []byte(fresh), 0o600))

	c := &Client{State: &state.State{APIURL: "http://127.0.0.1:1", SessionToken: "sess-token"}}
	err = c.EnsureCert(t.Context(), state.Target{ID: targetID}, state.CA{
		UserPublicKey: ca.pubKey,
	})
	require.NoError(t, err, "a fresh certificate must not trigger a re-sign")
}

func TestEnsureCertSignsAndWritesCert(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	setupKey(t)
	cliPub, err := ssh.PubKey()
	require.NoError(t, err)
	pub, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(cliPub))
	require.NoError(t, err)
	issued := ca.signCert(t, pub, time.Hour)

	core := &fakeCore{
		sign: func(req *nokkuv1.SignSSHCertificateRequest) (*nokkuv1.SignSSHCertificateResponse, error) {
			assert.Equal(t, targetID, req.GetTargetId(), "a certificate is asked for one server")
			assert.Equal(t, cliPub, req.GetPublicKey(), "the request must carry nk's key")
			return &nokkuv1.SignSSHCertificateResponse{SignedCertificate: new(issued)}, nil
		},
	}
	c := newSyncTestClient(t, core)

	err = c.EnsureCert(t.Context(), state.Target{ID: targetID}, state.CA{UserPublicKey: ca.pubKey})
	require.NoError(t, err)

	certPath := paths.SSHCertificate(targetID)
	signed, err := os.ReadFile(certPath)
	require.NoError(t, err)
	require.NoError(t, ssh.CheckCert(signed, ca.pubKey, 0),
		"the written certificate must pass local validation")
}

// Renewed past half its life, so an outage never finds it near expiry.
func TestEnsureCertRenewsPastHalfLife(t *testing.T) {
	setTestDirs(t)
	ca := newFakeCA(t)
	setupKey(t)
	cliPub, err := ssh.PubKey()
	require.NoError(t, err)
	pub, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(cliPub))
	require.NoError(t, err)

	// Issued an hour ago with half an hour left.
	aging := ca.signCert(t, pub, 30*time.Minute)
	certPath := paths.SSHCertificate(targetID)
	require.NoError(t, os.WriteFile(certPath, []byte(aging), 0o600))
	target := state.Target{ID: targetID}
	authority := state.CA{UserPublicKey: ca.pubKey}
	require.True(t, ssh.CertValid(target, authority, 0))

	core := &fakeCore{}
	c := newSyncTestClient(t, core)
	require.Error(t, c.EnsureCert(t.Context(), target, authority), "the core refused to sign")
	kept, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, aging, string(kept), "a failed renewal must leave the working certificate")

	issued := ca.signCert(t, pub, 3*time.Hour)
	core.sign = func(*nokkuv1.SignSSHCertificateRequest) (*nokkuv1.SignSSHCertificateResponse, error) {
		return &nokkuv1.SignSSHCertificateResponse{SignedCertificate: new(issued)}, nil
	}
	require.NoError(t, c.EnsureCert(t.Context(), target, authority))
	renewed, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.NotEqual(t, aging, string(renewed), "the aging certificate was not renewed")
	assert.True(t, ssh.CertFresh(target, authority))
}

// A private CA reaches nk through --ca-file only, the error names the flag.
func TestSyncUntrustedServerNamesCAFile(t *testing.T) {
	setTestDirs(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c := &Client{State: &state.State{APIURL: srv.URL, Token: "nk_sa_test"}}
	require.NoError(t, c.dial())

	err := c.Sync(t.Context(), true)
	require.ErrorContains(t, err, "--ca-file")
	assert.Empty(t, c.State.APICA, "no CA is kept without the file")
}

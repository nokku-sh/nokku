//go:build integration && smoke

package smoke_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

const (
	ciAccount    = "deploy"
	jobSubject   = "repo:acme/app:ref:refs/heads/main"
	runnerSecret = "runner-request-token"
)

// jobPlatform is what GitHub Actions is to a job: it signs tokens, and a runner
// asks it for one over a URL it was given.
type jobPlatform struct {
	srv *httptest.Server
	// certFile lets the core trust the issuer, it only takes one over https.
	certFile string
}

func startJobPlatform(t *testing.T) *jobPlatform {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &jobPlatform{}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		answer(w, map[string]any{
			"issuer":                                p.srv.URL,
			"jwks_uri":                              p.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		answer(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: "job", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer "+runnerSecret {
			http.Error(w, "not a runner", http.StatusUnauthorized)
			return
		}
		now := time.Now()
		signed, err := signJobToken(key, map[string]any{
			"iss": p.srv.URL,
			"aud": r.URL.Query().Get("audience"),
			"sub": jobSubject,
			"exp": now.Add(10 * time.Minute).Unix(),
			"iat": now.Unix(),
			"jti": uuid.New().String(),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		answer(w, map[string]string{"value": signed})
	})
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)

	p.certFile = filepath.Join(t.TempDir(), "platform.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(p.certFile, block, 0o600))
	return p
}

func answer(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func signJobToken(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "job"}},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

// ciJob is a job on a runner: it holds no secret, signs in with what its
// platform gives it and reaches the server.
func (s *smoke) ciJob(t *testing.T) {
	accounts := nokkuv1connect.NewServiceAccountServiceClient(s.client)
	created, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new(ciAccount),
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()
	_, err = accounts.AddServiceAccountFederation(t.Context(), &nokkuv1.AddServiceAccountFederationRequest{
		ServiceAccountId: new(id),
		Issuer:           new(s.platform.srv.URL),
		Claims:           map[string]string{"sub": jobSubject},
	})
	require.NoError(t, err)
	_, err = s.targetAccounts.AddSubjects(t.Context(), &nokkuv1.AddSubjectsRequest{
		Id:         new(s.devAccount.GetId()),
		SubjectIds: []string{id},
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_SERVICE_ACCOUNT.Enum(),
	})
	require.NoError(t, err)

	job := newNKHome(t, filepath.Dir(s.home.nkBinary), s.home.sshBinary)
	job.env = append(job.env,
		"NK_API_URL="+s.core.url,
		"ACTIONS_ID_TOKEN_REQUEST_URL="+s.platform.srv.URL+"/token",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN="+runnerSecret,
		// nk talks to the platform itself on a runner.
		"SSL_CERT_FILE="+s.platform.certFile,
	)

	out, err := job.nk(t, "login", "--ci", ciAccount).CombinedOutput()
	require.NoError(t, err, "nk login --ci: %s", out)

	// The daemon learns the grant from a sync, the first tries may be too
	// early.
	var last []byte
	waitFor(t, time.Minute, func() bool {
		last, err = job.ssh(t, login, "echo smoke-ci").CombinedOutput()
		return err == nil
	}, "the job never reached the server: %s", &last)
	assert.Contains(t, string(last), "smoke-ci")

	exchanges := s.auditLogs(t, "ExchangeWorkloadToken")
	require.NotEmpty(t, exchanges, "the exchange left no audit row")
	assert.True(t, exchanges[0].GetOk())

	_, err = accounts.DeleteServiceAccount(t.Context(), &nokkuv1.DeleteServiceAccountRequest{Id: new(id)})
	require.NoError(t, err)
	// A job with no session fails and says so, nobody can approve a sign-in.
	out, err = job.nk(t, "ls").CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(out), "run nk login --ci")
	out, err = job.ssh(t, login, "echo smoke-ci").CombinedOutput()
	assert.Error(t, err, "the deleted account still reached the server: %s", out)
}

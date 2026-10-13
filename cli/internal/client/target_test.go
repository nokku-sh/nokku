package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

// captureTargetService records the requests and answers a create with the
// target the backend would have made.
type captureTargetService struct {
	nokkuv1connect.UnimplementedTargetServiceHandler

	got     *nokkuv1.CreateTargetRequest
	deleted *nokkuv1.DeleteTargetRequest
}

func (s *captureTargetService) DeleteTarget(
	_ context.Context,
	req *nokkuv1.DeleteTargetRequest,
) (*nokkuv1.DeleteTargetResponse, error) {
	s.deleted = req
	return &nokkuv1.DeleteTargetResponse{}, nil
}

func (s *captureTargetService) CreateTarget(
	_ context.Context,
	req *nokkuv1.CreateTargetRequest,
) (*nokkuv1.CreateTargetResponse, error) {
	s.got = req
	return &nokkuv1.CreateTargetResponse{Target: &nokkuv1.Target{
		Id:   new("target-1"),
		Name: new("fair-juniper"),
	}}, nil
}

func TestCreateTarget(t *testing.T) {
	t.Parallel()

	svc := &captureTargetService{}
	mux := http.NewServeMux()
	mux.Handle(nokkuv1connect.NewTargetServiceHandler(svc))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	c := &Client{State: &state.State{APIURL: server.URL, SessionToken: "sess-token"}}
	c.targets = nokkuv1connect.NewTargetServiceClient(http.DefaultClient, server.URL)

	created, err := c.CreateTarget(t.Context(), &state.Target{
		CAID: "ca-1", HostPublicKey: "ssh-ed25519 AAAA", Endpoints: []string{"10.0.0.5"},
	}, []string{"prod"}, []Grant{{Account: "deploy", Users: []string{"user-1"}, Teams: []string{"team-1"}}})
	require.NoError(t, err)

	assert.Equal(t, "fair-juniper", created.Name, "the server-generated name comes back")
	assert.Equal(t, "ca-1", created.CAID)
	require.NotNil(t, svc.got)
	assert.Empty(t, svc.got.GetName(), "an empty name asks the server to generate one")
	assert.Equal(t, "ca-1", svc.got.GetCaId())
	assert.Equal(t, []string{"10.0.0.5"}, svc.got.GetEndpoints())
	assert.Equal(t, "ssh-ed25519 AAAA", svc.got.GetHostPublicKey())
	assert.Equal(t, []string{"prod"}, svc.got.GetTags())
	require.Len(t, svc.got.GetGrants(), 1)
	assert.Equal(t, "deploy", svc.got.GetGrants()[0].GetUsername())
	assert.Equal(t, []string{"user-1"}, svc.got.GetGrants()[0].GetUserIds())
	assert.Equal(t, []string{"team-1"}, svc.got.GetGrants()[0].GetTeamIds())
}

func TestDeleteTarget(t *testing.T) {
	t.Parallel()

	svc := &captureTargetService{}
	mux := http.NewServeMux()
	mux.Handle(nokkuv1connect.NewTargetServiceHandler(svc))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	c := &Client{State: &state.State{APIURL: server.URL, SessionToken: "sess-token"}}
	c.targets = nokkuv1connect.NewTargetServiceClient(http.DefaultClient, server.URL)

	require.NoError(t, c.DeleteTarget(t.Context(), &state.Target{ID: "target-1"}))
	require.NotNil(t, svc.deleted)
	assert.Equal(t, "target-1", svc.deleted.GetId())
}

type listCAService struct {
	nokkuv1connect.UnimplementedCertificateServiceHandler
}

func (listCAService) ListCertificateAuthorities(
	context.Context,
	*nokkuv1.ListCertificateAuthoritiesRequest,
) (*nokkuv1.ListCertificateAuthoritiesResponse, error) {
	return &nokkuv1.ListCertificateAuthoritiesResponse{
		CertificateAuthorities: []*nokkuv1.CertificateAuthority{
			{
				Id:        new("0199a0a0-0000-7000-8000-000000000001"),
				Name:      new("default"),
				PublicKey: new("ssh-ed25519 AAAA"),
				IsActive:  new(true),
				IsDefault: new(true),
			},
			{Id: new("0199a0a0-0000-7000-8000-000000000002"), Name: new("retired")},
		},
	}, nil
}

// A CA without targets is missing from the access sync, nk sync still needs it.
func TestListSSHCAs(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.Handle(nokkuv1connect.NewCertificateServiceHandler(listCAService{}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	c := &Client{State: &state.State{APIURL: server.URL, SessionToken: "sess-token"}}
	c.certs = nokkuv1connect.NewCertificateServiceClient(http.DefaultClient, server.URL)

	cas, err := c.ListSSHCAs(t.Context())
	require.NoError(t, err)
	require.Len(t, cas, 1, "inactive CAs are left out")
	assert.Equal(t, "default", cas[0].Name)
	assert.True(t, cas[0].Default)
	assert.Equal(t, "ssh-ed25519 AAAA", cas[0].PublicKey)
}

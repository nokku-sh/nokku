package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

// captureTargetService records requests, and answers a create like the core.
type captureTargetService struct {
	nokkuv1connect.UnimplementedTargetServiceHandler

	got     *nokkuv1.CreateTargetRequest
	deleted *nokkuv1.DeleteTargetRequest
}

type workspaceCAService struct {
	nokkuv1connect.UnimplementedCertificateServiceHandler

	rotatedAt time.Time
}

type pagedTargetService struct {
	nokkuv1connect.UnimplementedTargetServiceHandler

	total int
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
	srv := connect.NewServer()
	nokkuv1connect.RegisterTargetServiceHandler(srv, svc)
	connecthttp.Mount(mux, srv)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	c := &Client{State: &state.State{APIURL: server.URL, SessionToken: "sess-token"}}
	c.targets = nokkuv1connect.NewTargetServiceClient(
		connect.NewClient(connecthttp.NewTransport(http.DefaultClient, server.URL)),
	)

	created, err := c.CreateTarget(t.Context(), &state.Target{
		HostPublicKey: "ssh-ed25519 AAAA", Endpoints: []string{"10.0.0.5"},
	}, []string{"prod"}, []Grant{{Account: "deploy", Users: []string{"user-1"}, Teams: []string{"team-1"}}})
	require.NoError(t, err)

	assert.Equal(t, "fair-juniper", created.Name, "the server-generated name comes back")
	require.NotNil(t, svc.got)
	assert.Empty(t, svc.got.GetName(), "an empty name asks the server to generate one")
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
	srv := connect.NewServer()
	nokkuv1connect.RegisterTargetServiceHandler(srv, svc)
	connecthttp.Mount(mux, srv)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	c := &Client{State: &state.State{APIURL: server.URL, SessionToken: "sess-token"}}
	c.targets = nokkuv1connect.NewTargetServiceClient(
		connect.NewClient(connecthttp.NewTransport(http.DefaultClient, server.URL)),
	)

	require.NoError(t, c.DeleteTarget(t.Context(), &state.Target{ID: "target-1"}))
	require.NotNil(t, svc.deleted)
	assert.Equal(t, "target-1", svc.deleted.GetId())
}

func (s workspaceCAService) GetCertificateAuthority(
	context.Context,
	*nokkuv1.GetCertificateAuthorityRequest,
) (*nokkuv1.GetCertificateAuthorityResponse, error) {
	return &nokkuv1.GetCertificateAuthorityResponse{
		CertificateAuthority: &nokkuv1.CertificateAuthority{
			UserPublicKey: new("ssh-ed25519 AAAA"),
			RotatedAt:     timestamppb.New(s.rotatedAt),
		},
	}, nil
}

// nk sync asks the core, a subject with no targets gets no CA in its sync.
func TestWorkspaceCA(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	srv := connect.NewServer()
	rotatedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	nokkuv1connect.RegisterCertificateServiceHandler(srv, workspaceCAService{rotatedAt: rotatedAt})
	connecthttp.Mount(mux, srv)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	c := &Client{State: &state.State{APIURL: server.URL, SessionToken: "sess-token"}}
	c.certs = nokkuv1connect.NewCertificateServiceClient(
		connect.NewClient(connecthttp.NewTransport(http.DefaultClient, server.URL)),
	)

	ca, err := c.WorkspaceCA(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "ssh-ed25519 AAAA", ca.UserPublicKey)
	assert.True(t, rotatedAt.Equal(ca.RotatedAt))
}

func (s pagedTargetService) ListTargets(
	_ context.Context,
	req *nokkuv1.ListTargetsRequest,
) (*nokkuv1.ListTargetsResponse, error) {
	res := nokkuv1.ListTargetsResponse{Total: new(int32(s.total))}
	for i := int(req.GetOffset()); i < min(s.total, int(req.GetOffset()+req.GetLimit())); i++ {
		res.Targets = append(res.Targets, &nokkuv1.Target{
			Id:   new(fmt.Sprintf("0199a0a0-0000-7000-8000-%012d", i)),
			Name: new(fmt.Sprintf("t%d", i)),
		})
	}
	return &res, nil
}

func TestListAllTargetsPages(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	srv := connect.NewServer()
	nokkuv1connect.RegisterTargetServiceHandler(srv, pagedTargetService{total: 2*lookupLimit + 3})
	connecthttp.Mount(mux, srv)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	c := &Client{State: &state.State{APIURL: server.URL}}
	c.targets = nokkuv1connect.NewTargetServiceClient(
		connect.NewClient(connecthttp.NewTransport(http.DefaultClient, server.URL)),
	)

	targets, err := c.ListAllTargets(t.Context())
	require.NoError(t, err)
	require.Len(t, targets, 2*lookupLimit+3, "every page is read")
	assert.Equal(t, "t0", targets[0].Name)
	assert.Equal(t, fmt.Sprintf("t%d", 2*lookupLimit+2), targets[len(targets)-1].Name)
}

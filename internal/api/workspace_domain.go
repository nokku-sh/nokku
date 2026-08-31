package api

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/config"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/iam"
)

// Workspace domain storage and verification live in the iam domains manager;
// this service only maps them to the API surface. The binding's provider is
// the workspace itself, matching the provider id convention.

type WorkspaceDomainService struct {
	cfg *config.Config
}

func NewWorkspaceDomainService(cfg *config.Config) *WorkspaceDomainService {
	return &WorkspaceDomainService{cfg: cfg}
}

func (s *WorkspaceDomainService) GetWorkspaceDomain(
	ctx context.Context,
	req *nokkuv1.GetWorkspaceDomainRequest,
) (*nokkuv1.GetWorkspaceDomainResponse, error) {
	result, err := s.cfg.IAM.GetTenantDomain(ctx, req.GetWorkspaceId(), req.GetDomain())
	if err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.GetWorkspaceDomainResponse{
		Domain: domainToProto(result),
	}, nil
}

func (s *WorkspaceDomainService) CreateWorkspaceDomain(
	ctx context.Context,
	req *nokkuv1.CreateWorkspaceDomainRequest,
) (*nokkuv1.CreateWorkspaceDomainResponse, error) {
	result, err := s.cfg.IAM.PutTenantDomain(ctx, req.GetWorkspaceId(), req.GetDomain())
	if err != nil {
		fmt.Printf("err.Error(): %v\n", err.Error())
		return nil, DBError(err)
	}
	return &nokkuv1.CreateWorkspaceDomainResponse{
		Domain: domainToProto(result),
	}, nil
}

func (s *WorkspaceDomainService) ListWorkspaceDomains(
	ctx context.Context,
	req *nokkuv1.ListWorkspaceDomainsRequest,
) (*nokkuv1.ListWorkspaceDomainsResponse, error) {
	result, err := s.cfg.IAM.ListTenantDomains(ctx, req.GetWorkspaceId())
	if err != nil {
		return nil, DBError(err)
	}
	domains := make([]*nokkuv1.WorkspaceDomain, 0, len(result))
	for _, d := range result {
		domains = append(domains, domainToProto(d))
	}
	return &nokkuv1.ListWorkspaceDomainsResponse{
		Domains: domains,
	}, nil
}

func (s *WorkspaceDomainService) DeleteWorkspaceDomain(
	ctx context.Context,
	req *nokkuv1.DeleteWorkspaceDomainRequest,
) (*nokkuv1.DeleteWorkspaceDomainResponse, error) {
	if err := s.cfg.IAM.DeleteTenantDomain(ctx, req.GetWorkspaceId(), req.GetDomain()); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeleteWorkspaceDomainResponse{}, nil
}

func (s *WorkspaceDomainService) VerifyWorkspaceDomain(
	ctx context.Context,
	req *nokkuv1.VerifyWorkspaceDomainRequest,
) (*nokkuv1.VerifyWorkspaceDomainResponse, error) {
	// The iam manager resolves the TXT proof at _nokku-verify.<domain> itself.
	result, err := s.cfg.IAM.VerifyTenantDomain(ctx, req.GetWorkspaceId(), req.GetDomain())
	if err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.VerifyWorkspaceDomainResponse{
		Domain: domainToProto(result),
	}, nil
}

func (s *WorkspaceDomainService) RegenerateWorkspaceDomainToken(
	ctx context.Context,
	req *nokkuv1.RegenerateWorkspaceDomainTokenRequest,
) (*nokkuv1.RegenerateWorkspaceDomainTokenResponse, error) {
	// Regenerating is a rebind: a fresh token, verification reset.
	result, err := s.cfg.IAM.PutTenantDomain(ctx, req.GetWorkspaceId(), req.GetDomain())
	if err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.RegenerateWorkspaceDomainTokenResponse{
		Domain: domainToProto(result),
	}, nil
}

func domainToProto(d iam.TenantDomain) *nokkuv1.WorkspaceDomain {
	var verifiedAt *timestamppb.Timestamp
	if !d.VerifiedAt.IsZero() {
		verifiedAt = timestamppb.New(d.VerifiedAt)
	}
	return &nokkuv1.WorkspaceDomain{
		Domain:            &d.Domain,
		WorkspaceId:       &d.WorkspaceID,
		VerificationToken: &d.Token,
		VerifiedAt:        verifiedAt,
		CreatedAt:         domainTimestamp(d.CreatedAt),
		UpdatedAt:         domainTimestamp(d.UpdatedAt),
	}
}

// domainTimestamp leaves unset timestamps out of the proto instead of
// reporting the epoch.
func domainTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

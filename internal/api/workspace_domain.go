package api

import (
	"context"
	"fmt"
	"net"
	"slices"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/util"
)

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
	var result *db.WorkspaceDomain
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.GetWorkspaceDomain(ctx, req.GetDomain())
		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
		return err
	}); err != nil {
		return nil, ErrNotFound
	}

	return &nokkuv1.GetWorkspaceDomainResponse{
		Domain: result.ToProto(),
	}, nil
}

func (s *WorkspaceDomainService) CreateWorkspaceDomain(
	ctx context.Context,
	req *nokkuv1.CreateWorkspaceDomainRequest,
) (*nokkuv1.CreateWorkspaceDomainResponse, error) {
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

	var result *db.WorkspaceDomain
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.CreateWorkspaceDomain(ctx, &db.CreateWorkspaceDomainParams{
			WorkspaceID: req.GetWorkspaceId(),
			Domain:      req.GetDomain(),
		})
		return err
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.CreateWorkspaceDomainResponse{
		Domain: result.ToProto(),
	}, nil
}

func (s *WorkspaceDomainService) ListWorkspaceDomains(
	ctx context.Context,
	req *nokkuv1.ListWorkspaceDomainsRequest,
) (*nokkuv1.ListWorkspaceDomainsResponse, error) {
	var result []*db.WorkspaceDomain
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.ListWorkspaceDomains(ctx, req.GetWorkspaceId())
		return err
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.ListWorkspaceDomainsResponse{
		Domains: db.WorkspaceDomainsToProto(result),
	}, nil
}

func (s *WorkspaceDomainService) DeleteWorkspaceDomain(
	ctx context.Context,
	req *nokkuv1.DeleteWorkspaceDomainRequest,
) (*nokkuv1.DeleteWorkspaceDomainResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		result, err := q.DeleteWorkspaceDomain(ctx, req.GetDomain())
		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
		return err
	}); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.DeleteWorkspaceDomainResponse{}, nil
}

func (s *WorkspaceDomainService) VerifyWorkspaceDomain(
	ctx context.Context,
	req *nokkuv1.VerifyWorkspaceDomainRequest,
) (*nokkuv1.VerifyWorkspaceDomainResponse, error) {
	var domain *db.WorkspaceDomain
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		domain, err = q.GetWorkspaceDomain(ctx, req.GetDomain())
		meta.SetAuditWorkspaceID(ctx, domain.WorkspaceID)
		return err
	}); err != nil {
		return nil, ErrInternal
	}

	if domain.VerifiedAt != nil {
		return nil, NewError(connect.CodePermissionDenied, "workspace domain already verified")
	}

	dnsQuery := fmt.Sprintf("_nokku-verify.%s", domain.Domain)
	txtRecords, err := util.LookupTXTDOH(ctx, dnsQuery, "https://cloudflare-dns.com/dns-query")
	if err != nil {
		// Fall back to the OS resolver; DoH may be unreachable (offline, blocked).
		txtRecords, err = net.DefaultResolver.LookupTXT(ctx, dnsQuery)
	}
	if err != nil || len(txtRecords) == 0 {
		return nil, NewError(connect.CodeNotFound, "no TXT records found")
	}

	found := slices.Contains(txtRecords, domain.VerificationToken)
	if !found {
		return nil, NewError(
			connect.CodeNotFound,
			"token invalid, please wait for a few minutes if you just added it",
		)
	}

	result, err := s.cfg.Conn.Q.VerifyWorkspaceDomain(
		ctx,
		&db.VerifyWorkspaceDomainParams{
			Domain:      domain.Domain,
			Token:       domain.VerificationToken,
			WorkspaceID: domain.WorkspaceID,
		},
	)
	if err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.VerifyWorkspaceDomainResponse{
		Domain: result.ToProto(),
	}, nil
}

func (s *WorkspaceDomainService) RegenerateWorkspaceDomainToken(
	ctx context.Context,
	req *nokkuv1.RegenerateWorkspaceDomainTokenRequest,
) (*nokkuv1.RegenerateWorkspaceDomainTokenResponse, error) {
	var result *db.WorkspaceDomain
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.RegenerateVerificationToken(ctx, req.GetDomain())
		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
		return err
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.RegenerateWorkspaceDomainTokenResponse{
		Domain: result.ToProto(),
	}, nil
}

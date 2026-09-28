package iam

// A verified domain belongs to exactly one workspace and makes it the
// authority over every account under it.

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
)

// domainTXTPrefix must match the UI's instructions text.
const domainTXTPrefix = "_nokku-verify."

type TenantDomain struct {
	WorkspaceID string
	Domain      string
	Token       string
	VerifiedAt  time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Verified never expires, a proven claim is never re-proven.
func (d TenantDomain) Verified() bool {
	return !d.VerifiedAt.IsZero()
}

func (s *Service) ListTenantDomains(
	ctx context.Context,
	workspaceID string,
) ([]TenantDomain, error) {
	var out []TenantDomain
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		rows, err := q.ListWorkspaceDomains(ctx, workspaceID)
		if err != nil {
			return err
		}
		out = make([]TenantDomain, 0, len(rows))
		for _, r := range rows {
			out = append(out, domainFromRow(r))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) GetTenantDomain(
	ctx context.Context,
	workspaceID, domain string,
) (TenantDomain, error) {
	var out TenantDomain
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		r, err := q.GetWorkspaceDomain(ctx, &db.GetWorkspaceDomainParams{
			WorkspaceID: workspaceID,
			Domain:      domain,
		})
		if err != nil {
			return err
		}
		out = domainFromRow(r)
		return nil
	})
	if err != nil {
		return TenantDomain{}, mapNotFound(err)
	}
	return out, nil
}

// PutTenantDomain issues a fresh token and resets verification.
func (s *Service) PutTenantDomain(
	ctx context.Context,
	workspaceID, domain string,
) (TenantDomain, error) {
	var out TenantDomain
	if err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		r, err := q.UpsertWorkspaceDomain(ctx, &db.UpsertWorkspaceDomainParams{
			WorkspaceID: workspaceID,
			Domain:      domain,
		})
		if err != nil {
			return err
		}
		out = domainFromRow(r)
		return nil
	}); err != nil {
		return TenantDomain{}, err
	}
	return out, nil
}

func (s *Service) DeleteTenantDomain(ctx context.Context, workspaceID, domain string) error {
	return s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteWorkspaceDomain(ctx, &db.DeleteWorkspaceDomainParams{
			WorkspaceID: workspaceID,
			Domain:      domain,
		})
	})
}

func (s *Service) VerifyTenantDomain(
	ctx context.Context,
	workspaceID, domain string,
) (TenantDomain, error) {
	d, err := s.GetTenantDomain(ctx, workspaceID, domain)
	if err != nil {
		return TenantDomain{}, err
	}

	records, err := net.DefaultResolver.LookupTXT(ctx, domainTXTPrefix+d.Domain)
	if err != nil {
		return d, nil // unverifiable right now: report the unverified binding
	}
	for _, rec := range records {
		if rec != d.Token {
			continue
		}
		// The query re-checks the token and evicts other workspaces' claims.
		if err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
			_, err := q.VerifyWorkspaceDomain(ctx, &db.VerifyWorkspaceDomainParams{
				WorkspaceID: workspaceID,
				Domain:      domain,
				Token:       d.Token,
			})
			return err
		}); err != nil {
			return TenantDomain{}, err
		}
		return s.GetTenantDomain(ctx, workspaceID, domain)
	}
	return d, nil
}

// GetVerifiedTenantDomain reads globally since discovery runs pre-auth.
func (s *Service) GetVerifiedTenantDomain(ctx context.Context, domain string) (TenantDomain, error) {
	r, err := s.sys.GetVerifiedWorkspaceDomain(ctx, domain)
	if err != nil {
		return TenantDomain{}, mapNotFound(err)
	}
	return domainFromRow(r), nil
}

// managedBy gates every workspace write to a global account, or one tenant
// could reach another tenant's users.
func (s *Service) managedBy(ctx context.Context, workspaceID, email string) (bool, error) {
	d, err := s.GetVerifiedTenantDomain(ctx, emailDomain(email))
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return d.WorkspaceID == workspaceID, nil
}

func domainFromRow(r *db.WorkspaceDomain) TenantDomain {
	out := TenantDomain{
		WorkspaceID: r.WorkspaceID,
		Domain:      r.Domain,
		Token:       r.Token,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
	if r.VerifiedAt != nil {
		out.VerifiedAt = *r.VerifiedAt
	}
	return out
}

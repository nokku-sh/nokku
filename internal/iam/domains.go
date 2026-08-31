package iam

// Workspace domains: verified email-domain to workspace bindings that drive
// home-realm discovery, JIT checks, and SSO enforcement. Verification is a
// DNS TXT lookup at _nokku-verify.<domain> (the label the UI shows; kept
// stable across the merge-back).

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
)

// domainTXTPrefix is the DNS label the verification token lives under.
// Keep in sync with the UI's instructions text.
const domainTXTPrefix = "_nokku-verify."

// TenantDomain is one workspace domain binding.
type TenantDomain struct {
	WorkspaceID string
	ProviderID  string
	Domain      string
	Token       string
	VerifiedAt  time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Verified reports whether the domain is verified. Verification is
// permanent: a proven claim is never re-proven and never expires.
func (d TenantDomain) Verified() bool {
	return !d.VerifiedAt.IsZero()
}

// ListTenantDomains returns the workspace's domain bindings.
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

// GetTenantDomain returns one binding, or ErrNotFound.
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
		if errors.Is(err, pgx.ErrNoRows) {
			return TenantDomain{}, ErrNotFound
		}
		return TenantDomain{}, err
	}
	return out, nil
}

// PutTenantDomain creates or rebinds a domain: a fresh verification token,
// verification reset. Regenerating is the same operation.
func (s *Service) PutTenantDomain(
	ctx context.Context,
	workspaceID, domain string,
) (TenantDomain, error) {
	var out TenantDomain
	if err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		r, err := q.UpsertWorkspaceDomain(ctx, &db.UpsertWorkspaceDomainParams{
			WorkspaceID: workspaceID,
			ProviderID:  workspaceID,
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

// DeleteTenantDomain removes the binding.
func (s *Service) DeleteTenantDomain(ctx context.Context, workspaceID, domain string) error {
	return s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteWorkspaceDomain(ctx, &db.DeleteWorkspaceDomainParams{
			WorkspaceID: workspaceID,
			Domain:      domain,
		})
	})
}

// VerifyTenantDomain resolves the TXT proof at _nokku-verify.<domain> and, on
// a match, marks the binding verified for the verification window.
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
		// The SQL proof re-checks the token and evicts every other
		// workspace's claim on the domain; verification is permanent.
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

// GetVerifiedTenantDomain returns the verified binding for domain, or
// ErrNotFound. It backs home-realm discovery on the login page. Discovery
// runs pre-auth with no principal, so the read goes out as nokku_system:
// matching by domain is global by design.
func (s *Service) GetVerifiedTenantDomain(
	ctx context.Context,
	domain string,
) (TenantDomain, error) {
	var out TenantDomain
	err := s.conn.WithTx(ctx, func(q *db.Queries) error {
		r, err := q.GetVerifiedWorkspaceDomain(ctx, domain)
		if err != nil {
			return err
		}
		out = domainFromRow(r)
		return nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TenantDomain{}, ErrNotFound
		}
		return TenantDomain{}, err
	}
	if !out.Verified() {
		return TenantDomain{}, ErrNotFound
	}
	return out, nil
}

func domainFromRow(r *db.WorkspaceDomain) TenantDomain {
	out := TenantDomain{
		WorkspaceID: r.WorkspaceID,
		ProviderID:  r.ProviderID,
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

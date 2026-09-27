package iam

// Workspace domains: verified email-domain to workspace bindings. A verified
// domain belongs to exactly one workspace and makes that workspace the
// authority over every account under it: home-realm discovery, SSO
// enforcement, SSO email matching, JIT provisioning, and SCIM. Verification
// is a DNS TXT lookup at _nokku-verify.<domain>.

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
)

// domainTXTPrefix is the DNS label the verification token lives under.
// Keep in sync with the UI's instructions text.
const domainTXTPrefix = "_nokku-verify."

// TenantDomain is one workspace domain binding.
type TenantDomain struct {
	WorkspaceID string
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
		return TenantDomain{}, mapNotFound(err)
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
// a match, marks the binding verified.
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
// ErrNotFound. Discovery runs pre-auth, so the read is global by design.
func (s *Service) GetVerifiedTenantDomain(ctx context.Context, domain string) (TenantDomain, error) {
	r, err := s.sys.GetVerifiedWorkspaceDomain(ctx, domain)
	if err != nil {
		return TenantDomain{}, mapNotFound(err)
	}
	return domainFromRow(r), nil
}

// managedBy reports whether workspaceID has verified the domain of email.
// Only then may the workspace create, match, change, or delete the account
// behind it. Anything else would let one tenant reach another tenant's
// users, since accounts are global.
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

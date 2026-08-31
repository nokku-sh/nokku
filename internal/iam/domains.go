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

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// domainTXTPrefix is the DNS label the verification token lives under.
// Keep in sync with the UI's instructions text.
const domainTXTPrefix = "_nokku-verify."

// DomainVerificationWindow is how long a verification stays valid before
// the domain must be re-proven.
const DomainVerificationWindow = 180 * 24 * time.Hour

// TenantDomain is one workspace domain binding.
type TenantDomain struct {
	WorkspaceID   string
	ProviderID    string
	Domain        string
	Token         string
	VerifiedAt    time.Time
	VerifiedUntil time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Verified reports whether the domain is currently verified.
func (d TenantDomain) Verified() bool {
	return !d.VerifiedAt.IsZero() &&
		(d.VerifiedUntil.IsZero() || d.VerifiedUntil.After(time.Now()))
}

// ListTenantDomains returns the workspace's domain bindings.
func (s *Service) ListTenantDomains(
	ctx context.Context,
	workspaceID string,
) ([]TenantDomain, error) {
	rows, err := s.q.ListWorkspaceDomains(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	out := make([]TenantDomain, 0, len(rows))
	for _, r := range rows {
		out = append(out, domainFromRow(r))
	}
	return out, nil
}

// GetTenantDomain returns one binding, or ErrNotFound.
func (s *Service) GetTenantDomain(
	ctx context.Context,
	workspaceID, domain string,
) (TenantDomain, error) {
	r, err := s.q.GetWorkspaceDomain(ctx, &db.GetWorkspaceDomainParams{
		WorkspaceID: workspaceID,
		Domain:      domain,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TenantDomain{}, ErrNotFound
		}
		return TenantDomain{}, err
	}
	return domainFromRow(r), nil
}

// PutTenantDomain creates or rebinds a domain: a fresh verification token,
// verification reset. Regenerating is the same operation.
func (s *Service) PutTenantDomain(
	ctx context.Context,
	workspaceID, domain string,
) (TenantDomain, error) {
	token, err := crypto.RandomString(24)
	if err != nil {
		return TenantDomain{}, err
	}
	r, err := s.q.UpsertWorkspaceDomain(ctx, &db.UpsertWorkspaceDomainParams{
		WorkspaceID: workspaceID,
		Domain:      domain,
		Token:       token,
	})
	if err != nil {
		return TenantDomain{}, err
	}
	return domainFromRow(r), nil
}

// DeleteTenantDomain removes the binding.
func (s *Service) DeleteTenantDomain(ctx context.Context, workspaceID, domain string) error {
	return s.q.DeleteWorkspaceDomain(ctx, &db.DeleteWorkspaceDomainParams{
		WorkspaceID: workspaceID,
		Domain:      domain,
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
		now := time.Now()
		until := now.Add(DomainVerificationWindow)
		if err := s.q.VerifyWorkspaceDomain(ctx, &db.VerifyWorkspaceDomainParams{
			WorkspaceID:   workspaceID,
			Domain:        domain,
			VerifiedAt:    &now,
			VerifiedUntil: &until,
		}); err != nil {
			return TenantDomain{}, err
		}
		return s.GetTenantDomain(ctx, workspaceID, domain)
	}
	return d, nil
}

// GetVerifiedTenantDomain returns the verified binding for domain, or
// ErrNotFound. It backs home-realm discovery on the login page.
func (s *Service) GetVerifiedTenantDomain(
	ctx context.Context,
	domain string,
) (TenantDomain, error) {
	r, err := s.q.GetVerifiedWorkspaceDomain(ctx, domain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TenantDomain{}, ErrNotFound
		}
		return TenantDomain{}, err
	}
	d := domainFromRow(r)
	if !d.Verified() {
		return TenantDomain{}, ErrNotFound
	}
	return d, nil
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
	if r.VerifiedUntil != nil {
		out.VerifiedUntil = *r.VerifiedUntil
	}
	return out
}

package iam

// A provider's config, secret included, is one JSON blob sealed to its row.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type OIDCProvider struct {
	IssuerURL       string   `json:"issuer_url"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	JITProvisioning bool     `json:"jit_provisioning,omitempty"`
	// TrustUnverifiedEmail takes an address sent without email_verified, as
	// Entra does. A provider that says false is never trusted, and the owner is
	// never linked by email.
	TrustUnverifiedEmail bool `json:"trust_unverified_email,omitempty"`
}

type SSOProvider struct {
	ProviderID string
	Name       string
	Enabled    bool
	OIDC       OIDCProvider
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (s *Service) ListSSOProviders(ctx context.Context) ([]SSOProvider, error) {
	rows, err := s.conn.Tenant().ListSSOProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SSOProvider, 0, len(rows))
	for _, row := range rows {
		p, err := s.ssoProviderFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

func (s *Service) GetSSOProvider(ctx context.Context, providerID string) (*SSOProvider, error) {
	row, err := s.conn.Tenant().GetSSOProvider(ctx, providerID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return s.ssoProviderFromRow(row)
}

func (s *Service) loginProvider(ctx context.Context, providerID string) (*SSOProvider, error) {
	p, err := s.GetSSOProvider(ctx, providerID)
	if err != nil {
		return nil, err
	}
	if !p.Enabled {
		return nil, ErrNotFound
	}
	return p, nil
}

func (s *Service) PutSSOProvider(ctx context.Context, p SSOProvider) (*SSOProvider, error) {
	var out *SSOProvider
	err := s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		out, err = s.putSSOProvider(ctx, q, p)
		return err
	})
	return out, err
}

func (s *Service) putSSOProvider(ctx context.Context, q *db.Queries, p SSOProvider) (*SSOProvider, error) {
	var prev *SSOProvider
	row, err := q.GetSSOProvider(ctx, p.ProviderID)
	switch {
	case err == nil:
		prev, _ = s.ssoProviderFromRow(row)
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}
	if prev != nil && prev.Enabled && !p.Enabled {
		if err := keepSSOProvider(ctx, q, p.ProviderID); err != nil {
			return nil, err
		}
	}
	issuerChanged := prev != nil && prev.OIDC.IssuerURL != p.OIDC.IssuerURL
	if p.OIDC.ClientSecret == "" && prev != nil {
		// The secret goes to the issuer, so a new issuer must not inherit it.
		if issuerChanged {
			return nil, ErrSecretRequired
		}
		p.OIDC.ClientSecret = prev.OIDC.ClientSecret
	}
	if issuerChanged {
		// sub is only unique per issuer, so the old identities are stale.
		if _, err := q.DeleteCredentialsByProvider(ctx, &db.DeleteCredentialsByProviderParams{
			Type: string(MethodOIDC), Provider: p.ProviderID,
		}); err != nil {
			return nil, err
		}
	}
	cfg, err := json.Marshal(p.OIDC) //nolint:gosec // sealed before it is stored
	if err != nil {
		return nil, err
	}
	sealed, err := s.keys.Seal(SSOConfigAAD(actor.WorkspaceIDFromContext(ctx), p.ProviderID), cfg)
	if err != nil {
		return nil, err
	}
	row, err = q.UpsertSSOProvider(ctx, &db.UpsertSSOProviderParams{
		ProviderID: p.ProviderID,
		Name:       p.Name,
		Enabled:    p.Enabled,
		Config:     sealed,
	})
	if err != nil {
		return nil, err
	}
	return s.ssoProviderFromRow(row)
}

func (s *Service) DeleteSSOProvider(ctx context.Context, providerID string) error {
	return s.conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := keepSSOProvider(ctx, q, providerID); err != nil {
			return err
		}
		n, err := q.DeleteSSOProvider(ctx, providerID)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		_, err = q.DeleteCredentialsByProvider(ctx, &db.DeleteCredentialsByProviderParams{
			Type: string(MethodOIDC), Provider: providerID,
		})
		return err
	})
}

// HasSSOProvider guards enforced SSO, without one only the owner gets in.
func HasSSOProvider(ctx context.Context, q *db.Queries) (bool, error) {
	return hasSSOProviderBesides(ctx, q, "")
}

func hasSSOProviderBesides(ctx context.Context, q *db.Queries, providerID string) (bool, error) {
	rows, err := q.ListSSOProviders(ctx)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(rows, func(r *db.SsoProvider) bool {
		return r.Enabled && r.ProviderID != providerID
	}), nil
}

// keepSSOProvider refuses to drop the last provider of enforced SSO. The lock
// keeps a save that turns enforcement on from slipping past.
func keepSSOProvider(ctx context.Context, q *db.Queries, providerID string) error {
	ws, err := q.GetWorkspaceForUpdate(ctx)
	if err != nil || !ws.Settings.GetEnforceSso() {
		return err
	}
	has, err := hasSSOProviderBesides(ctx, q, providerID)
	if err == nil && !has {
		return ErrLastSSOProvider
	}
	return err
}

func (s *Service) ssoProviderFromRow(row *db.SsoProvider) (*SSOProvider, error) {
	cfg, err := s.keys.Open(SSOConfigAAD(row.WorkspaceID, row.ProviderID), row.Config)
	if err != nil {
		return nil, err
	}
	p := &SSOProvider{
		ProviderID: row.ProviderID,
		Name:       row.Name,
		Enabled:    row.Enabled,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}
	if err := json.Unmarshal(cfg, &p.OIDC); err != nil {
		return nil, err
	}
	return p, nil
}

// SSOConfigAAD is where the config of a provider is sealed.
func SSOConfigAAD(workspaceID, providerID string) crypto.AAD {
	return crypto.AAD{Table: "sso_providers", Column: "config", Workspace: workspaceID, Row: providerID}
}

// CheckIssuer skips the discovery cache, an unsaved issuer must not stay in it.
func (s *Service) CheckIssuer(ctx context.Context, issuer string) error {
	_, err := oidc.NewProvider(s.providerContext(ctx), issuer)
	return err
}

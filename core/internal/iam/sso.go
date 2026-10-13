package iam

// OIDC providers of a workspace. The config, secret included, is one JSON blob encrypted at rest.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type OIDCProvider struct {
	IssuerURL       string   `json:"issuer_url"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	JITProvisioning bool     `json:"jit_provisioning,omitempty"`
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
		p, err := ssoProviderFromRow(row)
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
	return ssoProviderFromRow(row)
}

// loginProvider is a provider that may sign people in right now.
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

// PutSSOProvider keeps the stored client secret when the new one is empty, unless the issuer changed.
func (s *Service) PutSSOProvider(ctx context.Context, p SSOProvider) (*SSOProvider, error) {
	var out *SSOProvider
	err := s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		out, err = putSSOProvider(ctx, q, p)
		return err
	})
	return out, err
}

func putSSOProvider(ctx context.Context, q *db.Queries, p SSOProvider) (*SSOProvider, error) {
	var prev *SSOProvider
	row, err := q.GetSSOProvider(ctx, p.ProviderID)
	switch {
	case err == nil:
		prev, _ = ssoProviderFromRow(row)
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}
	issuerChanged := prev != nil && prev.OIDC.IssuerURL != p.OIDC.IssuerURL
	if p.OIDC.ClientSecret == "" && prev != nil {
		// The secret goes to the issuer's token endpoint, so a new issuer must not inherit it.
		if issuerChanged {
			return nil, ErrSecretRequired
		}
		p.OIDC.ClientSecret = prev.OIDC.ClientSecret
	}
	if issuerChanged {
		// sub is only unique per issuer, so the identities the old one vouched for are stale.
		if _, err := q.DeleteCredentialsByProvider(ctx, &db.DeleteCredentialsByProviderParams{
			Type: string(MethodOIDC), Provider: p.ProviderID,
		}); err != nil {
			return nil, err
		}
	}
	cfg, err := json.Marshal(p.OIDC) //nolint:gosec // encrypted before it is stored
	if err != nil {
		return nil, err
	}
	row, err = q.UpsertSSOProvider(ctx, &db.UpsertSSOProviderParams{
		ProviderID: p.ProviderID,
		Name:       p.Name,
		Enabled:    p.Enabled,
		Config:     crypto.EncryptedBytes(cfg),
	})
	if err != nil {
		return nil, err
	}
	return ssoProviderFromRow(row)
}

// DeleteSSOProvider also unlinks every identity the provider vouched for.
func (s *Service) DeleteSSOProvider(ctx context.Context, providerID string) error {
	return s.conn.TenantTx(ctx, func(q *db.Queries) error {
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

func ssoProviderFromRow(row *db.SsoProvider) (*SSOProvider, error) {
	p := &SSOProvider{
		ProviderID: row.ProviderID,
		Name:       row.Name,
		Enabled:    row.Enabled,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &p.OIDC); err != nil {
			return nil, err
		}
	}
	return p, nil
}

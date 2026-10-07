package iam

// OIDC providers of a workspace. The config, secret included, is one JSON
// blob encrypted at rest.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
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
	var out []SSOProvider
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		rows, err := q.ListSSOProviders(ctx, ws)
		if err != nil {
			return err
		}
		out = make([]SSOProvider, 0, len(rows))
		for _, row := range rows {
			p, err := ssoProviderFromRow(row)
			if err != nil {
				return err
			}
			out = append(out, *p)
		}
		return nil
	})
	return out, err
}

func (s *Service) GetSSOProvider(ctx context.Context, providerID string) (*SSOProvider, error) {
	var out *SSOProvider
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		row, err := q.GetSSOProvider(ctx, &db.GetSSOProviderParams{WorkspaceID: ws, ProviderID: providerID})
		if err != nil {
			return err
		}
		out, err = ssoProviderFromRow(row)
		return err
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return out, nil
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

// PutSSOProvider keeps the stored client secret when the new one is empty.
func (s *Service) PutSSOProvider(ctx context.Context, p SSOProvider) (*SSOProvider, error) {
	var out *SSOProvider
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		out, err = putSSOProvider(ctx, q, ws, p)
		return err
	})
	return out, err
}

func putSSOProvider(ctx context.Context, q db.Querier, ws string, p SSOProvider) (*SSOProvider, error) {
	if p.OIDC.ClientSecret == "" {
		row, err := q.GetSSOProvider(ctx, &db.GetSSOProviderParams{WorkspaceID: ws, ProviderID: p.ProviderID})
		if err == nil {
			if prev, err := ssoProviderFromRow(row); err == nil {
				p.OIDC.ClientSecret = prev.OIDC.ClientSecret
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	cfg, err := json.Marshal(p.OIDC) //nolint:gosec // encrypted before it is stored
	if err != nil {
		return nil, err
	}
	row, err := q.UpsertSSOProvider(ctx, &db.UpsertSSOProviderParams{
		WorkspaceID: ws,
		ProviderID:  p.ProviderID,
		Name:        p.Name,
		Enabled:     p.Enabled,
		Config:      crypto.EncryptedBytes(cfg),
	})
	if err != nil {
		return nil, err
	}
	return ssoProviderFromRow(row)
}

// DeleteSSOProvider also unlinks every identity the provider vouched for.
func (s *Service) DeleteSSOProvider(ctx context.Context, providerID string) error {
	return s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		n, err := q.DeleteSSOProvider(ctx, &db.DeleteSSOProviderParams{WorkspaceID: ws, ProviderID: providerID})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		_, err = q.DeleteCredentialsByProvider(ctx, &db.DeleteCredentialsByProviderParams{
			WorkspaceID: ws, Type: string(MethodOIDC), Provider: providerID,
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

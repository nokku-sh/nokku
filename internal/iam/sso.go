package iam

// Enterprise providers use their workspace id as provider id, social ones are
// global rows. The config, secret included, is one JSON blob encrypted at rest.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

type OIDCProvider struct {
	IssuerURL       string   `json:"issuer_url"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	JITProvisioning bool     `json:"jit_provisioning,omitempty"`
	EnforceSSO      bool     `json:"enforce_sso,omitempty"`
}

type OAuth2Provider struct {
	AuthURL     string `json:"auth_url"`
	TokenURL    string `json:"token_url"`
	UserInfoURL string `json:"user_info_url"`
	// EmailURL lists addresses with their verified flag.
	EmailURL        string   `json:"email_url,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret,omitempty"`
	JITProvisioning bool     `json:"jit_provisioning,omitempty"`
	EnforceSSO      bool     `json:"enforce_sso,omitempty"`
}

type SAMLIDP struct {
	MetadataURL     string `json:"metadata_url,omitempty"`
	MetadataXML     []byte `json:"metadata_xml,omitempty"`
	JITProvisioning bool   `json:"jit_provisioning,omitempty"`
	EnforceSSO      bool   `json:"enforce_sso,omitempty"`
}

type SSOProvider struct {
	WorkspaceID string
	ProviderID  string
	Method      Method
	Name        string
	Enabled     bool
	OIDC        *OIDCProvider
	OAuth2      *OAuth2Provider
	SAML        *SAMLIDP
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (p *SSOProvider) Enforced() bool {
	if !p.Enabled {
		return false
	}
	switch {
	case p.OIDC != nil:
		return p.OIDC.EnforceSSO
	case p.OAuth2 != nil:
		return p.OAuth2.EnforceSSO
	case p.SAML != nil:
		return p.SAML.EnforceSSO
	}
	return false
}

type providerConfig struct {
	OIDC   *OIDCProvider   `json:"oidc,omitempty"`
	OAuth2 *OAuth2Provider `json:"oauth2,omitempty"`
	SAML   *SAMLIDP        `json:"saml,omitempty"`
}

// GetSSOProvider reads globally since login flows run before any principal
// exists. Admin reads go through GetWorkspaceSSOProvider.
func (s *Service) GetSSOProvider(ctx context.Context, providerID string) (*SSOProvider, error) {
	row, err := s.sys.GetSSOProvider(ctx, providerID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return ssoProviderFromRow(row)
}

func (s *Service) GetWorkspaceSSOProvider(ctx context.Context, workspaceID string) (*SSOProvider, error) {
	var out *SSOProvider
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		row, err := q.GetSSOProvider(ctx, workspaceID)
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

// PutSSOProvider keeps the stored client secret when the new one is empty.
func (s *Service) PutSSOProvider(ctx context.Context, p SSOProvider) error {
	if p.WorkspaceID == "" {
		return putSSOProvider(ctx, s.sys, p)
	}
	return s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return putSSOProvider(ctx, q, p)
	})
}

func putSSOProvider(ctx context.Context, q db.Querier, p SSOProvider) error {
	if (p.OIDC != nil && p.OIDC.ClientSecret == "") || (p.OAuth2 != nil && p.OAuth2.ClientSecret == "") {
		if row, err := q.GetSSOProvider(ctx, p.ProviderID); err == nil {
			var prev providerConfig
			if json.Unmarshal(row.Config, &prev) == nil {
				if p.OIDC != nil && prev.OIDC != nil && p.OIDC.ClientSecret == "" {
					p.OIDC.ClientSecret = prev.OIDC.ClientSecret
				}
				if p.OAuth2 != nil && prev.OAuth2 != nil && p.OAuth2.ClientSecret == "" {
					p.OAuth2.ClientSecret = prev.OAuth2.ClientSecret
				}
			}
		}
	}
	cfg, err := json.Marshal(providerConfig{OIDC: p.OIDC, OAuth2: p.OAuth2, SAML: p.SAML})
	if err != nil {
		return err
	}
	_, err = q.UpsertSSOProvider(ctx, &db.UpsertSSOProviderParams{
		WorkspaceID: nonEmpty(p.WorkspaceID),
		ProviderID:  p.ProviderID,
		Method:      string(p.Method),
		Name:        p.Name,
		Enabled:     p.Enabled,
		Config:      crypto.EncryptedBytes(cfg),
	})
	return err
}

func ssoProviderFromRow(row *db.SsoProvider) (*SSOProvider, error) {
	var cfg providerConfig
	if err := json.Unmarshal(row.Config, &cfg); err != nil {
		return nil, err
	}
	return &SSOProvider{
		WorkspaceID: deref(row.WorkspaceID),
		ProviderID:  row.ProviderID,
		Method:      Method(row.Method),
		Name:        row.Name,
		Enabled:     row.Enabled,
		OIDC:        cfg.OIDC,
		OAuth2:      cfg.OAuth2,
		SAML:        cfg.SAML,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

func (s *Service) enforceSSO(ctx context.Context, email string) error {
	d, err := s.GetVerifiedTenantDomain(ctx, emailDomain(email))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	p, err := s.GetSSOProvider(ctx, d.WorkspaceID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.Enforced() {
		return ErrSSORequired
	}
	return nil
}

func isSSOMethod(m Method) bool {
	return m == MethodOIDC || m == MethodOAuth2 || m == MethodSAML
}

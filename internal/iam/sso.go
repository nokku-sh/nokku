package iam

// SSO provider storage: one unified table, oidc/oauth2/saml discriminated by
// method. provider_id is globally unique (enterprise providers use the
// workspace id; social providers are global rows with NULL workspace). The
// manager owns persistence, the at-rest secret split (client secret encrypted
// into secret_enc), and the SAML SP keypair. Login flows live in the flow
// files.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// OIDCProvider is the stored OIDC configuration.
type OIDCProvider struct {
	IssuerURL       string   `json:"issuer_url"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"-"` // in-memory only; encrypted into secret_enc
	RedirectURL     string   `json:"redirect_url,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	JITProvisioning bool     `json:"jit_provisioning,omitempty"`
	EnforceSSO      bool     `json:"enforce_sso,omitempty"`
}

// SAMLIDP is the stored SAML configuration.
type SAMLIDP struct {
	MetadataURL     string `json:"metadata_url,omitempty"`
	MetadataXML     []byte `json:"metadata_xml,omitempty"` // inline IdP metadata, base64 in JSON
	SPEntityID      string `json:"sp_entity_id,omitempty"`
	AcsURL          string `json:"acs_url,omitempty"`
	JITProvisioning bool   `json:"jit_provisioning,omitempty"`
	EnforceSSO      bool   `json:"enforce_sso,omitempty"`
}

// SAMLConfig mirrors kagi's static SP settings.
type SAMLConfig struct {
	ErrorRedirect string
	AcsURL        string
	SPEntityID    string
}

// SSOProvider is one stored SSO provider. Enterprise providers carry the
// workspace id as their provider id; social providers are global rows.
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

type providerConfig struct {
	OIDC   *OIDCProvider   `json:"oidc,omitempty"`
	OAuth2 *OAuth2Provider `json:"oauth2,omitempty"`
	SAML   *SAMLIDP        `json:"saml,omitempty"`
}

// GetSSOProvider returns the provider stored under id, or ErrNotFound. The
// client secret is decrypted into the payload for in-memory use.
func (s *Service) GetSSOProvider(ctx context.Context, providerID string) (*SSOProvider, error) {
	row, err := s.q.GetSSOProvider(ctx, providerID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return s.ssoProviderFromRow(row)
}

// PutSSOProvider stores the provider. A non-empty client secret replaces the
// stored one; an empty secret keeps the previous value, so callers can
// update configuration without resubmitting the secret.
func (s *Service) PutSSOProvider(ctx context.Context, p SSOProvider) error {
	cfg := providerConfig{OIDC: p.OIDC, OAuth2: p.OAuth2, SAML: p.SAML}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	secret := crypto.EncryptedBytes(nil)
	if p.OIDC != nil && p.OIDC.ClientSecret != "" {
		enc, err := crypto.Encryptor()
		if err != nil {
			return err
		}
		secret, err = enc.Encrypt([]byte(p.OIDC.ClientSecret))
		if err != nil {
			return err
		}
	} else if p.OAuth2 != nil && p.OAuth2.ClientSecret != "" {
		enc, err := crypto.Encryptor()
		if err != nil {
			return err
		}
		secret, err = enc.Encrypt([]byte(p.OAuth2.ClientSecret))
		if err != nil {
			return err
		}
	} else if row, err := s.q.GetSSOProvider(ctx, p.ProviderID); err == nil {
		secret = row.SecretEnc
	}

	var workspaceID *string
	if p.WorkspaceID != "" {
		workspaceID = &p.WorkspaceID
	}
	_, err = s.q.UpsertSSOProvider(ctx, &db.UpsertSSOProviderParams{
		WorkspaceID: workspaceID,
		ProviderID:  p.ProviderID,
		Method:      string(p.Method),
		Name:        p.Name,
		Enabled:     p.Enabled,
		Config:      cfgJSON,
		SecretEnc:   secret,
	})
	return err
}

// DeleteSSOProvider removes the provider row.
func (s *Service) DeleteSSOProvider(ctx context.Context, providerID string) error {
	return s.q.DeleteSSOProvider(ctx, providerID)
}

// DeleteTenantSSOProviders removes every provider of a workspace; used when
// a workspace is torn down. Domain rows cascade through the schema.
func (s *Service) DeleteTenantSSOProviders(ctx context.Context, workspaceID string) (int64, error) {
	return s.q.DeleteTenantSSOProviders(ctx, &workspaceID)
}

func (s *Service) ssoProviderFromRow(
	row *db.SsoProvider,
) (*SSOProvider, error) {
	var cfg providerConfig
	if err := json.Unmarshal(row.Config, &cfg); err != nil {
		return nil, err
	}
	// Decrypt the stored secret into the in-memory payload.
	if len(row.SecretEnc) > 0 {
		enc, err := crypto.Encryptor()
		if err == nil {
			if plain, err := enc.Decrypt(row.SecretEnc); err == nil {
				switch {
				case cfg.OIDC != nil:
					cfg.OIDC.ClientSecret = string(plain)
				case cfg.OAuth2 != nil:
					cfg.OAuth2.ClientSecret = string(plain)
				}
			}
		}
	}
	out := &SSOProvider{
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
	}
	return out, nil
}

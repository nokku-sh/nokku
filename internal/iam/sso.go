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
	Scopes          []string `json:"scopes,omitempty"`
	ClientSecret    string   `json:"client_secret,omitempty"` // only ever at rest inside the encrypted config blob
	RedirectURL     string   `json:"redirect_url,omitempty"`
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
// client secret is decrypted into the payload for in-memory use. The read is
// global (nokku_system): login flows resolve providers by their globally
// unique id before any principal exists. Workspace admin reads go through
// GetWorkspaceSSOProvider, which enforces tenant isolation.
func (s *Service) GetSSOProvider(ctx context.Context, providerID string) (*SSOProvider, error) {
	var out *SSOProvider
	err := s.conn.WithTx(ctx, func(q *db.Queries) error {
		row, err := q.GetSSOProvider(ctx, providerID)
		if err != nil {
			return err
		}
		out, err = s.ssoProviderFromRow(row)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return out, nil
}

// GetWorkspaceSSOProvider returns the workspace's enterprise provider, or
// ErrNotFound. Tenant-isolated: the read runs pinned to the caller's
// workspace, so one workspace can never read another's configuration.
func (s *Service) GetWorkspaceSSOProvider(
	ctx context.Context,
	workspaceID string,
) (*SSOProvider, error) {
	var out *SSOProvider
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		row, err := q.GetSSOProvider(ctx, workspaceID)
		if err != nil {
			return err
		}
		out, err = s.ssoProviderFromRow(row)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return out, nil
}

// PutSSOProvider stores the provider. A non-empty client secret replaces the
// stored one; an empty secret keeps the previous value, so callers can
// update configuration without resubmitting the secret.
func (s *Service) PutSSOProvider(ctx context.Context, p SSOProvider) error {
	// Social rows (NULL workspace) are global: RLS admits them unpinned, and
	// the boot seeder has no principal to pin with. Enterprise rows carry the
	// workspace id and must run pinned to pass tenant isolation.
	if p.WorkspaceID == "" {
		return s.putSSOProvider(ctx, s.q, p)
	}
	return s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return s.putSSOProvider(ctx, q, p)
	})
}

// putSSOProvider stores the provider. The whole configuration, client
// secret included, is marshaled into one JSON blob that the sqlc type
// override (crypto.EncryptedBytes) encrypts on the way in and decrypts on
// the way out; the database never holds it in plaintext.
func (s *Service) putSSOProvider(
	ctx context.Context,
	q db.Querier,
	p SSOProvider,
) error {
	cfg := providerConfig{OIDC: p.OIDC, OAuth2: p.OAuth2, SAML: p.SAML}

	// An empty incoming secret keeps the stored one: decrypt the previous
	// config through the same querier (so tenant isolation holds) and carry
	// the secret over before encrypting.
	if (p.OIDC != nil && p.OIDC.ClientSecret == "") ||
		(p.OAuth2 != nil && p.OAuth2.ClientSecret == "") {
		if row, err := q.GetSSOProvider(ctx, p.ProviderID); err == nil {
			var prev providerConfig
			if json.Unmarshal(row.Config, &prev) == nil {
				if p.OIDC != nil && prev.OIDC != nil {
					p.OIDC.ClientSecret = prev.OIDC.ClientSecret
				}
				if p.OAuth2 != nil && prev.OAuth2 != nil {
					p.OAuth2.ClientSecret = prev.OAuth2.ClientSecret
				}
			}
		}
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	var workspaceID *string
	if p.WorkspaceID != "" {
		workspaceID = &p.WorkspaceID
	}
	_, err = q.UpsertSSOProvider(ctx, &db.UpsertSSOProviderParams{
		WorkspaceID: workspaceID,
		ProviderID:  p.ProviderID,
		Method:      string(p.Method),
		Name:        p.Name,
		Enabled:     p.Enabled,
		Config:      crypto.EncryptedBytes(cfgJSON),
	})
	return err
}

// DeleteSSOProvider removes the provider row. Deletion is by globally unique
// provider id, so it runs as nokku_system; no current caller needs the
// tenant-pinned variant.
func (s *Service) DeleteSSOProvider(ctx context.Context, providerID string) error {
	return s.conn.WithTx(ctx, func(q *db.Queries) error {
		return q.DeleteSSOProvider(ctx, providerID)
	})
}

// DeleteTenantSSOProviders removes every provider of a workspace; used when
// a workspace is torn down. Domain rows cascade through the schema.
func (s *Service) DeleteTenantSSOProviders(ctx context.Context, workspaceID string) (int64, error) {
	return s.q.DeleteTenantSSOProviders(ctx, &workspaceID)
}

func (s *Service) ssoProviderFromRow(
	row *db.SsoProvider,
) (*SSOProvider, error) {
	// row.Config arrives decrypted (EncryptedBytes scan); it is empty only
	// for rows written before the unified config column.
	var cfg providerConfig
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &cfg); err != nil {
			return nil, err
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

package api

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/util"
)

type SAMLHandler struct {
	cfg           *config.Config
	metadataCache sync.Map
}

type SAMLState struct {
	ProviderID string `json:"provider_id"`
}

func NewSAMLHandler(cfg *config.Config) *SAMLHandler {
	return &SAMLHandler{cfg: cfg}
}

func (s *SAMLHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	providerID := r.URL.Query().Get("provider")
	if providerID == "" {
		writeJSONError(w, http.StatusBadRequest, "Invalid provider ID")
		return
	}

	// Get SAML middleware
	middleware, err := s.getSAMLMiddleware(r.Context(), providerID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Provider configuration failed")
		return
	}

	// Create state with provider ID
	state := SAMLState{ProviderID: providerID}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	relayState := base64.StdEncoding.EncodeToString(stateJSON)

	// Build authentication request
	authReq, err := middleware.ServiceProvider.MakeAuthenticationRequest(
		middleware.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to build auth request")
		return
	}

	// Store the request in the tracker (required for validation)
	if _, err := middleware.RequestTracker.TrackRequest(w, r, authReq.ID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to track request")
		return
	}

	// Redirect to IdP with RelayState
	redirectURL, err := authReq.Redirect(relayState, &middleware.ServiceProvider)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to build redirect URL")
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

// CallbackHandler processes SAML assertions.
func (s *SAMLHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	redirect := s.cfg.FullURL()

	// Parse form to get RelayState
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, redirect+"?error=invalid_request", http.StatusTemporaryRedirect)
		return
	}

	// Decode state from RelayState
	var state SAMLState
	if relayState := r.FormValue("RelayState"); relayState != "" {
		stateJSON, err := base64.StdEncoding.DecodeString(relayState)
		if err != nil {
			http.Redirect(w, r, redirect+"?error=invalid_state", http.StatusTemporaryRedirect)
			return
		}
		if err := json.Unmarshal(stateJSON, &state); err != nil {
			http.Redirect(w, r, redirect+"?error=invalid_state", http.StatusTemporaryRedirect)
			return
		}
	}

	// Get SAML middleware
	middleware, err := s.getSAMLMiddleware(ctx, state.ProviderID)
	if err != nil {
		http.Redirect(w, r, redirect+"?error=provider_config_failed", http.StatusTemporaryRedirect)
		return
	}

	// Get possible request IDs from tracker
	var possibleRequestIDs []string
	trackedRequests := middleware.RequestTracker.GetTrackedRequests(r)
	for _, req := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, req.SAMLRequestID)
	}

	// Parse and validate SAML response
	assertion, err := middleware.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		http.Redirect(w, r, redirect+"?error=invalid_assertion", http.StatusTemporaryRedirect)
		return
	}

	// Stop tracking the request
	if err := middleware.RequestTracker.StopTrackingRequest(w, r, assertion.ID); err != nil {
		slog.Warn("Failed to stop tracking request", "error", err)
	}
	for _, req := range trackedRequests {
		if err := middleware.RequestTracker.StopTrackingRequest(
			w,
			r,
			req.SAMLRequestID,
		); err != nil {
			slog.Debug("Failed to stop tracking request", "error", err)
		}
	}

	// Get provider config for attribute mappings
	dbConfig, err := s.cfg.Conn.Q.GetSAMLProviderByID(ctx, state.ProviderID)
	if err != nil {
		http.Redirect(w, r, redirect+"?error=provider_config_failed", http.StatusTemporaryRedirect)
		return
	}

	// Extract user attributes
	userAttr, err := s.extractAttributes(ctx, assertion, dbConfig)
	if err != nil {
		http.Redirect(w, r, redirect+"?error=invalid_attributes", http.StatusTemporaryRedirect)
		return
	}

	// Get NameID
	if assertion.Subject == nil || assertion.Subject.NameID == nil ||
		assertion.Subject.NameID.Value == "" {
		http.Redirect(w, r, redirect+"?error=missing_name_id", http.StatusTemporaryRedirect)
		return
	}
	nameID := assertion.Subject.NameID.Value

	// Handle user (create or update)
	user, err := s.handleSAMLUser(ctx, userAttr, dbConfig, nameID)
	if err != nil {
		http.Redirect(w, r, redirect+"?error=user_failed", http.StatusTemporaryRedirect)
		return
	}

	if a := meta.AuditStateFromContext(r.Context()); a != nil {
		a.UserID = user.ID
	}

	// Create tokens and set cookies
	s.cfg.Authn.AccessCookie(ctx, w.Header(), user)
	s.cfg.Authn.RefreshCookie(ctx, w.Header(), user)
	syncWebDevice(ctx, s.cfg, r.Header, w.Header(), user)

	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

// MetadataHandler returns SP metadata.
func (s *SAMLHandler) MetadataHandler(w http.ResponseWriter, r *http.Request) {
	middleware, err := s.getSAMLMiddleware(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "Provider not found")
		return
	}

	buf, err := xml.MarshalIndent(middleware.ServiceProvider.Metadata(), "", "  ")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to generate metadata")
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if _, err := w.Write(buf); err != nil { // #nosec G705
		slog.Error("Failed to write metadata", "error", err)
	}
}

// handleSAMLUser creates or updates user from SAML assertion.
func (s *SAMLHandler) handleSAMLUser(
	ctx context.Context,
	user *db.User,
	saml *db.SamlProvider,
	nameID string,
) (*db.User, error) {
	// Check if user exists by email
	existingUser, err := s.cfg.Conn.Q.GetUserByEmail(ctx, user.Email)

	// User exists, update and return
	if err == nil {
		var updatedUser *db.User
		err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
			// If enforce_sso is enabled, verify user came from SAML
			if saml.EnforceSso {
				// Check if user has SAML identity linked
				identity, err := q.GetOAuthIdentity(
					ctx,
					&db.GetOAuthIdentityParams{
						ProviderID: nameID,
						Provider:   saml.WorkspaceID,
					},
				)
				// If identity doesn't exist, this is first SAML login - allow it
				if err == nil && identity.UserID != existingUser.ID {
					return fmt.Errorf("enforce_sso: user must login via SAML")
				}
			}

			// Update user info
			updatedUser, err = q.UpdateUser(ctx, &db.UpdateUserParams{
				UserID:   existingUser.ID,
				Username: &user.Username,
				Name:     &user.Name,
				Picture:  user.Picture,
			})
			if err != nil {
				return fmt.Errorf("failed to update user: %w", err)
			}

			// Verify user email
			if err := q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
				UserID: existingUser.ID,
				Email:  user.Email,
			}); err != nil {
				return fmt.Errorf("failed to verify user email: %w", err)
			}

			// Upsert identity to link SAML to existing user
			_, err = q.UpsertOAuthIdentity(ctx, &db.UpsertOAuthIdentityParams{
				ProviderID:       nameID,
				Provider:         saml.WorkspaceID,
				UserID:           existingUser.ID,
				ProviderEmail:    &user.Email,
				ProviderUsername: &user.Username,
			})
			if err != nil {
				return fmt.Errorf("failed to link SAML identity: %w", err)
			}

			if err = q.AddWorkspaceMember(ctx, &db.AddWorkspaceMemberParams{
				UserID:      existingUser.ID,
				WorkspaceID: saml.WorkspaceID,
			}); err != nil {
				return fmt.Errorf("failed to add workspace member: %w", err)
			}

			return nil
		})

		return updatedUser, err
	}

	// JIT provisioning check
	if !saml.AllowJitProvisioning {
		return nil, fmt.Errorf("user not found and JIT provisioning is disabled")
	}

	var newUser *db.User
	err = s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		// Create new user
		newUser, err = q.CreateUser(ctx, &db.CreateUserParams{
			Name:     user.Name,
			Username: user.Username,
			Picture:  user.Picture,
			Email:    user.Email,
		})
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// Verify email immediately
		if err := q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
			UserID: newUser.ID,
			Email:  newUser.Email,
		}); err != nil {
			return fmt.Errorf("failed to verify user email: %w", err)
		}

		// Link OAuth identity (using SAML provider ID as the provider identifier)
		_, err = q.UpsertOAuthIdentity(ctx, &db.UpsertOAuthIdentityParams{
			ProviderID:       nameID,
			Provider:         saml.WorkspaceID,
			UserID:           newUser.ID,
			ProviderEmail:    &newUser.Email,
			ProviderUsername: &newUser.Username,
		})
		if err != nil {
			return fmt.Errorf("failed to create OAuth identity: %w", err)
		}

		if err = q.AddWorkspaceMember(ctx, &db.AddWorkspaceMemberParams{
			UserID:      newUser.ID,
			WorkspaceID: saml.WorkspaceID,
		}); err != nil {
			return fmt.Errorf("failed to add workspace member: %w", err)
		}
		return nil
	})

	return newUser, err
}

// extractAttributes converts SAML attributes to db.User using custom mappings.
func (s *SAMLHandler) extractAttributes(
	ctx context.Context,
	assertion *saml.Assertion,
	saml *db.SamlProvider,
) (*db.User, error) {
	// Helper to get attribute value
	getAttr := func(name string) string {
		for _, stmt := range assertion.AttributeStatements {
			for _, attr := range stmt.Attributes {
				if attr.Name == name && len(attr.Values) > 0 {
					return attr.Values[0].Value
				}
			}
		}
		return ""
	}

	email := getAttr(saml.EmailAttribute)
	if email == "" {
		return nil, fmt.Errorf("email attribute '%s' not found", saml.EmailAttribute)
	}

	name := getAttr(saml.NameAttribute)

	var picture string
	if saml.PictureAttribute != nil {
		picture = getAttr(*saml.PictureAttribute)
	}

	// Generate username
	username, err := util.GenerateUsername(
		email,
		getAttr(saml.UsernameAttribute),
		[]string{name},
	)
	if err != nil || username == "" {
		return nil, fmt.Errorf("failed to generate username: %w", err)
	}

	// Verify domain
	domain := strings.Split(email, "@")
	if len(domain) != 2 {
		return nil, fmt.Errorf("invalid email format")
	}

	ok, err := s.cfg.Conn.Q.VerifiedDomainExists(ctx, domain[1])
	if err != nil || !ok {
		return nil, fmt.Errorf("domain not verified for SSO: %w", err)
	}

	return &db.User{
		Email:    email,
		Name:     name,
		Username: username,
		Picture:  &picture,
	}, nil
}

// getSAMLMiddleware retrieves or creates SAML middleware for a provider.
func (s *SAMLHandler) getSAMLMiddleware(
	ctx context.Context,
	id string,
) (*samlsp.Middleware, error) {
	// Get provider config (always needed for SP cert/key)
	provider, err := s.cfg.Conn.Q.GetSAMLProviderByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get SAML provider: %w", err)
	}

	if provider.MetadataURL == nil {
		return nil, fmt.Errorf("missing metadata URL")
	}
	if provider.SpCertificate == nil {
		return nil, fmt.Errorf("missing SP certificate")
	}
	if provider.SpPrivateKey.Bytes() == nil {
		return nil, fmt.Errorf("missing SP private key")
	}

	cacheKey := fmt.Sprintf("saml.idp_metadata.%s.%d", id, provider.UpdatedAt.Unix())
	// Try to get IdP metadata from cache
	var idpMetadata *saml.EntityDescriptor
	if cached, ok := s.metadataCache.Load(cacheKey); ok {
		idpMetadata, ok = cached.(*saml.EntityDescriptor)
		if !ok {
			s.metadataCache.Delete(cacheKey)
		}
	}

	// Cache miss - fetch metadata
	if idpMetadata == nil {
		metadataURL, err := url.Parse(*provider.MetadataURL)
		if err != nil {
			return nil, fmt.Errorf("invalid metadata URL: %w", err)
		}

		idpMetadata, err = samlsp.FetchMetadata(ctx, http.DefaultClient, *metadataURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch IdP metadata: %w", err)
		}

		// Cache the metadata as XML
		if metadataXML, err := xml.Marshal(idpMetadata); err == nil {
			_ = s.cfg.Cache.Set(ctx, cacheKey, metadataXML, 1*time.Hour)
		}
		s.metadataCache.Store(cacheKey, idpMetadata)
	}

	// Parse SP certificate
	certBlock, _ := pem.Decode([]byte(*provider.SpCertificate))
	if certBlock == nil {
		return nil, fmt.Errorf("failed to parse sp certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SP certificate: %w", err)
	}

	// Parse SP private key
	keyBlock, _ := pem.Decode(provider.SpPrivateKey.Bytes())
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to parse sp private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SP private key: %w", err)
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key must be RSA")
	}

	// Build root URL
	rootURL, err := url.Parse(s.cfg.FullURL())
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Create middleware with all options
	middleware, err := samlsp.New(samlsp.Options{
		EntityID:          s.cfg.FullURL() + "/saml/metadata/" + id,
		URL:               *rootURL,
		Key:               rsaKey,
		Certificate:       cert,
		IDPMetadata:       idpMetadata,
		SignRequest:       true,
		AllowIDPInitiated: false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML middleware: %w", err)
	}

	// Set signature method
	middleware.ServiceProvider.SignatureMethod = dsig.RSASHA256SignatureMethod

	// Override ACS URL to match our routing
	middleware.ServiceProvider.AcsURL = *rootURL.ResolveReference(&url.URL{Path: "/saml/acs"})

	return middleware, nil
}

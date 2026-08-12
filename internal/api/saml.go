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

	"github.com/nokku-sh/nokku/internal/billing"
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

	middleware, err := s.getSAMLMiddleware(r.Context(), providerID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Provider configuration failed")
		return
	}

	state := SAMLState{ProviderID: providerID}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	relayState := base64.StdEncoding.EncodeToString(stateJSON)

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

	redirectURL, err := authReq.Redirect(relayState, &middleware.ServiceProvider)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to build redirect URL")
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

func (s *SAMLHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	redirect := s.cfg.FullURL()

	fail := func(code string, err error) {
		if err != nil {
			slog.Debug("saml callback failed", "error_code", code, "error", err)
		}
		authErrorRedirect(w, r, redirect, code)
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB
	if err := r.ParseForm(); err != nil {
		fail("invalid_request", err)
		return
	}

	var state SAMLState
	if relayState := r.FormValue("RelayState"); relayState != "" {
		stateJSON, err := base64.StdEncoding.DecodeString(relayState)
		if err != nil {
			fail("invalid_state", err)
			return
		}
		if err := json.Unmarshal(stateJSON, &state); err != nil {
			fail("invalid_state", err)
			return
		}
	}

	middleware, err := s.getSAMLMiddleware(ctx, state.ProviderID)
	if err != nil {
		fail("provider_config_failed", err)
		return
	}

	var possibleRequestIDs []string
	trackedRequests := middleware.RequestTracker.GetTrackedRequests(r)
	for _, req := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, req.SAMLRequestID)
	}

	assertion, err := middleware.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		fail("invalid_assertion", err)
		return
	}

	if err := middleware.RequestTracker.StopTrackingRequest(w, r, assertion.ID); err != nil {
		slog.Warn("failed to stop tracking request", "error", err)
	}
	for _, req := range trackedRequests {
		if err := middleware.RequestTracker.StopTrackingRequest(
			w,
			r,
			req.SAMLRequestID,
		); err != nil {
			slog.Debug("failed to stop tracking request", "error", err)
		}
	}

	// Get provider config for attribute mappings. Pre-authentication SSO
	// callback: resolved by provider ID, running as a system transaction.
	var dbConfig *db.SamlProvider
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		dbConfig, err = q.GetSAMLProviderByID(ctx, state.ProviderID)
		return err
	}); err != nil {
		fail("provider_config_failed", err)
		return
	}

	userAttr, err := s.extractAttributes(ctx, assertion, dbConfig)
	if err != nil {
		fail("invalid_attributes", err)
		return
	}

	if assertion.Subject == nil || assertion.Subject.NameID == nil ||
		assertion.Subject.NameID.Value == "" {
		fail("missing_name_id", nil)
		return
	}
	nameID := assertion.Subject.NameID.Value

	user, err := s.handleSAMLUser(ctx, userAttr, dbConfig, nameID)
	if err != nil {
		fail("user_failed", err)
		return
	}

	if a := meta.AuditStateFromContext(r.Context()); a != nil {
		a.UserID = user.ID
	}

	s.cfg.Authn.AccessCookie(ctx, w.Header(), user)
	s.cfg.Authn.RefreshCookie(ctx, w.Header(), user)
	syncWebDevice(ctx, s.cfg, r.Header, w.Header(), r.RemoteAddr, user)

	authRedirect(w, r, redirect)
}

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
		slog.Error("failed to write metadata", "error", err)
	}
}

func (s *SAMLHandler) CertificateHandler(w http.ResponseWriter, r *http.Request) {
	var provider *db.SamlProvider
	if err := s.cfg.Conn.WithTx(r.Context(), func(q *db.Queries) (err error) {
		provider, err = q.GetSAMLProviderByID(r.Context(), r.PathValue("id"))
		return err
	}); err != nil || provider == nil {
		writeJSONError(w, http.StatusNotFound, "Provider not found")
		return
	}
	if provider.SpCertificate == nil {
		writeJSONError(w, http.StatusNotFound, "Certificate not found")
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="nokku-sp.pem"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if _, err := w.Write([]byte(*provider.SpCertificate)); err != nil {
		slog.Error("failed to write certificate", "error", err)
	}
}

func (s *SAMLHandler) handleSAMLUser(
	ctx context.Context,
	user *db.User,
	saml *db.SamlProvider,
	nameID string,
) (*db.User, error) {
	existingUser, err := s.cfg.Conn.Q.GetUserByEmail(ctx, user.Email)

	if err == nil {
		var updatedUser *db.User
		err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
			if saml.EnforceSso {
				identity, err := q.GetUserIdentity(
					ctx,
					&db.GetUserIdentityParams{
						ProviderID: nameID,
						Provider:   saml.WorkspaceID,
					},
				)
				// First SAML login: no identity yet, so allow it.
				if err == nil && identity.UserID != existingUser.ID {
					return fmt.Errorf("enforce_sso: user must login via SAML")
				}
			}

			updatedUser, err = q.UpdateUser(ctx, &db.UpdateUserParams{
				UserID:   existingUser.ID,
				Username: &user.Username,
				Name:     &user.Name,
				Picture:  user.Picture,
			})
			if err != nil {
				return fmt.Errorf("failed to update user: %w", err)
			}

			if err := q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
				UserID: existingUser.ID,
				Email:  user.Email,
			}); err != nil {
				return fmt.Errorf("failed to verify user email: %w", err)
			}

			// Transient NameIDs change on every login, so stale rows would
			// accumulate: keep at most one SAML identity per user. The
			// protocol filter leaves OIDC mappings for the same workspace
			// provider untouched.
			if err := q.DeleteUserIdentitiesByUserAndProtocol(
				ctx,
				&db.DeleteUserIdentitiesByUserAndProtocolParams{
					UserID:   existingUser.ID,
					Provider: saml.WorkspaceID,
					Protocol: "saml",
				},
			); err != nil {
				return fmt.Errorf("failed to clear stale SAML identity: %w", err)
			}

			_, err = q.UpsertUserIdentity(ctx, &db.UpsertUserIdentityParams{
				ProviderID:       nameID,
				Provider:         saml.WorkspaceID,
				UserID:           existingUser.ID,
				ProviderEmail:    &user.Email,
				ProviderUsername: &user.Username,
				Protocol:         "saml",
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

	if !saml.AllowJitProvisioning {
		return nil, fmt.Errorf("user not found and JIT provisioning is disabled")
	}

	var newUser *db.User
	err = s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		newUser, err = q.CreateUser(ctx, &db.CreateUserParams{
			Name:     user.Name,
			Username: user.Username,
			Picture:  user.Picture,
			Email:    user.Email,
		})
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		if err := q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
			UserID: newUser.ID,
			Email:  newUser.Email,
		}); err != nil {
			return fmt.Errorf("failed to verify user email: %w", err)
		}

		// Link the SAML identity (using the NameID as the provider identifier)
		_, err = q.UpsertUserIdentity(ctx, &db.UpsertUserIdentityParams{
			ProviderID:       nameID,
			Provider:         saml.WorkspaceID,
			UserID:           newUser.ID,
			ProviderEmail:    &newUser.Email,
			ProviderUsername: &newUser.Username,
			Protocol:         "saml",
		})
		if err != nil {
			return fmt.Errorf("failed to create SAML identity: %w", err)
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

func (s *SAMLHandler) extractAttributes(
	ctx context.Context,
	assertion *saml.Assertion,
	saml *db.SamlProvider,
) (*db.User, error) {
	getAttr := func(name string) string {
		for _, stmt := range assertion.AttributeStatements {
			for _, attr := range stmt.Attributes {
				if len(attr.Values) > 0 &&
					(attr.Name == name || attr.FriendlyName == name) {
					return attr.Values[0].Value
				}
			}
		}
		return ""
	}

	attributeNames := func() []string {
		var names []string
		for _, stmt := range assertion.AttributeStatements {
			for _, attr := range stmt.Attributes {
				names = append(names, attr.Name)
			}
		}
		return names
	}

	email := getAttr(saml.EmailAttribute)
	if email == "" {
		return nil, fmt.Errorf(
			"email attribute '%s' not found; received attributes: %v",
			saml.EmailAttribute,
			attributeNames(),
		)
	}

	name := getAttr(saml.NameAttribute)

	// A nil picture keeps the stored one: not every IdP sends a picture
	// attribute, and an empty value would wipe it on every login.
	var picture *string
	if saml.PictureAttribute != nil {
		if p := getAttr(*saml.PictureAttribute); p != "" {
			picture = &p
		}
	}

	username, err := util.GenerateUsername(
		email,
		getAttr(saml.UsernameAttribute),
		[]string{name},
	)
	if err != nil || username == "" {
		return nil, fmt.Errorf("failed to generate username: %w", err)
	}

	domain := strings.Split(email, "@")
	if len(domain) != 2 {
		return nil, fmt.Errorf("invalid email format")
	}

	var ok bool
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		ok, err = q.VerifiedDomainExists(ctx, domain[1])
		return err
	}); err != nil || !ok {
		return nil, fmt.Errorf("domain %q not verified for SSO: %w", domain[1], err)
	}

	return &db.User{
		Email:    email,
		Name:     name,
		Username: username,
		Picture:  picture,
	}, nil
}

func (s *SAMLHandler) getSAMLMiddleware(
	ctx context.Context,
	id string,
) (*samlsp.Middleware, error) {
	// Get provider config (always needed for SP cert/key). Pre-auth lookup
	// by provider ID, running as a system transaction.
	var provider *db.SamlProvider
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		provider, err = q.GetSAMLProviderByID(ctx, id)
		return err
	}); err != nil {
		return nil, fmt.Errorf("failed to get SAML provider: %w", err)
	}
	if !s.cfg.Billing.Has(ctx, provider.WorkspaceID, billing.FeatureSAML) {
		return nil, fmt.Errorf("SAML requires an Enterprise plan")
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
	var idpMetadata *saml.EntityDescriptor
	if cached, ok := s.metadataCache.Load(cacheKey); ok {
		idpMetadata, ok = cached.(*saml.EntityDescriptor)
		if !ok {
			s.metadataCache.Delete(cacheKey)
		}
	}

	if idpMetadata == nil {
		metadataURL, err := url.Parse(*provider.MetadataURL)
		if err != nil {
			return nil, fmt.Errorf("invalid metadata URL: %w", err)
		}

		idpMetadata, err = samlsp.FetchMetadata(ctx, http.DefaultClient, *metadataURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch IdP metadata: %w", err)
		}

		if metadataXML, err := xml.Marshal(idpMetadata); err == nil {
			_ = s.cfg.Cache.Set(ctx, cacheKey, metadataXML, 1*time.Hour)
		}
		s.metadataCache.Store(cacheKey, idpMetadata)
	}

	certBlock, _ := pem.Decode([]byte(*provider.SpCertificate))
	if certBlock == nil {
		return nil, fmt.Errorf("failed to parse sp certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SP certificate: %w", err)
	}

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

	rootURL, err := url.Parse(s.cfg.FullURL())
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

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

	middleware.ServiceProvider.SignatureMethod = dsig.RSASHA256SignatureMethod

	// Override ACS URL to match our routing
	middleware.ServiceProvider.AcsURL = *rootURL.ResolveReference(&url.URL{Path: "/saml/acs"})

	return middleware, nil
}

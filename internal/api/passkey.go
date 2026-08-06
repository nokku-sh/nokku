package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/nokku-sh/nokku/internal/authn"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
	"github.com/nokku-sh/nokku/internal/meta"
)

// AAGUIDMetadata maps known AAGUIDs to device/authenticator names.
var aaguidDeviceMap = map[string]string{
	"00000000-0000-0000-0000-000000000000": "Generic Authenticator",
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain (Managed)",
	"531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"b84e4048-15dc-4dd0-8640-f4f60813c8af": "NordPass",
	"0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6": "Keeper",
	"891494da-2c90-4d31-a9cd-4eab0aed1309": "Sésame",
	"f3809540-7f14-49c1-a8b3-8f813b225541": "Enpass",
	"b5397666-4885-aa6b-cebf-e52262a439a2": "Chromium Browser",
	"771b48fd-d3d4-4f74-9232-fc157ab0507a": "Edge on Mac",
	"39a5647e-1853-446c-a1f6-a79bae9f5bc7": "IDmelon",
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
	"66a0ccb3-bd6a-191f-ee06-e375c50b9846": "Thales Bio iOS SDK",
	"8836336a-f590-0921-301d-46427531eee6": "Thales Bio Android SDK",
	"cd69adb5-3c7a-deb9-3177-6800ea6cb72a": "Thales PIN Android SDK",
	"17290f1e-c212-34d0-1423-365d729f09d9": "Thales PIN iOS SDK",
	"50726f74-6f6e-5061-7373-50726f746f6e": "Proton Pass",
	"fdb141b2-5d84-443e-8a35-4698c205a502": "KeePassXC",
	"cc45f64e-52a2-451b-831a-4edd8022a202": "ToothPic Passkey Provider",
	"bfc748bb-3429-4faa-b9f9-7cfa9f3b76d0": "iPasswords",
	"b35a26b2-8f6e-4697-ab1d-d44db4da28c6": "Zoho Vault",
	"b78a0a55-6ef8-d246-a042-ba0f6d55050c": "LastPass",
	"de503f9c-21a4-4f76-b4b7-558eb55c6f89": "Devolutions",
	"22248c4c-7a12-46e2-9a41-44291b373a4d": "LogMeOnce",
	"a10c6dd9-465e-4226-8198-c7c44b91c555": "Kaspersky Password Manager",
	"d350af52-0351-4ba2-acd3-dfeeadc3f764": "pwSafe",
	"d3452668-01fd-4c12-926c-83a4204853aa": "Microsoft Password Manager",
	"6d212b28-a2c1-4638-b375-5932070f62e9": "initial",
}

type PasskeyService struct {
	cfg      *config.Config
	webauthn *webauthn.WebAuthn
}

// WebAuthnUser implements the webauthn.User interface.
type WebAuthnUser struct {
	user        *db.User
	credentials []*db.Passkey
}

func (u WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u WebAuthnUser) WebAuthnName() string {
	return u.user.Username
}

func (u WebAuthnUser) WebAuthnDisplayName() string {
	if u.user.Name != "" {
		return u.user.Name
	}
	return u.user.Username
}

func (u WebAuthnUser) WebAuthnIcon() string {
	if u.user.Picture != nil {
		return *u.user.Picture
	}
	return ""
}

func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(u.credentials))
	for i, dbCred := range u.credentials {
		transports := make([]protocol.AuthenticatorTransport, len(dbCred.Transports))
		for j, t := range dbCred.Transports {
			transports[j] = protocol.AuthenticatorTransport(t)
		}

		credentialID, err := base64.RawURLEncoding.DecodeString(dbCred.ID)
		if err != nil {
			slog.Error("failed to decode credential id", "error", err, "id", dbCred.ID)
			continue
		}

		// Cap sign count to uint32 max before conversion.
		var signCount uint32
		if dbCred.SignCount < 0 || dbCred.SignCount > int64(^uint32(0)) {
			slog.Warn("sign count out of range, capping", "value", dbCred.SignCount)
			signCount = ^uint32(0)
		} else {
			signCount = uint32(dbCred.SignCount)
		}

		creds[i] = webauthn.Credential{
			ID:              credentialID,
			PublicKey:       dbCred.PublicKey,
			AttestationType: dbCred.AttestationType,
			Transport:       transports,
			Flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: dbCred.BackupEligible,
				BackupState:    dbCred.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    dbCred.Aaguid,
				SignCount: signCount,
			},
		}
	}
	return creds
}

func NewPasskeyService(cfg *config.Config) (*PasskeyService, error) {
	rpOrigins := []string{cfg.FullURL()}
	if cfg.Debug {
		rpOrigins = append(rpOrigins, "http://localhost:5173")
	}

	wconfig := &webauthn.Config{
		RPDisplayName:         "Nokku",
		RPID:                  cfg.AppURL().Hostname(),
		RPOrigins:             rpOrigins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyNotRequired(),
			ResidentKey:        protocol.ResidentKeyRequirementPreferred,
			UserVerification:   protocol.VerificationPreferred,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Timeout: time.Minute * 5},
			Registration: webauthn.TimeoutConfig{Timeout: time.Minute * 5},
		},
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize webauthn: %w", err)
	}

	return &PasskeyService{
		cfg:      cfg,
		webauthn: webAuthn,
	}, nil
}

func (s *PasskeyService) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := meta.UserIDFromContext(ctx)

	user, err := s.cfg.Conn.Q.GetUserByID(ctx, userID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "User not found")
		return
	}

	if err := checkSSOEnforced(ctx, s.cfg, user.Email); err != nil {
		if errors.Is(err, ErrSSORequired) {
			writeJSONError(w, http.StatusForbidden, "Single sign-on is required")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	credentials, err := s.cfg.Conn.Q.GetPasskeysByUserID(ctx, user.ID)
	if err != nil {
		slog.Error("failed to get passkeys", "error", err)
		credentials = []*db.Passkey{}
	}

	webauthnUser := WebAuthnUser{
		user:        user,
		credentials: credentials,
	}

	creation, session, err := s.webauthn.BeginRegistration(webauthnUser)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to begin registration")
		return
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to store session")
		return
	}
	_ = s.cfg.Cache.Set(ctx, fmt.Sprintf("passkey_session.%s", user.ID), sessionData, 5*time.Minute)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(creation); err != nil {
		http.Error(
			w,
			"Failed to encode passkey registration options",
			http.StatusInternalServerError,
		)
		return
	}
}

func (s *PasskeyService) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user, err := s.cfg.Conn.Q.GetUserByID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "User not found")
		return
	}

	type RegistrationRequest struct {
		Name string `json:"name"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Failed to read request")
		return
	}

	var reqBody RegistrationRequest
	_ = json.Unmarshal(body, &reqBody)

	r.Body = io.NopCloser(bytes.NewBuffer(body)) // Reset body for webauthn parsing

	credentials, err := s.cfg.Conn.Q.GetPasskeysByUserID(ctx, user.ID)
	if err != nil {
		credentials = []*db.Passkey{}
	}

	webauthnUser := WebAuthnUser{
		user:        user,
		credentials: credentials,
	}

	sessionKey := fmt.Sprintf("passkey_session.%s", user.ID)
	data, err := s.cfg.Cache.Get(ctx, sessionKey)
	if err != nil || data == nil {
		writeJSONError(w, http.StatusBadRequest, "Session not found or expired")
		return
	}
	_ = s.cfg.Cache.Delete(ctx, sessionKey)

	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to parse session")
		return
	}

	credential, err := s.webauthn.FinishRegistration(webauthnUser, session, r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Failed to finish registration")
		return
	}

	if reqBody.Name == "" {
		reqBody.Name = s.detectAuthenticatorName(credential)
	}

	transports := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transports[i] = string(t)
	}
	if err = s.cfg.Conn.Q.CreatePasskey(ctx, &db.CreatePasskeyParams{
		ID:              base64.RawURLEncoding.EncodeToString(credential.ID),
		UserID:          user.ID,
		Name:            &reqBody.Name,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Aaguid:          credential.Authenticator.AAGUID,
		SignCount:       int64(credential.Authenticator.SignCount),
		Transports:      transports,
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
	}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to store credential")
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *PasskeyService) BeginLogin(w http.ResponseWriter, r *http.Request) {
	// For login, we don't know the user yet, so we use discoverable credentials
	options, session, err := s.webauthn.BeginDiscoverableLogin()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to begin login")
		return
	}

	sessionID := uuid.New().String()
	sessionKey := fmt.Sprintf("passkey_login.%s", sessionID)

	sessionData, err := json.Marshal(session)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to store session")
		return
	}
	_ = s.cfg.Cache.Set(r.Context(), sessionKey, sessionData, 5*time.Minute)

	response := map[string]any{
		"options":   options,
		"sessionId": sessionID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(
			w,
			"Failed to encode passkey login response",
			http.StatusInternalServerError,
		)
		return
	}
}

func (s *PasskeyService) FinishLogin(w http.ResponseWriter, r *http.Request) {
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Failed to parse response")
		return
	}

	req := struct {
		SessionID string `json:"sessionId"`
	}{
		SessionID: r.URL.Query().Get("sessionId"),
	}

	if req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "Session ID required")
		return
	}

	sessionKey := fmt.Sprintf("passkey_login.%s", req.SessionID)
	data, err := s.cfg.Cache.Get(r.Context(), sessionKey)
	if err != nil || data == nil {
		writeJSONError(w, http.StatusBadRequest, "Session not found or expired")
		return
	}
	_ = s.cfg.Cache.Delete(r.Context(), sessionKey)

	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to parse session")
		return
	}

	credentialID := base64.RawURLEncoding.EncodeToString(parsedResponse.RawID)
	credential, err := s.cfg.Conn.Q.GetPasskey(r.Context(), credentialID)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "Credential not found")
		return
	}

	user, err := s.cfg.Conn.Q.GetUserByID(r.Context(), credential.UserID)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "User not found")
		return
	}

	if err := checkSSOEnforced(r.Context(), s.cfg, user.Email); err != nil {
		if errors.Is(err, ErrSSORequired) {
			writeJSONError(w, http.StatusForbidden, "Single sign-on is required")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if !user.EmailVerified {
		writeJSONError(w, http.StatusForbidden, "Email not verified. Please check your email.")
		return
	}

	credentials, err := s.cfg.Conn.Q.GetPasskeysByUserID(r.Context(), user.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to get credentials")
		return
	}

	webauthnUser := WebAuthnUser{
		user:        user,
		credentials: credentials,
	}

	cred, err := s.webauthn.ValidateDiscoverableLogin(
		func(_, _ []byte) (webauthn.User, error) {
			return webauthnUser, nil
		},
		session,
		parsedResponse,
	)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "Failed to validate login")
		return
	}

	// Security check for authenticator cloning
	if cred.Authenticator.SignCount > 0 &&
		int64(cred.Authenticator.SignCount) <= credential.SignCount {
		writeJSONError(w, http.StatusUnauthorized, "Security check failed")
		return
	}

	err = s.cfg.Conn.Q.UpdatePasskeySignCount(
		r.Context(),
		&db.UpdatePasskeySignCountParams{
			PasskeyID: base64.RawURLEncoding.EncodeToString(cred.ID),
			SignCount: int64(cred.Authenticator.SignCount),
		},
	)
	if err != nil {
		slog.Warn("failed to update passkey sign count", "error", err)
	}

	now := time.Now()
	err = s.cfg.Conn.Q.UpdatePasskeyLastUsed(
		r.Context(),
		&db.UpdatePasskeyLastUsedParams{
			PasskeyID:  base64.RawURLEncoding.EncodeToString(cred.ID),
			LastUsedAt: &now,
		},
	)
	if err != nil {
		slog.Warn("failed to update passkey last used", "error", err)
	}

	s.cfg.Authn.AccessCookie(r.Context(), w.Header(), user)
	s.cfg.Authn.RefreshCookie(r.Context(), w.Header(), user)
	syncWebDevice(r.Context(), s.cfg, r.Header, w.Header(), r.RemoteAddr, user)
	meta.SetAuditUserID(r.Context(), user.ID)

	w.WriteHeader(http.StatusOK)
}

func (s *PasskeyService) BeginSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Name     string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	if req.Email == "" || req.Username == "" {
		writeJSONError(w, http.StatusBadRequest, "Email and username are required")
		return
	}

	if err := email.Verify(req.Email); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid email address")
		return
	}

	found, err := s.cfg.Conn.Q.EmailExists(ctx, req.Email)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if found {
		writeJSONError(w, http.StatusConflict, "Email already registered")
		return
	}

	if err := checkSSOEnforced(ctx, s.cfg, req.Email); err != nil {
		if errors.Is(err, ErrSSORequired) {
			writeJSONError(w, http.StatusForbidden, "Single sign-on is required")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	user, err := s.cfg.Conn.Q.CreateUser(ctx, &db.CreateUserParams{
		Name:     req.Name,
		Username: req.Username,
		Email:    req.Email,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	webauthnUser := WebAuthnUser{
		user:        user,
		credentials: []*db.Passkey{},
	}

	creation, session, err := s.webauthn.BeginRegistration(webauthnUser)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to begin registration")
		return
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to store session")
		return
	}
	_ = s.cfg.Cache.Set(ctx, fmt.Sprintf("passkey_signup.%s", user.ID), sessionData, 5*time.Minute)

	creationJSON, err := json.Marshal(creation)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode response")
		return
	}
	var response map[string]any
	if err := json.Unmarshal(creationJSON, &response); err != nil || response == nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode response")
		return
	}
	response["userId"] = user.ID

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode response")
		return
	}
}

func (s *PasskeyService) FinishSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	type FinishSignupRequest struct {
		UserID string `json:"userId"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Failed to read request")
		return
	}

	var reqBody FinishSignupRequest
	_ = json.Unmarshal(body, &reqBody)

	if reqBody.UserID == "" {
		writeJSONError(w, http.StatusBadRequest, "User ID required")
		return
	}

	user, err := s.cfg.Conn.Q.GetUserByID(ctx, reqBody.UserID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "User not found")
		return
	}

	sessionKey := fmt.Sprintf("passkey_signup.%s", user.ID)
	data, err := s.cfg.Cache.Get(ctx, sessionKey)
	if err != nil || data == nil {
		writeJSONError(w, http.StatusBadRequest, "Session not found or expired")
		return
	}
	_ = s.cfg.Cache.Delete(ctx, sessionKey)

	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to parse session")
		return
	}

	r.Body = io.NopCloser(bytes.NewBuffer(body))

	credentials := []*db.Passkey{}
	webauthnUser := WebAuthnUser{
		user:        user,
		credentials: credentials,
	}

	credential, err := s.webauthn.FinishRegistration(webauthnUser, session, r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Failed to finish registration")
		return
	}

	var name string
	if err := json.Unmarshal(body, &struct {
		Name *string `json:"name"`
	}{Name: &name}); err != nil || name == "" {
		name = s.detectAuthenticatorName(credential)
	}

	transports := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transports[i] = string(t)
	}
	if err = s.cfg.Conn.Q.CreatePasskey(ctx, &db.CreatePasskeyParams{
		ID:              base64.RawURLEncoding.EncodeToString(credential.ID),
		UserID:          user.ID,
		Name:            &name,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Aaguid:          credential.Authenticator.AAGUID,
		SignCount:       int64(credential.Authenticator.SignCount),
		Transports:      transports,
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
	}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to store credential")
		return
	}

	token, err := s.cfg.Authn.CreateToken(&authn.TokenParams{
		UserID:    user.ID,
		Email:     user.Email,
		Username:  user.Username,
		TokenType: authn.VerifyToken,
	})
	if err == nil {
		verifyURL := fmt.Sprintf("%s/verify?token=%s", s.cfg.FullURL(), token)
		if err := s.cfg.Email.SendWelcomeEmail(
			ctx,
			user.ID,
			user.Email,
			user.Username,
			verifyURL,
			authn.GetExpiry(authn.VerifyToken),
		); err != nil {
			slog.Error("failed to send welcome email", "error", err)
		}
	} else {
		slog.Error("failed to create verification token", "error", err)
	}

	w.WriteHeader(http.StatusOK)
}

func (s *PasskeyService) detectAuthenticatorName(credential *webauthn.Credential) string {
	var parts []string

	if len(credential.Authenticator.AAGUID) == 16 {
		aaguid := uuid.UUID{}
		copy(aaguid[:], credential.Authenticator.AAGUID)
		if name, ok := aaguidDeviceMap[aaguid.String()]; ok {
			parts = append(parts, name)
		}
	}

	// Check transport types for additional hints
	if len(parts) == 0 && len(credential.Transport) > 0 {
		transport := credential.Transport[0]
		switch transport {
		case protocol.USB:
			parts = append(parts, "USB Security Key")
		case protocol.NFC:
			parts = append(parts, "NFC Security Key")
		case protocol.BLE:
			parts = append(parts, "Bluetooth Security Key")
		case protocol.SmartCard:
			parts = append(parts, "Smart Card")
		case protocol.Hybrid:
			parts = append(parts, "Hybrid")
		case protocol.Internal:
			parts = append(parts, "Internal")
		}
	}

	if len(parts) > 0 {
		return strings.Join(parts, " - ")
	}

	// Ultimate fallback
	now := time.Now()
	return fmt.Sprintf("Passkey (%s)", now.Format("Jan 2, 2006"))
}

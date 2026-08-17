package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/mizuchilabs/kagi"
	"github.com/mizuchilabs/kagi/passkey"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/email"
)

// Passkeys wires kagi's passkey handler to nokku's three flows: adding a key
// to a signed-in account, usernameless login, and passkey-only signup.
type Passkeys struct {
	Register *passkey.Handler
	Login    *passkey.Handler
	Signup   *passkey.Handler
}

func NewPasskeys(cfg *config.Config) (*Passkeys, error) {
	rpOrigins := []string{cfg.FullURL()}
	if cfg.Debug {
		rpOrigins = append(rpOrigins, "http://localhost:5173")
	}
	waConfig := webauthn.Config{
		RPDisplayName: "Nokku",
		RPID:          cfg.AppURL().Hostname(),
		RPOrigins:     rpOrigins,
	}

	register, err := passkey.New(cfg.Auth.Kagi, passkey.Options{
		Cache:                 cfg.Cache,
		Config:                waConfig,
		Secure:                true,
		ResolveUser:           principalUser(cfg),
		SkipSessionOnRegister: true,
	})
	if err != nil {
		return nil, err
	}

	login, err := passkey.New(cfg.Auth.Kagi, passkey.Options{
		Cache:  cfg.Cache,
		Config: waConfig,
		Secure: true,
	})
	if err != nil {
		return nil, err
	}

	signup, err := passkey.New(cfg.Auth.Kagi, passkey.Options{
		Cache:                 cfg.Cache,
		Config:                waConfig,
		Secure:                true,
		ResolveUser:           signupUser(cfg),
		SkipSessionOnRegister: true,
		OnRegistered:          welcomeEmail(cfg),
	})
	if err != nil {
		return nil, err
	}

	return &Passkeys{Register: register, Login: login, Signup: signup}, nil
}

// principalUser resolves the signed-in user for the add-key flow.
func principalUser(cfg *config.Config) func(context.Context, *http.Request) (kagi.User, error) {
	return func(ctx context.Context, _ *http.Request) (kagi.User, error) {
		p, ok := kagi.PrincipalFromContext(ctx)
		if !ok {
			return kagi.User{}, errors.New("not authenticated")
		}
		return cfg.Auth.Store.GetUser(ctx, "", p.SubjectID)
	}
}

// signupUser resolves (or provisions) the user for passkey-only signup. It is
// idempotent: the user is created on the begin call and looked up on finish.
func signupUser(cfg *config.Config) func(context.Context, *http.Request) (kagi.User, error) {
	return func(ctx context.Context, r *http.Request) (kagi.User, error) {
		addr := r.FormValue("email")
		if addr == "" {
			return kagi.User{}, errors.New("email required")
		}
		if err := email.Verify(addr); err != nil {
			return kagi.User{}, errors.New("invalid email address")
		}
		if err := checkSSOEnforced(ctx, cfg, addr); err != nil {
			return kagi.User{}, err
		}

		u, err := cfg.Auth.Store.GetUserByEmail(ctx, "", addr)
		if err == nil {
			return u, nil
		}
		if !errors.Is(err, kagi.ErrNotFound) {
			return kagi.User{}, err
		}

		name := r.FormValue("name")
		if name == "" {
			name = auth.UsernameFromEmail(addr)
		}
		return cfg.Auth.Store.CreateUser(ctx, "", kagi.User{Email: addr, DisplayName: name})
	}
}

// welcomeEmail sends the verification email after a passkey-only signup.
func welcomeEmail(cfg *config.Config) func(context.Context, kagi.TenantID, kagi.User) error {
	return func(ctx context.Context, _ kagi.TenantID, u kagi.User) error {
		token, err := cfg.Auth.Tokens.Issue(ctx, u.ID, auth.PurposeVerify)
		if err != nil {
			return err
		}
		verifyURL := fmt.Sprintf("%s/verify?token=%s", cfg.FullURL(), token)
		return cfg.Email.SendWelcomeEmail(
			ctx, u.ID, u.Email, auth.UsernameFromEmail(u.Email), verifyURL,
			oneTimeTokenTTL.String(),
		)
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/caarlos0/env/v11"
	"github.com/jackc/pgx/v5"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// What compose.dev.yml sets up for Pocket ID.
const (
	pocketID     = "http://localhost:1411"
	pocketIDKey  = "dev-static-api-key" // STATIC_API_KEY of compose.dev.yml
	providerID   = "pocket-id"
	clientID     = "nokku"
	clientSecret = "nokku-dev-secret" //nolint:gosec // dev only
	scimLabel    = "pocket-id (dev)"
)

var groups = []string{"Platform", "SRE"}

// users exist in Pocket ID with a fixed id. It is the sub and the SCIM externalId nokku sees.
// Pocket ID owns the directory, SCIM deletes a user here whose externalId it does not know.
var users = []struct {
	id, email, first, last string
	// role is set before SCIM arrives, members need nothing. The first one is the owner, with its email and name.
	role     nokkuv1.WorkspaceRole
	admin    bool
	disabled bool
	groups   []string
}{
	{
		"00000000-0000-4000-8000-000000000001",
		"admin@nokku.test",
		"Ada",
		"Admin",
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER,
		true,
		false,
		[]string{"Platform"},
	},
	{
		"00000000-0000-4000-8000-000000000002",
		"editor@nokku.test",
		"Eddie",
		"Editor",
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR,
		false,
		false,
		[]string{"Platform"},
	},
	{
		"00000000-0000-4000-8000-000000000003",
		"member@nokku.test",
		"Mona",
		"Member",
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		false,
		false,
		[]string{"Platform"},
	},
	{
		"00000000-0000-4000-8000-000000000004",
		"viewer@nokku.test",
		"Vera",
		"Viewer",
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER,
		false,
		false,
		[]string{"SRE"},
	},
	{
		"00000000-0000-4000-8000-000000000005",
		"gone@nokku.test",
		"Gus",
		"Gone",
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		false,
		true,
		[]string{"SRE"},
	},
}

func runIDP(ctx context.Context, _ *cli.Command) error {
	ec, err := env.ParseAs[config.EnvConfig]()
	if err != nil {
		return err
	}
	if err := waitForServer(ctx, ec.Port); err != nil {
		return err
	}
	ctx, conn, ws, err := open(ctx, ec)
	if err != nil {
		return err
	}
	var scimToken string
	var owner *db.User
	err = conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		scimToken, owner, err = seedIDP(ctx, q, ws.ID)
		return err
	})
	if err != nil {
		return err
	}
	// Pocket ID runs in Docker, the server on this machine.
	scimURL := "http://host.docker.internal:" + ec.Port + "/scim/v2"
	if err := setupPocketID(ctx, owner, iam.RedirectURI(ctx), scimURL, scimToken); err != nil {
		return fmt.Errorf("pocket id: %w", err)
	}
	fmt.Printf("%s signs in with Pocket ID at %s, SCIM sends its %d users now\n", ws.Name, pocketID, len(users))
	return nil
}

// waitForServer returns once the server listens. By then it has made the workspace and the owner.
func waitForServer(ctx context.Context, port string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var d net.Dialer
	for {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("localhost", port))
		if err == nil {
			return c.Close()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the server is not up on port %s: %w", port, err)
		case <-time.After(time.Second):
		}
	}
}

// seedIDP may run again, what is there stays as it is. It returns a new SCIM token for Pocket ID and the owner.
func seedIDP(ctx context.Context, q *db.Queries, workspaceID string) (string, *db.User, error) {
	// SCIM brings everyone, so the provider has no JIT. Settings changed in nokku stay.
	_, err := q.GetSSOProvider(ctx, providerID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		cfg, err := json.Marshal(iam.OIDCProvider{IssuerURL: pocketID, ClientID: clientID, ClientSecret: clientSecret})
		if err != nil {
			return "", nil, err
		}
		if _, err := q.UpsertSSOProvider(ctx, &db.UpsertSSOProviderParams{
			ProviderID: providerID,
			Name:       "Pocket ID",
			Enabled:    true,
			Config:     crypto.EncryptedBytes(cfg),
		}); err != nil {
			return "", nil, fmt.Errorf("provider: %w", err)
		}
	case err != nil:
		return "", nil, err
	}

	for _, u := range users {
		if u.role == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER ||
			u.role == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER {
			continue
		}
		row, err := q.GetUserByEmail(ctx, u.email)
		if errors.Is(err, pgx.ErrNoRows) {
			row, err = q.CreateUser(
				ctx,
				&db.CreateUserParams{Email: u.email, Name: u.first + " " + u.last, Role: u.role},
			)
		}
		if err != nil {
			return "", nil, fmt.Errorf("user %s: %w", u.email, err)
		}
		if err := q.SetUserSCIMExternalID(
			ctx,
			&db.SetUserSCIMExternalIDParams{ID: row.ID, ExternalID: &u.id},
		); err != nil {
			return "", nil, err
		}
	}

	// A sign-in never matches the owner by email, so the link is made here, the way the profile page does it.
	owner, err := q.GetOwner(ctx)
	switch {
	case err == nil:
		sub := users[0].id
		if err := q.SetUserSCIMExternalID(
			ctx,
			&db.SetUserSCIMExternalIDParams{ID: owner.ID, ExternalID: &sub},
		); err != nil {
			return "", nil, err
		}
		if _, err := q.UpsertCredential(ctx, &db.UpsertCredentialParams{
			ID:       workspaceID + ":" + providerID + ":" + sub,
			UserID:   owner.ID,
			Type:     string(iam.MethodOIDC),
			Provider: providerID,
			Subject:  sub,
			Data:     []byte{},
		}); err != nil {
			return "", nil, fmt.Errorf("owner link: %w", err)
		}
	case errors.Is(err, pgx.ErrNoRows):
		owner = nil
		fmt.Println("there is no owner, set NOKKU_ADMIN_EMAIL and run task dev:reset")
	default:
		return "", nil, err
	}

	// Every run hands Pocket ID a new token, the one before is of no use.
	tokens, err := q.ListSCIMTokens(ctx)
	if err != nil {
		return "", nil, err
	}
	for _, t := range tokens {
		if t.Label != scimLabel {
			continue
		}
		if err := q.DeleteSCIMToken(ctx, t.ID); err != nil {
			return "", nil, err
		}
	}
	token, hash := crypto.NewKey(crypto.KeyPrefixSCIM)
	if _, err := q.CreateAccessToken(ctx, &db.CreateAccessTokenParams{
		TokenHash: hash,
		Kind:      string(actor.KindSCIM),
		Method:    string(iam.MethodSCIM),
		Label:     scimLabel,
	}); err != nil {
		return "", nil, fmt.Errorf("scim token: %w", err)
	}
	return token, owner, nil
}

// setupPocketID fills an empty Pocket ID. One that has the client only gets the new SCIM token. Then it syncs.
// The first user takes the owner's email and name, SCIM may neither change the owner's email nor drop them.
func setupPocketID(ctx context.Context, owner *db.User, redirectURI, scimURL, scimToken string) error {
	exists, err := waitForPocketID(ctx)
	if err != nil {
		return err
	}
	scim := map[string]string{"endpoint": scimURL, "token": scimToken, "oidcClientId": clientID}
	var provider struct {
		ID string `json:"id"`
	}

	if exists {
		if err := pocketIDCall(
			ctx,
			http.MethodGet,
			"/api/oidc/clients/"+clientID+"/scim-service-provider",
			nil,
			&provider,
		); err != nil {
			return err
		}
		if err := pocketIDCall(ctx, http.MethodPut, "/api/scim/service-provider/"+provider.ID, scim, nil); err != nil {
			return err
		}
		return pocketIDCall(ctx, http.MethodPost, "/api/scim/service-provider/"+provider.ID+"/sync", nil, nil)
	}

	groupIDs := map[string]string{}
	for _, name := range groups {
		var g struct {
			ID string `json:"id"`
		}
		if err := pocketIDCall(ctx, http.MethodPost, "/api/user-groups",
			map[string]string{"friendlyName": name, "name": name}, &g); err != nil {
			return err
		}
		groupIDs[name] = g.ID
	}
	for i, u := range users {
		ids := []string{}
		for _, g := range u.groups {
			ids = append(ids, groupIDs[g])
		}
		display := u.first + " " + u.last
		if i == 0 && owner != nil {
			u.email = owner.Email
			if owner.Name != "" {
				u.first, u.last, display = owner.Name, "", owner.Name
			}
		}
		if err := pocketIDCall(ctx, http.MethodPost, "/api/users", map[string]any{
			"id":            u.id,
			"username":      fmt.Sprintf("user%d", i+1),
			"email":         u.email,
			"emailVerified": true,
			"firstName":     u.first,
			"lastName":      u.last,
			"displayName":   display,
			"isAdmin":       u.admin,
			"disabled":      u.disabled,
			"userGroupIds":  ids,
		}, nil); err != nil {
			return err
		}
	}
	// Only the groups may use it, so SCIM leaves out the user behind the static API key.
	if err := pocketIDCall(ctx, http.MethodPost, "/api/oidc/clients", map[string]any{
		"id":                clientID,
		"name":              "nokku",
		"callbackURLs":      []string{redirectURI},
		"pkceEnabled":       true,
		"skipConsent":       true,
		"isGroupRestricted": true,
	}, nil); err != nil {
		return err
	}
	if err := pocketIDCall(ctx, http.MethodPut, "/api/oidc/clients/"+clientID+"/allowed-user-groups",
		map[string]any{"userGroupIds": slices.Collect(maps.Values(groupIDs))}, nil); err != nil {
		return err
	}
	if err := pocketIDCall(ctx, http.MethodPost, "/api/oidc/clients/"+clientID+"/secrets",
		map[string]string{"secret": clientSecret}, nil); err != nil {
		return err
	}
	if err := pocketIDCall(ctx, http.MethodPost, "/api/scim/service-provider", scim, &provider); err != nil {
		return err
	}
	return pocketIDCall(ctx, http.MethodPost, "/api/scim/service-provider/"+provider.ID+"/sync", nil, nil)
}

// waitForPocketID reports whether Pocket ID has the client yet.
func waitForPocketID(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for {
		err := pocketIDCall(ctx, http.MethodGet, "/api/oidc/clients/"+clientID, nil, nil)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, errNotFound) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, err
		case <-time.After(time.Second):
		}
	}
}

var errNotFound = errors.New("not found")

func pocketIDCall(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, pocketID+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", pocketIDKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s %s: %w", method, path, errNotFound)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.UnmarshalRead(resp.Body, out)
}

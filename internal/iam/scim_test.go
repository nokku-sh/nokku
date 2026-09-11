package iam

// SCIM flow tests. The store is faked at the same seams the SSO flow tests
// use: db.Querier methods for plain reads and writes, and a DBTX that
// dispatches the transactional queries by SQL shape, so the SCIM handlers
// run end to end over httptest.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

type scimStore struct {
	db.Querier

	users    map[string]*db.User
	byEmail  map[string]*db.User
	members  map[string]map[string]bool // workspace id -> user ids
	creds    map[string]*db.Credential  // key: type|provider|subject
	tokens   map[string]*db.ScimToken   // key: token hash
	sessions map[string]string          // token hash -> subject id
	teams    map[string]*db.Team
	teamMems map[string]map[string]bool // team id -> user ids

	revocations     map[string]bool // subject ids whose certificates were revoked
	grantDrops      map[string]int  // subject id -> grant delete statements run
	ownedWorkspaces map[string]int  // user id -> owned workspace count

	userCounter int
	teamCounter int
	tokenDate   time.Time
}

func newSCIMStore() *scimStore {
	return &scimStore{
		users:           map[string]*db.User{},
		byEmail:         map[string]*db.User{},
		members:         map[string]map[string]bool{},
		creds:           map[string]*db.Credential{},
		tokens:          map[string]*db.ScimToken{},
		sessions:        map[string]string{},
		ownedWorkspaces: map[string]int{},
		teams:           map[string]*db.Team{},
		teamMems:        map[string]map[string]bool{},
		revocations:     map[string]bool{},
		grantDrops:      map[string]int{},
	}
}

func (f *scimStore) seedMember(ws, email string) *db.User {
	f.userCounter++
	u := &db.User{
		ID:        fmt.Sprintf("user-%03d", f.userCounter),
		Email:     normalizeEmail(email),
		Name:      "Seeded " + email,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	f.users[u.ID] = u
	f.byEmail[u.Email] = u
	f.addMember(ws, u.ID)
	return u
}

func (f *scimStore) addMember(ws, userID string) {
	if f.members[ws] == nil {
		f.members[ws] = map[string]bool{}
	}
	f.members[ws][userID] = true
}

func (f *scimStore) CreateUser(_ context.Context, arg *db.CreateUserParams) (*db.User, error) {
	email := normalizeEmail(arg.Email)
	if _, taken := f.byEmail[email]; taken {
		return nil, &pgconn.PgError{Code: "23505", Message: "duplicate key"}
	}
	f.userCounter++
	u := &db.User{
		ID:        fmt.Sprintf("user-%03d", f.userCounter),
		Email:     email,
		Name:      arg.Name,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	f.users[u.ID] = u
	f.byEmail[u.Email] = u
	return u, nil
}

func (f *scimStore) GetUser(_ context.Context, id string) (*db.User, error) {
	u, ok := f.users[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return u, nil
}

func (f *scimStore) GetUserByEmail(_ context.Context, email string) (*db.User, error) {
	u, ok := f.byEmail[normalizeEmail(email)]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return u, nil
}

func (f *scimStore) UpdateUser(_ context.Context, arg *db.UpdateUserParams) (*db.User, error) {
	u, ok := f.users[arg.ID]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	if arg.Name != nil {
		u.Name = *arg.Name
	}
	if arg.Active != nil {
		u.Active = *arg.Active
	}
	if arg.DisablePasswordReset != nil {
		u.DisablePasswordReset = *arg.DisablePasswordReset
	}
	u.UpdatedAt = time.Now()
	return u, nil
}

func (f *scimStore) VerifyUserEmail(_ context.Context, id string) error {
	f.users[id].EmailVerified = true
	return nil
}

func (f *scimStore) DeleteSubjectSessions(_ context.Context, subjectID string) (int64, error) {
	var n int64
	for hash, subject := range f.sessions {
		if subject == subjectID {
			delete(f.sessions, hash)
			n++
		}
	}
	return n, nil
}

func (f *scimStore) GetWorkspaceMember(
	_ context.Context,
	arg *db.GetWorkspaceMemberParams,
) (*db.WorkspaceMember, error) {
	if !f.members[arg.WorkspaceID][arg.UserID] {
		return nil, pgx.ErrNoRows
	}
	return &db.WorkspaceMember{WorkspaceID: arg.WorkspaceID, UserID: arg.UserID}, nil
}

func (f *scimStore) ListWorkspaceMembers(
	_ context.Context,
	arg *db.ListWorkspaceMembersParams,
) ([]*db.ListWorkspaceMembersRow, error) {
	var out []*db.ListWorkspaceMembersRow
	for uid := range f.members[arg.WorkspaceID] {
		u := f.users[uid]
		out = append(out, &db.ListWorkspaceMembersRow{
			WorkspaceID: arg.WorkspaceID,
			UserID:      u.ID,
			Name:        u.Name,
			Email:       u.Email,
			Active:      u.Active,
			CreatedAt:   u.CreatedAt,
			UpdatedAt:   u.UpdatedAt,
		})
	}
	return out, nil
}

func (f *scimStore) GetSCIMCredentialByUser(
	_ context.Context,
	arg *db.GetSCIMCredentialByUserParams,
) (string, error) {
	for _, c := range f.creds {
		if c.UserID == arg.UserID && c.Type == string(MethodSCIM) && c.Provider == arg.WorkspaceID {
			return c.Subject, nil
		}
	}
	return "", pgx.ErrNoRows
}

func (f *scimStore) ListWorkspaceSCIMCredentials(
	_ context.Context,
	workspaceID string,
) ([]*db.ListWorkspaceSCIMCredentialsRow, error) {
	var out []*db.ListWorkspaceSCIMCredentialsRow
	for _, c := range f.creds {
		if c.Type == string(MethodSCIM) && c.Provider == workspaceID {
			out = append(out, &db.ListWorkspaceSCIMCredentialsRow{UserID: c.UserID, Subject: c.Subject})
		}
	}
	return out, nil
}

func (f *scimStore) CreateTeam(_ context.Context, arg *db.CreateTeamParams) (*db.Team, error) {
	for _, team := range f.teams {
		if team.WorkspaceID == arg.WorkspaceID && team.Name == arg.Name {
			return nil, &pgconn.PgError{Code: "23505", Message: "duplicate key"}
		}
	}
	f.teamCounter++
	team := &db.Team{
		ID:          fmt.Sprintf("team-%03d", f.teamCounter),
		WorkspaceID: arg.WorkspaceID,
		Name:        arg.Name,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	f.teams[team.ID] = team
	f.teamMems[team.ID] = map[string]bool{}
	return team, nil
}

func (f *scimStore) GetTeam(_ context.Context, id string) (*db.Team, error) {
	team, ok := f.teams[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return team, nil
}

func (f *scimStore) ListTeams(_ context.Context, arg *db.ListTeamsParams) ([]*db.ListTeamsRow, error) {
	var out []*db.ListTeamsRow
	for _, team := range f.teams {
		if team.WorkspaceID != arg.WorkspaceID {
			continue
		}
		out = append(out, &db.ListTeamsRow{Team: *team})
	}
	return out, nil
}

func (f *scimStore) UpdateTeam(_ context.Context, arg *db.UpdateTeamParams) (*db.Team, error) {
	team, ok := f.teams[arg.TeamID]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	if arg.Name != nil && *arg.Name != team.Name {
		for _, other := range f.teams {
			if other.ID != team.ID && other.WorkspaceID == team.WorkspaceID && other.Name == *arg.Name {
				return nil, &pgconn.PgError{Code: "23505", Message: "duplicate key"}
			}
		}
	}
	if arg.Name != nil {
		team.Name = *arg.Name
	}
	team.UpdatedAt = time.Now()
	return team, nil
}

func (f *scimStore) DeleteTeam(_ context.Context, id string) (*db.Team, error) {
	team, ok := f.teams[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	delete(f.teams, id)
	delete(f.teamMems, id)
	return team, nil
}

func (f *scimStore) AddTeamMember(_ context.Context, arg *db.AddTeamMemberParams) error {
	if f.teamMems[arg.TeamID] == nil {
		f.teamMems[arg.TeamID] = map[string]bool{}
	}
	f.teamMems[arg.TeamID][arg.UserID] = true
	return nil
}

func (f *scimStore) RemoveTeamMember(_ context.Context, arg *db.RemoveTeamMemberParams) error {
	if members, ok := f.teamMems[arg.TeamID]; ok {
		delete(members, arg.UserID)
	}
	return nil
}

func (f *scimStore) ListTeamMembers(_ context.Context, teamID string) ([]*db.ListTeamMembersRow, error) {
	var out []*db.ListTeamMembersRow
	for uid := range f.teamMems[teamID] {
		u := f.users[uid]
		out = append(out, &db.ListTeamMembersRow{TeamID: teamID, UserID: uid, Email: u.Email})
	}
	return out, nil
}

// scimConn fakes the transactional surface by dispatching the SQL shapes
// the SCIM path issues onto the shared in-memory store.
type scimConn struct{ st *scimStore }

func (c *scimConn) Querier() db.Querier { return c.st }

func (c *scimConn) AdminQuerier() db.Querier { return c.st }

func (c *scimConn) WithTx(_ context.Context, fn func(*db.Queries) error) error {
	return fn(db.New(c))
}

func (c *scimConn) WithWorkspace(_ context.Context, fn func(*db.Queries) error) error {
	return fn(db.New(c))
}

func (c *scimConn) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	switch {
	case strings.Contains(sql, "workspace_members") && strings.Contains(sql, "INSERT"):
		c.st.addMember(args[0].(string), args[1].(string))
	case strings.Contains(sql, "workspace_members") && strings.Contains(sql, "DELETE"):
		if members, ok := c.st.members[args[0].(string)]; ok {
			delete(members, args[1].(string))
		}
	case strings.Contains(sql, "credentials") && strings.Contains(sql, "DELETE"):
		for key, cred := range c.st.creds {
			if cred.UserID == args[0].(string) && cred.Provider == args[1].(string) {
				delete(c.st.creds, key)
			}
		}
	case strings.Contains(sql, "sessions") && strings.Contains(sql, "DELETE"):
		for hash, subject := range c.st.sessions {
			if subject == args[0].(string) {
				delete(c.st.sessions, hash)
			}
		}
	case strings.Contains(sql, "scim_tokens") && strings.Contains(sql, "UPDATE"):
		if tok, ok := c.st.tokens[args[0].(string)]; ok {
			tok.LastUsedAt = &c.st.tokenDate
		}
	case strings.Contains(sql, "scim_tokens") && strings.Contains(sql, "DELETE"):
		for key, tok := range c.st.tokens {
			if tok.ID == args[0].(string) && tok.WorkspaceID == args[1].(string) {
				delete(c.st.tokens, key)
			}
		}
	case strings.Contains(sql, "principal_grants") && strings.Contains(sql, "DELETE"):
		if strings.Contains(sql, "workspace_id") {
			c.st.grantDrops[args[2].(string)]++
		} else {
			c.st.grantDrops[args[1].(string)]++
		}
	case strings.Contains(sql, "ssh_principal_revocations"):
		c.st.revocations[args[1].(string)] = true
	case strings.Contains(sql, "DELETE") && strings.Contains(sql, "users"):
		uid := args[0].(string)
		if u, ok := c.st.users[uid]; ok {
			delete(c.st.users, uid)
			delete(c.st.byEmail, u.Email)
			for ws := range c.st.members {
				delete(c.st.members[ws], uid)
			}
		}
	default:
		panic("scim test: unexpected exec: " + sql)
	}
	return pgconn.NewCommandTag("OK"), nil
}

func (c *scimConn) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "users") && strings.Contains(sql, "UPDATE"):
		uid := args[4].(string)
		u, ok := c.st.users[uid]
		if !ok {
			return errRow{pgx.ErrNoRows}
		}
		if active, ok := args[2].(*bool); ok {
			u.Active = *active
		}
		if name, ok := args[0].(*string); ok && name != nil {
			u.Name = *name
		}
		u.UpdatedAt = time.Now()
		var picture any
		if u.Picture != nil {
			picture = *u.Picture
		}
		return &sliceRow{vals: []any{
			u.ID, u.Email, u.Name, picture, u.Active, u.EmailVerified, u.DisablePasswordReset, u.CreatedAt, u.UpdatedAt,
		}}
	case strings.Contains(sql, "workspace_members") && strings.Contains(sql, "COUNT"):
		uid := args[0].(string)
		n := 0
		for ws, members := range c.st.members {
			// Mirror the SQL: self-owned workspaces are shadow-IT, not
			// memberships that keep the account alive.
			if ws != args[1].(string) && members[uid] && c.st.ownedWorkspaces[uid] == 0 {
				n++
			}
		}
		return &sliceRow{vals: []any{int32(n)}}
	case strings.Contains(sql, "workspaces") && strings.Contains(sql, "COUNT"):
		return &sliceRow{vals: []any{int32(c.st.ownedWorkspaces[args[0].(string)])}}
	case strings.Contains(sql, "credentials") && strings.Contains(sql, "INSERT"):
		cred := &db.Credential{
			ID:        args[0].(string),
			UserID:    args[1].(string),
			Type:      args[2].(string),
			Provider:  args[3].(string),
			Subject:   args[4].(string),
			Data:      args[5].([]byte),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		c.st.creds[cred.Type+"|"+cred.Provider+"|"+cred.Subject] = cred
		return &sliceRow{vals: []any{
			cred.ID,
			cred.UserID,
			cred.Type,
			cred.Provider,
			cred.Subject,
			cred.Data,
			cred.Label,
			cred.CreatedAt,
			cred.UpdatedAt,
		}}
	case strings.Contains(sql, "scim_tokens") && strings.Contains(sql, "INSERT"):
		tok := &db.ScimToken{
			ID:          fmt.Sprintf("token-%d", len(c.st.tokens)+1),
			WorkspaceID: args[0].(string),
			TokenHash:   args[1].(crypto.HashedToken),
			Label:       args[2].(string),
			CreatedAt:   c.st.tokenDate,
		}
		c.st.tokens[tok.TokenHash.Hash()] = tok
		return &sliceRow{vals: []any{tok.ID, tok.Label, tok.CreatedAt, scimNullTime(tok.LastUsedAt)}}
	case strings.Contains(sql, "scim_tokens"):
		tok, ok := c.st.tokens[args[0].(crypto.HashedToken).Hash()]
		if !ok {
			return errRow{pgx.ErrNoRows}
		}
		return &sliceRow{
			vals: []any{tok.ID, tok.WorkspaceID, tok.TokenHash, tok.Label, tok.CreatedAt, scimNullTime(tok.LastUsedAt)},
		}
	default:
		panic("scim test: unexpected query row: " + sql)
	}
}

func (c *scimConn) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	panic("scim test: unexpected query: " + sql)
}

// scimNullTime passes NULL through the row scanner: a typed nil would not
// trip the scanner's v == nil check.
func scimNullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// newSCIMTest builds a service with a SCIM flow and mints a bearer token.
func newSCIMTest(t *testing.T) (*Service, *scimStore, string) {
	t.Helper()
	st := newSCIMStore()
	svc, err := New(Deps{Conn: &scimConn{st: st}})
	if err != nil {
		t.Fatal(err)
	}
	if svc.SCIM == nil {
		t.Fatal("scim flow missing")
	}
	_, token, err := svc.IssueSCIMToken(context.Background(), testWorkspaceID, "okta")
	if err != nil {
		t.Fatal(err)
	}
	return svc, st, token
}

func scimRequest(t *testing.T, svc *Service, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, &buf)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	svc.SCIMHandler().ServeHTTP(w, r)
	return w
}

const (
	testWorkspaceID  = "0197d5a1-6a33-7a2d-8a4b-000000000001"
	otherWorkspaceID = "0197d5a1-6a33-7a2d-8a4b-000000000002"
)

// oktaCreateUser mirrors the payload shape Okta sends on user creation.
func oktaCreateUser() map[string]any {
	return map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "john.doe@example.com",
		"name": map[string]any{
			"givenName":  "John",
			"familyName": "Doe",
		},
		"displayName": "John Doe",
		"emails": []any{map[string]any{
			"value":   "john.doe@example.com",
			"type":    "work",
			"primary": true,
		}},
		"active":     true,
		"externalId": "okta-user-42",
	}
}

func TestSCIMAuth(t *testing.T) {
	svc, _, _ := newSCIMTest(t)

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"garbage token", "not-a-token", http.StatusUnauthorized},
		{"token bound to another workspace", "deadbeef-0000-0000-0000-000000000000_secret", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := scimRequest(t, svc, http.MethodGet, "/scim/v2/"+testWorkspaceID+"/Users", tt.token, nil)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

func TestSCIMUserLifecycle(t *testing.T) {
	svc, st, token := newSCIMTest(t)

	// Create (Okta-shaped payload).
	w := scimRequest(
		t,
		svc,
		http.MethodPost,
		"/scim/v2/"+testWorkspaceID+"/Users",
		token,
		oktaCreateUser(),
	)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	// The account was provisioned: member of the workspace, email verified,
	// externalId linked as a scim credential.
	if !st.members[testWorkspaceID][created.ID] {
		t.Fatal("user not added to workspace")
	}
	if u := st.users[created.ID]; u.Email != "john.doe@example.com" || u.Name != "John Doe" || !u.EmailVerified {
		t.Fatalf("unexpected user: %+v", u)
	}
	cred, ok := st.creds["scim|"+testWorkspaceID+"|okta-user-42"]
	if !ok || cred.UserID != created.ID {
		t.Fatal("externalId not linked")
	}

	// Get by id returns the resource with externalId.
	w = scimRequest(t, svc, http.MethodGet, "/scim/v2/"+testWorkspaceID+"/Users/"+created.ID, token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d", w.Code)
	}
	var got struct {
		ExternalID string `json:"externalId"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ExternalID != "okta-user-42" {
		t.Fatalf("externalId = %q", got.ExternalID)
	}

	// Filter matches the IdP's sync lookup.
	w = scimRequest(t, svc, http.MethodGet,
		"/scim/v2/"+testWorkspaceID+"/Users?filter=userName%20eq%20%22john.doe@example.com%22",
		token, nil)
	var list struct {
		TotalResults int `json:"totalResults"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.TotalResults != 1 {
		t.Fatalf("filtered total = %d, want 1", list.TotalResults)
	}

	// Deactivate via PATCH (Azure pushes active:false on disable).
	w = scimRequest(t, svc, http.MethodPatch, "/scim/v2/"+testWorkspaceID+"/Users/"+created.ID, token, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{
			"op": "replace", "path": "active", "value": false,
		}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("patch status = %d: %s", w.Code, w.Body.String())
	}
	if st.users[created.ID].Active {
		t.Fatal("user still active after patch")
	}

	// Delete while another workspace still lists the account: membership
	// and credential go, the global account survives.
	st.addMember(otherWorkspaceID, created.ID)
	w = scimRequest(t, svc, http.MethodDelete, "/scim/v2/"+testWorkspaceID+"/Users/"+created.ID, token, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d: %s", w.Code, w.Body.String())
	}
	if st.members[testWorkspaceID][created.ID] {
		t.Fatal("membership survived delete")
	}
	if st.users[created.ID] == nil {
		t.Fatal("global account deleted while another workspace still lists it")
	}
	if _, ok := st.creds["scim|"+testWorkspaceID+"|okta-user-42"]; ok {
		t.Fatal("scim credential survived delete")
	}
	if !st.revocations[created.ID] {
		t.Fatal("deprovision did not revoke the user's certificates")
	}
	if st.grantDrops[created.ID] == 0 {
		t.Fatal("deprovision kept the user's workspace grants")
	}

	// Re-provision resolves back to the same account.
	w = scimRequest(
		t,
		svc,
		http.MethodPost,
		"/scim/v2/"+testWorkspaceID+"/Users",
		token,
		oktaCreateUser(),
	)
	if w.Code != http.StatusCreated {
		t.Fatalf("recreate status = %d", w.Code)
	}
	var recreated struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &recreated); err != nil {
		t.Fatal(err)
	}
	if recreated.ID != created.ID {
		t.Fatalf("recreate made a second account: %s != %s", recreated.ID, created.ID)
	}

	// An account that owns a workspace is never deleted by SCIM: the
	// created_by cascade would take the workspace with it.
	st.ownedWorkspaces[created.ID] = 1
	w = scimRequest(t, svc, http.MethodDelete, "/scim/v2/"+testWorkspaceID+"/Users/"+created.ID, token, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("owner delete status = %d: %s", w.Code, w.Body.String())
	}
	owner := st.users[created.ID]
	if owner == nil {
		t.Fatal("workspace owner account deleted by SCIM")
	}
	if owner.Active {
		t.Fatal("shadow-IT owner account left active")
	}
	st.ownedWorkspaces[created.ID] = 0

	// Delete with no other memberships left: the account goes entirely.
	delete(st.members[otherWorkspaceID], created.ID)
	w = scimRequest(
		t,
		svc,
		http.MethodPost,
		"/scim/v2/"+testWorkspaceID+"/Users",
		token,
		oktaCreateUser(),
	)
	if w.Code != http.StatusCreated {
		t.Fatalf("re-join status = %d", w.Code)
	}
	w = scimRequest(t, svc, http.MethodDelete, "/scim/v2/"+testWorkspaceID+"/Users/"+created.ID, token, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("second delete status = %d", w.Code)
	}
	if st.users[created.ID] != nil {
		t.Fatal("orphan account survived final delete")
	}
	if st.grantDrops[created.ID] < 2 {
		t.Fatal("final delete did not drop the user's remaining grants")
	}
}

func TestSCIMTenantIsolation(t *testing.T) {
	svc, st, _ := newSCIMTest(t)
	u := st.seedMember(otherWorkspaceID, "jane@example.com")
	_, tokenA, err := svc.IssueSCIMToken(context.Background(), testWorkspaceID, "a")
	if err != nil {
		t.Fatal(err)
	}
	_, tokenB, err := svc.IssueSCIMToken(context.Background(), otherWorkspaceID, "b")
	if err != nil {
		t.Fatal(err)
	}

	// Workspace A's token cannot see workspace B's member.
	w := scimRequest(t, svc, http.MethodGet, "/scim/v2/"+testWorkspaceID+"/Users/"+u.ID, tokenA, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant read status = %d, want 404", w.Code)
	}
	// Workspace B's token sees its own member.
	w = scimRequest(t, svc, http.MethodGet, "/scim/v2/"+otherWorkspaceID+"/Users/"+u.ID, tokenB, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("own-tenant read status = %d", w.Code)
	}
}

func TestSCIMGroups(t *testing.T) {
	svc, st, token := newSCIMTest(t)
	member := st.seedMember(testWorkspaceID, "member@example.com")
	outsider := st.seedMember("", "outsider@example.com")

	// Create with members (Okta pushes displayName + members on create).
	w := scimRequest(t, svc, http.MethodPost, "/scim/v2/"+testWorkspaceID+"/Groups", token, map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Engineering",
		"members": []any{
			map[string]any{"value": member.ID, "display": "member@example.com"},
		},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !st.teamMems[created.ID][member.ID] {
		t.Fatal("member not added")
	}

	// A user who exists globally but was pushed before their user sync
	// joins the workspace with the team (IdP sync-ordering race).
	w = scimRequest(t, svc, http.MethodPatch, "/scim/v2/"+testWorkspaceID+"/Groups/"+created.ID, token, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{
			"op": "add", "path": "members",
			"value": []any{map[string]any{"value": outsider.ID}},
		}},
	})
	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("add patch status = %d: %s", w.Code, w.Body.String())
	}
	if !st.teamMems[created.ID][outsider.ID] || !st.members[testWorkspaceID][outsider.ID] {
		t.Fatal("existing user not joined via group push")
	}

	// A truly unknown id must not widen anything.
	w = scimRequest(t, svc, http.MethodPatch, "/scim/v2/"+testWorkspaceID+"/Groups/"+created.ID, token, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{
			"op": "add", "path": "members",
			"value": []any{map[string]any{"value": "00000000-0000-0000-0000-00000000dead"}},
		}},
	})
	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("unknown-id patch status = %d: %s", w.Code, w.Body.String())
	}
	if st.teamMems[created.ID]["00000000-0000-0000-0000-00000000dead"] {
		t.Fatal("unknown id gained team access")
	}

	// Okta's member-removal PATCH: members[value eq "<id>"].
	w = scimRequest(t, svc, http.MethodPatch, "/scim/v2/"+testWorkspaceID+"/Groups/"+created.ID, token, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{
			"op":   "remove",
			"path": `members[value eq "` + member.ID + `"]`,
		}},
	})
	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("remove patch status = %d: %s", w.Code, w.Body.String())
	}
	if st.teamMems[created.ID][member.ID] {
		t.Fatal("member survived remove patch")
	}

	// Delete the group.
	w = scimRequest(t, svc, http.MethodDelete, "/scim/v2/"+testWorkspaceID+"/Groups/"+created.ID, token, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", w.Code)
	}
	if _, ok := st.teams[created.ID]; ok {
		t.Fatal("team survived delete")
	}
}

func TestSCIMReactivateOnReprovision(t *testing.T) {
	svc, st, token := newSCIMTest(t)

	// Provision, then deactivate via PATCH.
	w := scimRequest(
		t,
		svc,
		http.MethodPost,
		"/scim/v2/"+testWorkspaceID+"/Users",
		token,
		oktaCreateUser(),
	)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d", w.Code)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	w = scimRequest(t, svc, http.MethodPatch, "/scim/v2/"+testWorkspaceID+"/Users/"+created.ID, token, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{
			"op": "replace", "path": "active", "value": false,
		}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("patch status = %d", w.Code)
	}
	if st.users[created.ID].Active {
		t.Fatal("user still active after deactivate")
	}

	// The IdP pushes the user again: the account comes back.
	w = scimRequest(
		t,
		svc,
		http.MethodPost,
		"/scim/v2/"+testWorkspaceID+"/Users",
		token,
		oktaCreateUser(),
	)
	if w.Code != http.StatusCreated {
		t.Fatalf("reprovision status = %d", w.Code)
	}
	if !st.users[created.ID].Active {
		t.Fatal("reprovisioned user still deactivated")
	}

	// And the shadow-IT cycle: delete (deactivated, owns workspaces), then
	// a re-assignment reactivates.
	st.ownedWorkspaces[created.ID] = 1
	w = scimRequest(t, svc, http.MethodDelete, "/scim/v2/"+testWorkspaceID+"/Users/"+created.ID, token, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", w.Code)
	}
	if st.users[created.ID].Active {
		t.Fatal("shadow-IT orphan left active")
	}
	w = scimRequest(
		t,
		svc,
		http.MethodPost,
		"/scim/v2/"+testWorkspaceID+"/Users",
		token,
		oktaCreateUser(),
	)
	if w.Code != http.StatusCreated {
		t.Fatalf("reprovision after deactivate status = %d", w.Code)
	}
	if !st.users[created.ID].Active {
		t.Fatal("reassignment did not reactivate the account")
	}
}

func (f *scimStore) seedSession(userID string) string {
	hash := "sess-" + userID + "-" + strconv.Itoa(len(f.sessions))
	f.sessions[hash] = userID
	return hash
}

func TestSCIMProvisionedUsersAreSSOOnly(t *testing.T) {
	svc, st, token := newSCIMTest(t)

	w := scimRequest(t, svc, http.MethodPost, "/scim/v2/"+testWorkspaceID+"/Users", token, oktaCreateUser())
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d", w.Code)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !st.users[created.ID].DisablePasswordReset {
		t.Fatal("SCIM-provisioned user can self-serve a password reset")
	}
}

func TestSCIMExternalIdMigration(t *testing.T) {
	svc, st, token := newSCIMTest(t)

	w := scimRequest(t, svc, http.MethodPost, "/scim/v2/"+testWorkspaceID+"/Users", token, oktaCreateUser())
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.creds["scim|"+testWorkspaceID+"|okta-user-42"]; !ok {
		t.Fatal("initial externalId not linked")
	}

	// The IdP migrates identities: a Replace with a new externalId must
	// leave exactly one scim credential on the account.
	attrs := oktaCreateUser()
	attrs["externalId"] = "okta-user-43"
	w = scimRequest(t, svc, http.MethodPut, "/scim/v2/"+testWorkspaceID+"/Users/"+created.ID, token, attrs)
	if w.Code != http.StatusOK {
		t.Fatalf("replace status = %d: %s", w.Code, w.Body.String())
	}
	if _, ok := st.creds["scim|"+testWorkspaceID+"|okta-user-42"]; ok {
		t.Fatal("stale externalId survived the migration")
	}
	if cred, ok := st.creds["scim|"+testWorkspaceID+"|okta-user-43"]; !ok || cred.UserID != created.ID {
		t.Fatal("new externalId not linked")
	}
}

func TestSCIMDeactivateRevokesSessions(t *testing.T) {
	svc, st, token := newSCIMTest(t)

	w := scimRequest(t, svc, http.MethodPost, "/scim/v2/"+testWorkspaceID+"/Users", token, oktaCreateUser())
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	hash := st.seedSession(created.ID)

	w = scimRequest(t, svc, http.MethodPatch, "/scim/v2/"+testWorkspaceID+"/Users/"+created.ID, token, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{
			"op": "replace", "path": "active", "value": false,
		}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("patch status = %d: %s", w.Code, w.Body.String())
	}
	if _, ok := st.sessions[hash]; ok {
		t.Fatal("session survived deactivation")
	}
}

func TestSCIMShadowITDeactivateRevokesSessions(t *testing.T) {
	svc, st, token := newSCIMTest(t)

	w := scimRequest(t, svc, http.MethodPost, "/scim/v2/"+testWorkspaceID+"/Users", token, oktaCreateUser())
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	hash := st.seedSession(created.ID)
	st.ownedWorkspaces[created.ID] = 1

	w = scimRequest(t, svc, http.MethodDelete, "/scim/v2/"+testWorkspaceID+"/Users/"+created.ID, token, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", w.Code)
	}
	if st.users[created.ID] == nil || st.users[created.ID].Active {
		t.Fatal("shadow-IT orphan not deactivated")
	}
	if _, ok := st.sessions[hash]; ok {
		t.Fatal("session survived shadow-IT deactivation")
	}
}

func TestSCIMGroupDisplayNameUnique(t *testing.T) {
	svc, st, token := newSCIMTest(t)

	group := func() map[string]any {
		return map[string]any{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
			"displayName": "Engineering",
		}
	}
	w := scimRequest(t, svc, http.MethodPost, "/scim/v2/"+testWorkspaceID+"/Groups", token, group())
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", w.Code, w.Body.String())
	}
	w = scimRequest(t, svc, http.MethodPost, "/scim/v2/"+testWorkspaceID+"/Groups", token, group())
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate create status = %d, want 409: %s", w.Code, w.Body.String())
	}

	// Renaming an existing group onto a taken name is also a 409.
	var first struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	st.seedMember(testWorkspaceID, "x@example.com")
	w = scimRequest(t, svc, http.MethodPost, "/scim/v2/"+testWorkspaceID+"/Groups", token, map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Platform",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("second group create status = %d: %s", w.Code, w.Body.String())
	}
	var second struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	w = scimRequest(t, svc, http.MethodPatch, "/scim/v2/"+testWorkspaceID+"/Groups/"+second.ID, token, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{
			"op": "replace", "path": "displayName", "value": "Engineering",
		}},
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("rename onto taken name status = %d, want 409", w.Code)
	}
}

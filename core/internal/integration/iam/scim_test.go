//go:build integration

package iam_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

type scimClient struct {
	t     *testing.T
	svc   *iam.Service
	ws    actor.Workspace
	token string
}

func (e *testEnv) scim(t *testing.T, o org) *scimClient {
	t.Helper()
	_, token, err := e.svc.IssueToken(as(t.Context(), o.ws, o.owner), iam.TokenParams{
		Kind: actor.KindSCIM, Method: iam.MethodSCIM, Label: "okta",
	})
	require.NoError(t, err)
	return &scimClient{t: t, svc: e.svc, ws: o.ws, token: token}
}

// do sends one SCIM request and decodes a JSON reply into out when given.
func (c *scimClient) do(method, path string, body any, out any) int {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			c.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, "/scim/v2"+path, &buf)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/scim+json")
	rec := httptest.NewRecorder()
	c.svc.SCIMHandler().ServeHTTP(rec, req.WithContext(anon(req.Context(), c.ws)))
	if out != nil && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			c.t.Fatalf("decode %s %s: %v: %s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code
}

func scimUser(email, externalID string) map[string]any {
	return map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   email,
		"externalId": externalID,
		"name":       map[string]any{"givenName": "John", "familyName": "Doe"},
		"active":     true,
	}
}

func patchOp(op, path string, value any) map[string]any {
	return patchOps(map[string]any{"op": op, "path": path, "value": value})
}

func patchOps(ops ...map[string]any) map[string]any {
	return map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": ops,
	}
}

type scimResource struct {
	ID          string `json:"id"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Active      bool   `json:"active"`
	ExternalID  string `json:"externalId"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

type scimList struct {
	TotalResults int            `json:"totalResults"`
	Resources    []scimResource `json:"Resources"`
}

func TestSCIMAuth(t *testing.T) {
	e := newTestEnv(t)
	a, b := e.org(t), e.org(t)
	ca, cb := e.scim(t, a), e.scim(t, b)

	cb.token = ca.token // a's token presented on b's host
	assert.Equal(t, http.StatusUnauthorized, cb.do(http.MethodGet, "/Users", nil, nil), "foreign token")
	ca.token = "nk_scim_bogus"
	assert.Equal(t, http.StatusUnauthorized, ca.do(http.MethodGet, "/Users", nil, nil), "bogus token")
}

func TestSCIMUserLifecycle(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	c := e.scim(t, o)
	email := "john.doe@" + testDomain()

	var created scimResource
	require.Equal(t, http.StatusCreated, c.do(http.MethodPost, "/Users", scimUser(email, "okta-42"), &created))
	assert.Equal(t, "okta-42", created.ExternalID)
	assert.Equal(t, "John Doe", created.DisplayName)
	u := e.userByEmail(t, o.ws, email)
	require.NotNil(t, u)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, u.Role)
	assert.Equal(t, new("okta-42"), u.ScimExternalID)

	var list scimList
	c.do(http.MethodGet, "/Users?filter="+url.QueryEscape(`userName eq "`+email+`"`), nil, &list)
	require.Equal(t, 1, list.TotalResults)
	assert.Equal(t, u.ID, list.Resources[0].ID)

	e.session(t, o.ws, u, actor.KindUser)
	var patched scimResource
	require.Equal(
		t,
		http.StatusOK,
		c.do(http.MethodPatch, "/Users/"+u.ID, patchOp("replace", "active", false), &patched),
	)
	assert.False(t, patched.Active)
	assert.Zero(t, e.sessions(t, o.ws, u.ID), "deactivation kept the sessions alive")

	// Deprovisioning keeps the account for a later re-assignment.
	require.Equal(t, http.StatusNoContent, c.do(http.MethodDelete, "/Users/"+u.ID, nil, nil))
	after := e.userByEmail(t, o.ws, email)
	require.NotNil(t, after, "deprovisioning deleted the account")
	assert.False(t, after.Active)
	assert.Nil(t, after.ScimExternalID, "the IdP link survived deprovisioning")
}

// Authentik sends the username as userName and the address in emails.
func TestSCIMUserEmailComesFromEmails(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	c := e.scim(t, o)
	email := "alice@" + testDomain()
	body := scimUser("alice", "ak-1")
	body["emails"] = []any{
		map[string]any{"value": "other@" + testDomain(), "type": "other"},
		map[string]any{"value": email, "type": "other", "primary": true},
	}

	var created scimResource
	require.Equal(t, http.StatusCreated, c.do(http.MethodPost, "/Users", body, &created))
	assert.Equal(t, email, created.UserName)
	require.NotNil(t, e.userByEmail(t, o.ws, email))

	var replaced scimResource
	require.Equal(
		t,
		http.StatusOK,
		c.do(http.MethodPut, "/Users/"+created.ID, body, &replaced),
		"username-only userName",
	)

	delete(body, "emails")
	assert.Equal(t, http.StatusBadRequest, c.do(http.MethodPost, "/Users", body, nil), "no address anywhere")
}

// The IdP link is no way to sign in. The account cannot list or drop it, and its address stays the IdP's.
func TestSCIMLinkIsNoCredential(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	c := e.scim(t, o)
	email := "jane.doe@" + testDomain()
	require.Equal(t, http.StatusCreated, c.do(http.MethodPost, "/Users", scimUser(email, "okta-7"), nil))
	u := e.userByEmail(t, o.ws, email)
	require.NotNil(t, u)
	ctx := as(t.Context(), o.ws, u)
	// With a second way in, the last one is not what stops a removal.
	e.putCredential(t, o.ws, db.UpsertCredentialParams{
		ID: "pk-" + u.ID, UserID: u.ID, Type: string(iam.MethodPasskey), Data: []byte{},
	})

	creds, err := e.svc.ListCredentials(ctx)
	require.NoError(t, err)
	assert.Len(t, creds, 1, "the link is listed as a sign-in method")
	// The id the link had while it was a row in credentials.
	require.ErrorIs(t, e.svc.DeleteCredential(ctx, "scim:"+o.ws.ID+":okta-7"), iam.ErrNotFound)

	_, _, err = e.svc.RequestEmailChange(ctx, u, "other@"+testDomain())
	require.ErrorIs(t, err, iam.ErrManagedAccount)

	// A second account cannot take the same id.
	other := scimUser("john.roe@"+testDomain(), "okta-7")
	assert.Equal(t, http.StatusBadRequest, c.do(http.MethodPost, "/Users", other, nil))
}

// The IdP cannot switch the owner off. Okta and Entra deactivate with PATCH, PUT and POST carry the same flag.
func TestSCIMKeepsTheOwnerActive(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	c := e.scim(t, o)
	e.session(t, o.ws, o.owner, actor.KindUser)

	off := scimUser(o.owner.Email, "")
	off["active"] = false
	for name, req := range map[string]struct {
		method, path string
		body         any
	}{
		"patch":  {http.MethodPatch, "/Users/" + o.owner.ID, patchOp("replace", "active", false)},
		"put":    {http.MethodPut, "/Users/" + o.owner.ID, off},
		"post":   {http.MethodPost, "/Users", off},
		"delete": {http.MethodDelete, "/Users/" + o.owner.ID, nil},
	} {
		assert.Equal(t, http.StatusConflict, c.do(req.method, req.path, req.body, nil), name)
		assert.True(t, e.userByEmail(t, o.ws, o.owner.Email).Active, "%s switched the owner off", name)
	}
	assert.Equal(t, 1, e.sessions(t, o.ws, o.owner.ID), "the owner was signed out")

	on := scimUser(o.owner.Email, "okta-1")
	assert.Equal(t, http.StatusOK, c.do(http.MethodPut, "/Users/"+o.owner.ID, on, nil), "an active owner is fine")
}

func TestSCIMGroupsStayInWorkspace(t *testing.T) {
	e := newTestEnv(t)
	a, b := e.org(t), e.org(t)
	ca, cb := e.scim(t, a), e.scim(t, b)
	var member scimResource
	ca.do(http.MethodPost, "/Users", scimUser("dev@"+testDomain(), ""), &member)
	outsider := e.user(t, b.ws, "dev@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)

	var group scimResource
	code := ca.do(http.MethodPost, "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "engineering",
		"members":     []any{map[string]any{"value": member.ID}, map[string]any{"value": outsider.ID}},
	}, &group)
	require.Equal(t, http.StatusCreated, code)
	require.Len(t, group.Members, 1, "members = %+v, want only the workspace's user", group.Members)
	assert.Equal(t, member.ID, group.Members[0].Value)

	assert.Equal(t, http.StatusNotFound, cb.do(http.MethodGet, "/Groups/"+group.ID, nil, nil), "foreign group read")
	assert.Equal(
		t,
		http.StatusNotFound,
		cb.do(http.MethodDelete, "/Groups/"+group.ID, nil, nil),
		"foreign group delete",
	)
	assert.Equal(
		t,
		http.StatusOK,
		ca.do(http.MethodGet, "/Groups/"+group.ID, nil, nil),
		"own group after foreign delete",
	)

	assert.Equal(t, http.StatusNotFound, cb.do(http.MethodGet, "/Users/"+member.ID, nil, nil), "foreign user read")
}

// The IdP owns the address of its accounts. Entra sends a changed one and the deactivation in one request.
func TestSCIMRenamesTheLogin(t *testing.T) {
	mail := newMailbox()
	e := newTestEnvWith(t, mail.deps())
	o := e.org(t)
	c := e.scim(t, o)
	first, second, third := "first@"+testDomain(), "second@"+testDomain(), "third@"+testDomain()
	work := func(email string) map[string]any {
		return map[string]any{"op": "Replace", "path": `emails[type eq "work"].value`, "value": email}
	}
	var created scimResource
	require.Equal(t, http.StatusCreated, c.do(http.MethodPost, "/Users", scimUser(first, "entra-1"), &created))
	path := "/Users/" + created.ID
	ctx := anon(t.Context(), o.ws)
	e.svc.RequestMagicLink(ctx, first)
	oldLink := linkToken(t, mail.link(t))

	// A second address, a removal and a userName that may be no address at all are not the login.
	home := []any{map[string]any{"value": "home@" + testDomain(), "type": "home"}}
	for what, body := range map[string]map[string]any{
		"another type by filter": patchOp("replace", `emails[type eq "home"].value`, "home@"+testDomain()),
		"a negated filter":       patchOp("replace", `emails[type ne "work"].value`, "ne@"+testDomain()),
		"an added second entry":  patchOp("add", "emails", home),
		"a removed entry":        patchOp("remove", "emails", home),
		"the userName":           patchOp("replace", "userName", "upn@"+testDomain()),
	} {
		c.do(http.MethodPatch, path, body, nil)
		require.NotNil(t, e.userByEmail(t, o.ws, first), "%s renamed the login", what)
	}

	var patched scimResource
	off := map[string]any{"op": "Replace", "path": "active", "value": false}
	require.Equal(t, http.StatusOK, c.do(http.MethodPatch, path, patchOps(work(second), off), &patched))
	assert.Equal(t, second, patched.UserName)
	assert.False(t, patched.Active, "the deactivation did not land")
	_, _, err := e.svc.ConsumeMagicLink(ctx, oldLink)
	require.ErrorIs(t, err, iam.ErrInvalidToken, "a link mailed to the old address still signed in")

	var replaced scimResource
	require.Equal(t, http.StatusOK, c.do(http.MethodPut, path, scimUser(third, "entra-1"), &replaced))
	assert.Equal(t, third, replaced.UserName)
	assert.True(t, replaced.Active)

	taken := e.user(t, o.ws, "taken@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	assert.Equal(
		t,
		http.StatusConflict,
		c.do(http.MethodPatch, path, patchOps(work(taken.Email)), nil),
		"a taken address",
	)
	require.NotNil(t, e.userByEmail(t, o.ws, third), "a refused rename changed the address")

	// An account the IdP never linked is not its to rename, a sign-in link would hand it over.
	admin := e.user(t, o.ws, "admin@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	c.do(http.MethodPatch, "/Users/"+admin.ID, patchOps(work("evil@"+testDomain())), nil)
	assert.NotNil(t, e.userByEmail(t, o.ws, admin.Email), "the IdP renamed an account it never linked")

	// Whoever could rename the owner would get the owner's sign-in links, linked or not.
	owner := "/Users/" + o.owner.ID
	require.Equal(t, http.StatusOK, c.do(http.MethodPut, owner, scimUser(o.owner.Email, "entra-0"), nil))
	assert.Equal(t, http.StatusConflict, c.do(http.MethodPatch, owner, patchOps(work("ceo@"+testDomain())), nil))
	assert.NotNil(t, e.userByEmail(t, o.ws, o.owner.Email), "the IdP renamed the owner")
}

func TestSCIMPatchNameParts(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	c := e.scim(t, o)
	var created scimResource
	require.Equal(
		t,
		http.StatusCreated,
		c.do(http.MethodPost, "/Users", scimUser("john@"+testDomain(), "entra-2"), &created),
	)

	var patched scimResource
	code := c.do(http.MethodPatch, "/Users/"+created.ID, patchOps(
		map[string]any{"op": "Replace", "path": "name.givenName", "value": "Jane"},
		map[string]any{"op": "Replace", "path": "name.familyName", "value": "Roe"},
	), &patched)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "Jane Roe", patched.DisplayName)

	c.do(http.MethodPatch, "/Users/"+created.ID, patchOp("replace", "name.familyName", "Smith"), nil)
	var got scimResource
	require.Equal(t, http.StatusOK, c.do(http.MethodGet, "/Users/"+created.ID, nil, &got))
	assert.Equal(t, "Jane Roe", got.DisplayName, "half a name replaced the whole one")
}

func TestSCIMGroupPatchMembers(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	c := e.scim(t, o)
	var alice, bob scimResource
	c.do(http.MethodPost, "/Users", scimUser("alice@"+testDomain(), ""), &alice)
	c.do(http.MethodPost, "/Users", scimUser("bob@"+testDomain(), ""), &bob)
	ref := func(u scimResource) []any { return []any{map[string]any{"value": u.ID}} }

	var group scimResource
	require.Equal(t, http.StatusCreated, c.do(http.MethodPost, "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "engineering",
		"members":     append(ref(alice), ref(bob)...),
	}, &group))
	require.Len(t, group.Members, 2)

	members := func(body map[string]any) []string {
		var got scimResource
		require.Equal(t, http.StatusOK, c.do(http.MethodPatch, "/Groups/"+group.ID, body, &got))
		ids := []string{}
		for _, m := range got.Members {
			ids = append(ids, m.Value)
		}
		return ids
	}
	assert.Equal(t, []string{alice.ID}, members(patchOp("replace", "members", ref(alice))), "replace kept bob")
	assert.ElementsMatch(t, []string{alice.ID, bob.ID}, members(patchOp("add", "members", ref(bob))))
	assert.Equal(
		t,
		[]string{alice.ID},
		members(patchOp("remove", `members[value eq "`+bob.ID+`"]`, nil)),
		"remove by filter",
	)
	assert.ElementsMatch(t, []string{alice.ID, bob.ID}, members(patchOp("add", "members", ref(bob))))
	bare := patchOps(map[string]any{"op": "remove", "path": "members"})
	assert.Empty(t, members(bare), "a bare remove left members")
}

// Switching an account back on takes a seat like a join does.
func TestSCIMReactivationNeedsASeat(t *testing.T) {
	e := newTestEnvWith(t, iam.Deps{CanJoin: func(_ context.Context, _ string, used int64) error {
		if used >= 2 {
			return errors.New("plan allows 2 seats")
		}
		return nil
	}})
	o := e.org(t)
	c := e.scim(t, o)
	one, two := "one@"+testDomain(), "two@"+testDomain()
	var first scimResource
	require.Equal(t, http.StatusCreated, c.do(http.MethodPost, "/Users", scimUser(one, ""), &first))
	off, on := patchOp("replace", "active", false), patchOp("replace", "active", true)
	require.Equal(t, http.StatusOK, c.do(http.MethodPatch, "/Users/"+first.ID, off, nil))
	require.Equal(t, http.StatusCreated, c.do(http.MethodPost, "/Users", scimUser(two, ""), nil))

	assert.Equal(t, http.StatusForbidden, c.do(http.MethodPatch, "/Users/"+first.ID, on, nil), "patch")
	assert.Equal(t, http.StatusForbidden, c.do(http.MethodPost, "/Users", scimUser(one, ""), nil), "post")
	assert.False(t, e.userByEmail(t, o.ws, one).Active, "reactivated past the seat cap")

	// An account that is on stays on, IdPs resend active=true all the time.
	second := e.userByEmail(t, o.ws, two)
	require.NotNil(t, second)
	assert.Equal(t, http.StatusOK, c.do(http.MethodPatch, "/Users/"+second.ID, on, nil))
}

func TestSCIMAdvertisesWhatItSupports(t *testing.T) {
	e := newTestEnv(t)
	c := e.scim(t, e.org(t))
	var cfg struct {
		Patch  struct{ Supported bool } `json:"patch"`
		Filter struct {
			Supported  bool
			MaxResults int
		} `json:"filter"`
	}
	require.Equal(t, http.StatusOK, c.do(http.MethodGet, "/ServiceProviderConfig", nil, &cfg))
	assert.True(t, cfg.Patch.Supported, "patch")
	assert.True(t, cfg.Filter.Supported, "filter")
	assert.Positive(t, cfg.Filter.MaxResults, "filter.maxResults")
}

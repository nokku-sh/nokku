//go:build integration

package iam_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/iam"
)

type scimClient struct {
	t     *testing.T
	svc   *iam.Service
	ws    actor.Workspace
	token string
}

func (e *testEnv) scim(t *testing.T, o org) *scimClient {
	t.Helper()
	_, token, err := e.svc.IssueSCIMToken(as(t.Context(), o.ws, o.owner), "okta")
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
	return map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": op, "path": path, "value": value}},
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
	ca.token = "nokku_bogus"
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
	assert.Nil(t, e.credential(t, o.ws, iam.MethodSCIM, "", "okta-42"), "the IdP link survived deprovisioning")
}

// The IdP cannot switch the workspace owner off. Okta and Entra deactivate
// with PATCH, PUT and POST carry the same flag.
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

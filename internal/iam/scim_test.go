package iam

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type scimClient struct {
	t     *testing.T
	svc   *Service
	ws    string
	token string
}

func (e *testEnv) scim(t *testing.T, o org) *scimClient {
	t.Helper()
	ctx := as(t.Context(), o.owner.ID)
	ctx = AnnotateTenant(ctx, o.ws)
	ctx = WithMember(ctx, o.ws)
	_, token, err := e.svc.IssueSCIMToken(ctx, o.ws, "okta")
	if err != nil {
		t.Fatal(err)
	}
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
	req := httptest.NewRequest(method, "/scim/v2/"+c.ws+path, &buf)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/scim+json")
	rec := httptest.NewRecorder()
	c.svc.SCIMHandler().ServeHTTP(rec, req)
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

	cb.token = ca.token // a's token presented at b's endpoint
	if code := cb.do(http.MethodGet, "/Users", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("foreign token: code %d, want 401", code)
	}
	ca.token = "nokku_bogus"
	if code := ca.do(http.MethodGet, "/Users", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("bogus token: code %d, want 401", code)
	}
}

func TestSCIMUserLifecycle(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	c := e.scim(t, o)
	email := "john.doe@" + o.domain

	var created scimResource
	if code := c.do(http.MethodPost, "/Users", scimUser(email, "okta-42"), &created); code != http.StatusCreated {
		t.Fatalf("create: code %d", code)
	}
	if created.ExternalID != "okta-42" || created.DisplayName != "John Doe" {
		t.Errorf("created = %+v", created)
	}
	u := e.userByEmail(t, email)
	if u == nil || !u.EmailVerified || !u.DisablePasswordReset || !e.isMember(t, o.ws, u.ID) {
		t.Fatalf("provisioned account = %+v", u)
	}

	var list scimList
	c.do(http.MethodGet, "/Users?filter="+url.QueryEscape(`userName eq "`+email+`"`), nil, &list)
	if list.TotalResults != 1 || list.Resources[0].ID != u.ID {
		t.Errorf("userName filter = %+v", list)
	}

	if _, _, err := e.svc.IssueSession(
		t.Context(),
		SessionParams{SubjectID: u.ID, Kind: KindUser, Method: MethodSAML},
	); err != nil {
		t.Fatal(err)
	}
	var patched scimResource
	if code := c.do(
		http.MethodPatch,
		"/Users/"+u.ID,
		patchOp("replace", "active", false),
		&patched,
	); code != http.StatusOK {
		t.Fatalf("deactivate: code %d", code)
	}
	if patched.Active || e.sessions(t, u.ID) != 0 {
		t.Error("deactivation kept the account active or its sessions alive")
	}

	if code := c.do(http.MethodDelete, "/Users/"+u.ID, nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete: code %d", code)
	}
	if e.userByEmail(t, email) != nil {
		t.Error("an account in no other workspace survived deprovisioning")
	}
}

// A connector can neither create, see, nor change accounts outside its
// workspace's verified domains, even ones that are members.
func TestSCIMOnlyManagesVerifiedDomains(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	c := e.scim(t, o)
	victim := e.user(t, "ceo@"+testDomain(), true)
	guest := e.user(t, "contractor@"+testDomain(), true)
	e.member(t, o.ws, guest.ID)

	if code := c.do(http.MethodPost, "/Users", scimUser(victim.Email, ""), nil); code != http.StatusBadRequest {
		t.Errorf("foreign create: code %d, want 400", code)
	}
	if e.isMember(t, o.ws, victim.ID) {
		t.Error("a foreign account was pulled into the workspace")
	}
	if code := c.do(
		http.MethodPost,
		"/Users",
		scimUser("fresh@"+testDomain(), ""),
		nil,
	); code != http.StatusBadRequest {
		t.Errorf("foreign signup: code %d, want 400", code)
	}

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/Users/" + guest.ID},
		{http.MethodPatch, "/Users/" + guest.ID},
		{http.MethodDelete, "/Users/" + guest.ID},
	} {
		if code := c.do(req.method, req.path, patchOp("replace", "active", false), nil); code != http.StatusNotFound {
			t.Errorf("%s guest: code %d, want 404", req.method, code)
		}
	}
	var list scimList
	c.do(http.MethodGet, "/Users", nil, &list)
	for _, r := range list.Resources {
		if r.ID == guest.ID {
			t.Error("the guest is listed")
		}
	}
	if g := e.userByEmail(t, guest.Email); !g.Active || !e.isMember(t, o.ws, guest.ID) {
		t.Error("the guest account was changed")
	}
}

// An account still used elsewhere is deactivated, not deleted. The owner
// cannot be deprovisioned at all.
func TestSCIMDeprovision(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	c := e.scim(t, o)
	var created scimResource
	c.do(http.MethodPost, "/Users", scimUser("jane@"+o.domain, ""), &created)
	other := e.workspace(t, e.user(t, "x@"+testDomain(), true).ID)
	e.member(t, other, created.ID)

	if code := c.do(http.MethodDelete, "/Users/"+created.ID, nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete: code %d", code)
	}
	u := e.userByEmail(t, "jane@"+o.domain)
	if u == nil || u.Active || e.isMember(t, o.ws, u.ID) || !e.isMember(t, other, u.ID) {
		t.Errorf("after deprovision: %+v", u)
	}

	if code := c.do(http.MethodDelete, "/Users/"+o.owner.ID, nil, nil); code != http.StatusConflict {
		t.Errorf("owner delete: code %d, want 409", code)
	}
}

func TestSCIMGroupsStayInWorkspace(t *testing.T) {
	e := newTestEnv(t)
	a, b := e.org(t), e.org(t)
	ca, cb := e.scim(t, a), e.scim(t, b)
	var member scimResource
	ca.do(http.MethodPost, "/Users", scimUser("dev@"+a.domain, ""), &member)
	outsider := e.user(t, "dev@"+b.domain, true)

	var group scimResource
	code := ca.do(http.MethodPost, "/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "engineering",
		"members":     []any{map[string]any{"value": member.ID}, map[string]any{"value": outsider.ID}},
	}, &group)
	if code != http.StatusCreated {
		t.Fatalf("create group: code %d", code)
	}
	if len(group.Members) != 1 || group.Members[0].Value != member.ID {
		t.Errorf("members = %+v, want only the workspace member", group.Members)
	}
	if e.isMember(t, a.ws, outsider.ID) {
		t.Error("a group pulled an outsider into the workspace")
	}

	if code := cb.do(http.MethodGet, "/Groups/"+group.ID, nil, nil); code != http.StatusNotFound {
		t.Errorf("foreign group read: code %d, want 404", code)
	}
	if code := cb.do(http.MethodDelete, "/Groups/"+group.ID, nil, nil); code != http.StatusNotFound {
		t.Errorf("foreign group delete: code %d, want 404", code)
	}
	if code := ca.do(http.MethodGet, "/Groups/"+group.ID, nil, nil); code != http.StatusOK {
		t.Errorf("own group read after foreign delete: code %d", code)
	}
}

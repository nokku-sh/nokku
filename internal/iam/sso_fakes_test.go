package iam

// In-memory test doubles for the SSO flows: the IdPs are real (mockoidc,
// crewjam saml.IdentityProvider) so the protocol legs run for real, while
// the store is faked at the two seams the flows touch: db.Querier for plain
// reads and writes, and the WithTx/WithWorkspace runner for the provider
// and domain reads that run inside transactions.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// fakeStore is an in-memory db.Querier covering the tables the SSO login
// path touches. Methods the tests never reach stay nil (via the embedded
// interface) and panic, so a test that drifts onto an unexpected query
// fails loudly instead of silently.
type fakeStore struct {
	db.Querier

	users       map[string]*db.User
	byEmail     map[string]*db.User
	creds       map[string]*db.Credential // key: type|provider|subject
	sessions    map[string]*db.Session    // key: token hash
	tokens      map[string]fakeToken      // key: token hash
	keypair     *db.GetSAMLKeypairRow
	userCounter int
}

// fakeToken records a one-time token with the time the fake issued it, so
// HasRecentToken can answer cooldown checks.
type fakeToken struct {
	params    db.PutTokenParams
	createdAt time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		users:    map[string]*db.User{},
		byEmail:  map[string]*db.User{},
		creds:    map[string]*db.Credential{},
		sessions: map[string]*db.Session{},
		tokens:   map[string]fakeToken{},
	}
}

func (f *fakeStore) PutToken(_ context.Context, arg *db.PutTokenParams) error {
	f.tokens[arg.TokenHash.Hash()] = fakeToken{params: *arg, createdAt: time.Now()}
	return nil
}

func (f *fakeStore) HasRecentToken(_ context.Context, arg *db.HasRecentTokenParams) (bool, error) {
	for _, tok := range f.tokens {
		if tok.params.UserID == arg.UserID &&
			tok.params.Purpose == arg.Purpose &&
			tok.createdAt.After(arg.Since) {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) FindCredentialBySubject(
	_ context.Context,
	arg *db.FindCredentialBySubjectParams,
) (*db.Credential, error) {
	c, ok := f.creds[arg.Type+"|"+arg.Provider+"|"+arg.Subject]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return c, nil
}

func (f *fakeStore) GetUser(_ context.Context, id string) (*db.User, error) {
	u, ok := f.users[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return u, nil
}

func (f *fakeStore) GetUserByEmail(_ context.Context, email string) (*db.User, error) {
	u, ok := f.byEmail[normalizeEmail(email)]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return u, nil
}

func (f *fakeStore) CreateUser(_ context.Context, arg *db.CreateUserParams) (*db.User, error) {
	f.userCounter++
	u := &db.User{
		ID:    "user-000" + string(rune('a'+f.userCounter)),
		Email: normalizeEmail(arg.Email),
		Name:  arg.Name,
		// Mirror the schema defaults: new accounts are active and unverified.
		Active: true,
	}
	f.users[u.ID] = u
	f.byEmail[u.Email] = u
	return u, nil
}

func (f *fakeStore) UpdateUser(_ context.Context, arg *db.UpdateUserParams) (*db.User, error) {
	u, ok := f.users[arg.ID]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	if arg.Name != nil {
		u.Name = *arg.Name
	}
	if arg.Picture != nil {
		u.Picture = arg.Picture
	}
	return u, nil
}

func (f *fakeStore) ListCredentialsByType(
	_ context.Context,
	arg *db.ListCredentialsByTypeParams,
) ([]*db.Credential, error) {
	var out []*db.Credential
	for _, c := range f.creds {
		if c.UserID == arg.UserID && c.Type == arg.Type {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeStore) VerifyUserEmail(_ context.Context, id string) error {
	if u, ok := f.users[id]; ok {
		u.EmailVerified = true
	}
	return nil
}

func (f *fakeStore) UpsertCredential(_ context.Context, arg *db.UpsertCredentialParams) (*db.Credential, error) {
	c := &db.Credential{
		ID:       arg.ID,
		UserID:   arg.UserID,
		Type:     arg.Type,
		Provider: arg.Provider,
		Subject:  arg.Subject,
		Data:     arg.Data,
		Label:    arg.Label,
	}
	f.creds[arg.Type+"|"+arg.Provider+"|"+arg.Subject] = c
	return c, nil
}

func (f *fakeStore) CreateSession(_ context.Context, arg *db.CreateSessionParams) error {
	f.sessions[arg.TokenHash.Hash()] = &db.Session{
		TokenHash:  arg.TokenHash,
		SubjectID:  arg.SubjectID,
		Kind:       arg.Kind,
		Method:     arg.Method,
		LastSeenAt: arg.LastSeenAt,
		CreatedAt:  time.Now(),
	}
	return nil
}

func (f *fakeStore) GetSAMLKeypair(_ context.Context) (*db.GetSAMLKeypairRow, error) {
	if f.keypair == nil {
		return nil, pgx.ErrNoRows
	}
	return f.keypair, nil
}

func (f *fakeStore) PutSAMLKeypair(
	_ context.Context,
	arg *db.PutSAMLKeypairParams,
) (*db.PutSAMLKeypairRow, error) {
	f.keypair = &db.GetSAMLKeypairRow{KeyEnc: arg.KeyEnc, CertPem: arg.CertPem}
	return &db.PutSAMLKeypairRow{KeyEnc: arg.KeyEnc, CertPem: arg.CertPem}, nil
}

// fakeStoreConn fakes the WithTx/WithWorkspace surface. It doubles as the
// sqlc DBTX underneath, serving the transactional queries the SSO login path
// issues: the provider row and workspace domain rows. Anything else panics so
// an unexpected transactional read fails the test.
type fakeStoreConn struct {
	store    *fakeStore
	provider *db.SsoProvider
	domains  []*db.WorkspaceDomain
}

func (c *fakeStoreConn) Querier() db.Querier { return c.store }

func (c *fakeStoreConn) AdminQuerier() db.Querier { return c.store }

func (c *fakeStoreConn) WithTx(_ context.Context, fn func(*db.Queries) error) error {
	return fn(db.New(c))
}

func (c *fakeStoreConn) WithWorkspace(_ context.Context, fn func(*db.Queries) error) error {
	return fn(db.New(c))
}

func (c *fakeStoreConn) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	// Every SSO login upserts the provider's workspace membership. These tests
	// cover the flow, not membership, so the insert is accepted and not
	// modelled.
	if strings.Contains(sql, "workspace_members") && strings.Contains(sql, "INSERT") {
		return pgconn.CommandTag{}, nil
	}
	panic("sso test: unexpected exec: " + sql)
}

func (c *fakeStoreConn) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "sso_providers"):
		if c.provider == nil {
			return errRow{pgx.ErrNoRows}
		}
		return &sliceRow{vals: []any{
			c.provider.WorkspaceID,
			c.provider.ProviderID,
			c.provider.Method,
			c.provider.Name,
			c.provider.Enabled,
			[]byte(c.provider.Config),
			c.provider.CreatedAt,
			c.provider.UpdatedAt,
		}}
	case strings.Contains(sql, "workspace_domains") && len(args) == 1:
		for _, d := range c.domains {
			if d.Domain == args[0].(string) {
				return &sliceRow{vals: domainVals(d)}
			}
		}
		return errRow{pgx.ErrNoRows}
	}
	panic("sso test: unexpected query row: " + sql)
}

func (c *fakeStoreConn) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if !strings.Contains(sql, "workspace_domains") {
		panic("sso test: unexpected query: " + sql)
	}
	rows := make([][]any, 0, len(c.domains))
	for _, d := range c.domains {
		rows = append(rows, domainVals(d))
	}
	return &sliceRows{rows: rows}, nil
}

func domainVals(d *db.WorkspaceDomain) []any {
	return []any{
		d.WorkspaceID,
		d.Domain,
		d.ProviderID,
		d.Token,
		d.VerifiedAt,
		d.CreatedAt,
		d.UpdatedAt,
	}
}

// errRow is a pgx.Row that always fails with err.
type errRow struct{ err error }

func (r errRow) Scan(_ ...any) error { return r.err }

// sliceRow scans one row of values into dests positionally.
type sliceRow struct{ vals []any }

func (r *sliceRow) Scan(dest ...any) error { return scanVals(r.vals, dest) }

// sliceRows scans a small result set into dests positionally.
type sliceRows struct {
	rows [][]any
	i    int
}

func (r *sliceRows) Next() bool {
	r.i++
	return r.i <= len(r.rows)
}

func (r *sliceRows) Scan(dest ...any) error { return scanVals(r.rows[r.i-1], dest) }

func (r *sliceRows) Close()                        {}
func (r *sliceRows) Err() error                    { return nil }
func (r *sliceRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }
func (r *sliceRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}
func (r *sliceRows) Values() ([]any, error) { return r.rows[r.i-1], nil }
func (r *sliceRows) RawValues() [][]byte    { return nil }
func (r *sliceRows) Conn() *pgx.Conn        { return nil }

// scanVals fills dests positionally. The supported dest types cover the
// sqlc-generated scans of the rows the fake serves. Source values may be
// plain values or pointers (nullable columns).
func scanVals(vals []any, dest []any) error {
	if len(vals) != len(dest) {
		return pgx.ErrNoRows
	}
	for i, d := range dest {
		v := vals[i]
		switch out := d.(type) {
		case *string:
			s, ok := indirect(v).(string)
			if !ok {
				return pgx.ErrNoRows
			}
			*out = s
		case **string:
			if v == nil {
				*out = nil
				continue
			}
			s, ok := indirect(v).(string)
			if !ok {
				return pgx.ErrNoRows
			}
			*out = &s
		case *bool:
			b, ok := indirect(v).(bool)
			if !ok {
				return pgx.ErrNoRows
			}
			*out = b
		case *time.Time:
			ts, ok := indirect(v).(time.Time)
			if !ok {
				return pgx.ErrNoRows
			}
			*out = ts
		case **time.Time:
			if v == nil {
				*out = nil
				continue
			}
			ts, ok := indirect(v).(time.Time)
			if !ok {
				return pgx.ErrNoRows
			}
			*out = &ts
		case *crypto.EncryptedBytes:
			b, ok := indirect(v).([]byte)
			if !ok {
				return pgx.ErrNoRows
			}
			*out = crypto.EncryptedBytes(b)
		case *[]byte:
			b, ok := indirect(v).([]byte)
			if !ok {
				return pgx.ErrNoRows
			}
			*out = b
		case *int32:
			n, ok := indirect(v).(int32)
			if !ok {
				return pgx.ErrNoRows
			}
			*out = n
		case *crypto.HashedToken:
			s, ok := indirect(v).(crypto.HashedToken)
			if !ok {
				return pgx.ErrNoRows
			}
			*out = s
		default:
			return pgx.ErrNoRows
		}
	}
	return nil
}

// indirect dereferences a single-level pointer value.
func indirect(v any) any {
	if p, ok := v.(*string); ok {
		if p == nil {
			return nil
		}
		return *p
	}
	if p, ok := v.(*time.Time); ok {
		if p == nil {
			return nil
		}
		return *p
	}
	return v
}

// newSSOTestService builds a Service wired to the in-memory store, ready to
// serve the OIDC and SAML flows at http://nokku.test.
func newSSOTestService(t *testing.T, store *fakeStore, conn *fakeStoreConn) *Service {
	t.Helper()
	conn.store = store
	svc, err := New(t.Context(), Deps{
		BaseURL: "http://nokku.test",
		Conn:    conn,
		Cache:   cache.NewMemory(1000),
		// The passkey flow builds unconditionally when the cache exists and
		// validates its origins eagerly.
		PasskeyRPOrigins: []string{"http://nokku.test"},
	})
	if err != nil {
		t.Fatalf("build iam service: %v", err)
	}
	return svc
}

// seedOIDCProvider stores an OIDC provider row under workspace ws1.
var ws1ID = "ws1"

func seedOIDCProvider(conn *fakeStoreConn, oidc *OIDCProvider) {
	cfgJSON, _ := json.Marshal(providerConfig{OIDC: oidc})
	conn.provider = &db.SsoProvider{
		WorkspaceID: &ws1ID,
		ProviderID:  "ws1",
		Method:      string(MethodOIDC),
		Name:        "Test OIDC",
		Enabled:     true,
		Config:      crypto.EncryptedBytes(cfgJSON),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// seedSAMLProvider stores a SAML provider row under workspace ws1.
func seedSAMLProvider(conn *fakeStoreConn, samlIDP *SAMLIDP) {
	cfgJSON, _ := json.Marshal(providerConfig{SAML: samlIDP})
	conn.provider = &db.SsoProvider{
		WorkspaceID: &ws1ID,
		ProviderID:  "ws1",
		Method:      string(MethodSAML),
		Name:        "Test SAML",
		Enabled:     true,
		Config:      crypto.EncryptedBytes(cfgJSON),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

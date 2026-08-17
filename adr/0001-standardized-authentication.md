# ADR 0001: Standardized authentication across nokku, nk, and nokkud

- Status: Accepted
- Date: 2026-08-16 (revised)
- Scope: kagi (library), nokku (backend), nk (CLI), nokkud (daemon)

## Context

nokku is a simpler, more decentralized alternative to Teleport. Teleport routes
every SSH connection through a central proxy; here, users connect **directly** to
daemons. The backend is reduced to three jobs:

1. **CA storage and signing** (SSH user/host certs, X.509).
2. **Principal policy distribution** (push the `principal -> [uuid, ...]` map to
   each daemon).
3. **Enrollment and identity issuance** for users, CLIs, and daemons.

Because access is direct user-to-daemon, the daemon must keep serving SSH even
when the backend is unreachable. That constraint is central to every decision
below.

Four components authenticate in four different ways today:

- **kagi** is user-centric and `net/http`-only. Its `Principal` carries no notion
  of identity kind (human, service account, daemon, device). Sessions are opaque,
  store-backed tokens. `keyauth` proves key possession via a server nonce but has
  no TPM attestation. `apikey` anticipates service accounts in `APIKeyRecord.UserID`
  but has no first-class type.
- **nokku** has four identity kinds (users, service accounts, daemons, CLI devices)
  but three credential mechanisms: stateless PASETO (web + CLI), opaque `nks_*`
  service-account tokens, and a custom self-signed `Authorization: Nokku <challenge>`
  header for daemons and CLI devices. It serves connectrpc through a Vanguard
  transcoder, uses Postgres RLS for tenancy, RBAC in Go, and a hand-rolled
  `StreamCLILogin` server-stream RPC for CLI onboarding.
- **nk** derives a deterministic P-256 ECDSA key from TPM (software fallback),
  registers the public key, and signs per-request challenges. Interactive login is
  the browser-push `StreamCLILogin`; headless mode is a `nks_` service-account token.
- **nokkud** enrolls once with a time-limited token, registers its key, then signs
  per-request challenges. It embeds an SSH server that trusts CA-signed
  certificates only, and it already verifies them offline against a locally cached
  CA public key plus a cached `username -> UUID` principal map.

Three mismatches drive this refactor:

1. **Identity model.** kagi assumes every principal is a `User`. Daemons and service
   accounts are not users and should not be forced into the `users` table.
2. **Transport.** kagi's entry points are `http.Handler` wrappers, but its
   verification core (`SessionManager.Verify`, `apikey.Verify`, `keyauth.Begin/Finish`,
   context helpers) is already transport-neutral. What is missing is a connectrpc
   adapter and a transport-neutral tenant resolver.
3. **Session semantics.** kagi uses opaque revocable sessions; nokku uses stateless
   PASETO plus `user_devices` gating refresh. The two-token split works but is
   harder to reason about than it is worth; a single opaque session is both simpler
   and makes revocation of web sessions trivial.

The goal is one authentication engine (kagi) shared by all three apps, using
standard flows where they exist, and keeping authorization (RBAC, RLS) out of the
library. kagi stays **generic**: it serves simple single-tenant apps and enterprise
multi-tenant apps alike, and understands nokku only to the extent that its hooks
allow. Anything nokku-specific lives in nokku or in kagi subpackages that the core
does not depend on.

nokku is **not live yet**. There is no installed base, no migration window, and no
compatibility requirement: the refactor is a clean cut, not a dual-mode transition.

## Design principles

- **One authn engine** (kagi), one session model, one token-binding standard.
- **Standards over invention.** Prefer an RFC over a homegrown protocol wherever
  one fits. No custom crypto schemes.
- **The backend is an issuer, not a runtime dependency.** The daemon verifies SSH
  access offline from a locally cached trust bundle; the backend signs certs and
  pushes policy.
- **Tenant in the credential, never in a client hint.** A tenant-A credential
  structurally cannot act on tenant-B.
- **kagi is generic.** Its core carries *what* authenticated and *how*; the
  meaning of a principal kind is decided by the application. connectrpc, DPoP, and
  JWT dependencies stay in subpackages the core does not import.
- **Low mental overhead.** Prefer fewer moving parts; SPIFFE/SPIRE and full
  attestation are explicitly not adopted unless a concrete need appears.

## Decisions

### D1: Opaque server-side sessions (control plane only)

Users and CLIs authenticate with an opaque, store-backed, revocable session token.
nokku adds a `sessions` table and migrates off PASETO entirely.

- **Why.** Instant revocation, one model for web/CLI, matches kagi. The single
  token replaces the 15-minute access + 7-day refresh split; "remember me"
  becomes the session TTL. There is no refresh flow and no `user_devices`-gated
  refresh — both disappear. The stolen-refresh-token reuse detection that the
  two-token split enabled is intentionally dropped for the web (a browser session
  lives in an HttpOnly+SameSite cookie, so cookie theft = session theft either
  way); machines get a stronger guarantee from DPoP (D2).
- This applies only to the control plane. The SSH data plane uses certificates
  (D4), not sessions, so offline serving is unaffected.

### D2: DPoP-bound tokens for machines (RFC 9449, with server nonce)

After enrollment, nk and nokkud authenticate with a token bound to their TPM or
software key via DPoP. The per-request self-signed challenge and the `Nokku-Proof`
header are retired.

- **Why.** DPoP is the standard for proving possession of a key alongside a
  bearer token. It keeps the security property of the old challenge scheme (a
  stolen token is useless without the key) while being a real RFC with ecosystem
  support. It is lighter than mTLS (RFC 8705): no client-certificate PKI, works
  at the application layer, which matters because the daemon ships anywhere.
- **Replay protection.** The server issues a rotating nonce (RFC 9449 section 8)
  that every proof must carry, so a captured proof is not replayable once the
  nonce rotates. A bounded seen-`jti` cache closes the gap inside a nonce window.
  Details in the DPoP section below.

### D3: Full migration, clean cut

All four surfaces (web, CLI, daemon, service accounts) migrate, with no surface
left on the old mechanisms. Because nokku is not live, there is no compatibility
window: PASETO, the `Authorization: Nokku <challenge>` header, `StreamCLILogin`,
and the refresh-token flow are removed in the same change that adds their
replacement. The rollout section orders the work so each phase compiles and tests
independently, but nothing needs to dual-read.

- **Why.** Half-migrated auth is worse than the current state: two engines, two
  token models, two revocation paths. The whole point is one engine.

### D4: Decentralized trust: certs for the SSH plane, backend as CA + policy

The SSH data plane stays certificate-based and offline-verifiable. The backend
issues short-lived SSH certs (user and host) and pushes the
`principal -> [uuid, ...]` policy map; daemons verify certs locally against a
cached CA bundle and the cached map.

- **Why.** This is the property that makes the decentralized model work. A
  bearer session cannot be verified while the backend is down, but an SSH
  certificate can: CA public key, validity window, and principals are all
  self-contained. The existing nokkud already does this correctly, including the
  previous-CA grace window. The refactor standardizes around it instead of
  replacing it.

### D5: Identity model: subject vs. identity, app-defined kinds

A kagi principal separates **who is authorized** (the subject) from **what
authenticated** (the identity). The `Kind` discriminator is a kagi string type
that ships with `user` and is extended by the application.

- **Why.** For a human on a CLI device the subject is the user and the identity
  is the device (and its key). For a daemon the subject is the daemon row and the
  identity is the daemon's key. For a service account the subject is the service
  account. Conflating them — as the current `user_id` column does — breaks
  authorization (role lookup is `workspace_members.user_id`) or loses the device
  that a token is bound to. Splitting them keeps authorization keyed on the
  subject while retaining the binding's provenance.

### D6: kagi scope boundary

kagi's core adds the identity model (D5), binding (D2), and a transport-neutral
authenticator. It does **not** know what a "daemon" or "service account" is: those
are `Kind` constants defined in nokku. connectrpc, DPoP/JWT, and any nokku-shaped
tenant resolution live in subpackages (`kagi/connectrpc`, `kagi/dpop`) so `go get
github.com/mizuchilabs/kagi` does not pull a connectrpc or JWT dependency unless
those subpackages are imported.

- **Why.** kagi is meant to be reused in simpler and other enterprise apps. The
  nokku-specific semantics (daemon role, workspace RLS, service-account roles)
  stay in nokku's authorization interceptor, which consumes a plain `Principal`.

### D7: Email is the login identity; username is derived

kagi has no username concept: `User` is `{ID, Email, DisplayName}`. nokku's
`users` table keeps a `username` column for display and URL slugs, but it is no
longer a login identifier. `auth.UsernameFromEmail` derives a valid username from
the email local part (lowercased, restricted charset, `"user"` fallback), so the
column is filled consistently at every creation site (password register, passkey
signup, SSO provisioning).

- **Why.** Two identifiers (email + username) that must both be unique, both be
  validated, and both be changeable is complexity with no security benefit.
  Email is the only identity kagi understands; username becomes presentation.

### D8: SAML uses a single shared SP (not per-workspace SPs)

One SP keypair serves the whole deployment, persisted in a `saml_sp_keys`
singleton row and generated on first boot. Every workspace's IdP is configured
against the same SP entity and certificate.

- **Why.** The SP side of SAML identifies *Nokku* to the IdP, not the workspace;
  the workspace is identified by the IdP side (the IdP metadata the workspace
  uploads). Per-workspace SPs bought nothing and forced every workspace through
  a key-generation + cert-rotation lifecycle. The previous per-workspace
  `sp_private_key`/`sp_certificate` columns and the cert-rotation job were
  removed.

### D9: Backup codes move into kagi as credentials

Backup codes become a first-class kagi feature: a `backupcode` subpackage plus a
`CredentialBackupCode` type. Each code is stored as a `Credential` whose `Subject`
is the SHA-256 hash of the normalized code; **using a code deletes it**, so the
credential count is the number of remaining codes (no `used_at` column needed).
Regeneration deletes the old set first.

- **Why.** Backup codes are a recovery factor exactly like a password or passkey,
  and kagi already owns the credential model, the "must have another login
  method" guard, the `EnforceMethod` policy gate, and audit events. There is no
  governing RFC for backup codes — only the widely accepted invariants (random,
  hashed at rest, single-use, regenerable) — so the *format* (80-bit codes in an
  unambiguous Base32 alphabet with lookalike-typo normalization) is standardized
  in kagi, while the *count* and *email/UX* stay in nokku.

## Target architecture

- **Backend (nokku)** is the CA, the policy distributor, and the identity issuer.
  It does not proxy SSH.
- **User → daemon**: the user authenticates to the backend, obtains a short-lived
  SSH certificate listing their UUID as a valid principal, then connects directly
  to the daemon, which verifies the cert offline against the CA and the local
  principal policy.
- **CLI (nk)**: RFC 8628 device flow with DPoP binding to the TPM key; replaces
  `StreamCLILogin`. The browser is still auto-opened via `verification_uri_complete`.
- **Daemon (nokkud)**: enrolls with a bootstrap token on any platform, proves its
  key, and holds a non-expiring, DPoP-bound session for control-plane traffic;
  serves SSH offline from certs.
- **Service accounts**: kagi `apikey` with a first-class identity kind; roles
  remain in nokku's authz interceptor.

## Standards map

| Surface              | Flow                             | Standard                  | TPM role                     |
| -------------------- | -------------------------------- | ------------------------- | ---------------------------- |
| Interactive CLI (nk) | device grant                     | RFC 8628                  | holds DPoP key               |
| Token binding        | proof of possession              | RFC 9449 (DPoP)           | signs DPoP proof             |
| Replay protection    | rotating server nonce            | RFC 9449 section 8        | n/a                          |
| Headless CI          | client credentials               | RFC 6749 section 4.4      | n/a                          |
| Daemon bootstrap     | enrollment token                 | kubelet bootstrap pattern | attests at enrollment (opt.) |
| Daemon control plane | DPoP-bound token                 | RFC 9449                  | signs DPoP proof             |
| SSH data plane       | SSH certificates                 | OpenSSH cert model        | TPM host/user keys           |
| Offline trust        | trust bundle + short-lived certs | X.509/SSH cert model      | local verification           |
| Account recovery     | single-use recovery codes        | NIST SP 800-63B pattern   | n/a                          |

SPIFFE/SPIRE are deliberately not adopted: SPIFFE is only a naming spec, SPIRE is
a per-node agent. The useful ideas (tenant bound into the identity, short-lived
credentials, a trust bundle) are covered by D2 and D4 without either.

## kagi API changes

Identity model:

```go
// Kind discriminates what kind of principal a credential represents. kagi ships
// KindUser; applications define further kinds as constants of this type.
type Kind string

const KindUser Kind = "user"

type Principal struct {
    SubjectID    string   // authorization subject: user, service account, daemon, or device
    TenantID     TenantID // pinned for machine creds; empty for user principals
    Kind         Kind     // user (default) or app-defined
    IdentityID   string   // the authenticated entity when it differs from SubjectID (CLI device id)
    Method       Method
    SessionToken string
    Binding      string   // DPoP jkt when the credential is key-bound
    Scopes       []string
}
```

Session binding stores the DPoP key thumbprint (`jkt`, RFC 9449 section 4.2). A
zero `ExpiresAt` means the session never expires (daemons):

```go
type Session struct {
    Token      string
    TenantID   TenantID
    SubjectID  string
    Kind       Kind
    IdentityID string
    Method     Method
    Binding    string    // jkt for machine sessions, empty for humans
    ExpiresAt  time.Time // zero = never expires
}

type SessionParams struct {
    TenantID   TenantID
    SubjectID  string
    Kind       Kind
    IdentityID string
    Method     Method
    Binding    string        // DPoP jkt
    TTL        time.Duration // 0 = never expires
}

func (sm *SessionManager) IssueToken(ctx context.Context, p SessionParams) (Session, error)
```

The user-facing `Issue(ctx, w, t, u, m)` stays as a convenience that issues a
`KindUser` session, so the existing providers don't change.

The transport-neutral authenticator composes session verification with an
injected DPoP verifier. kagi core depends on DPoP only through an interface, so it
imports no JWT library:

```go
// DPoPVerifier verifies a DPoP proof and returns the key thumbprint it proves.
type DPoPVerifier interface {
    Verify(ctx context.Context, proofJWT, accessToken, htm, htu string) (jkt string, err error)
}

type ProofOptions struct {
    Method string // htm, e.g. POST
    URL    string // htu, the request URL including the connectrpc procedure
}

func (a *Authenticator) Authenticate(ctx context.Context, accessToken, dpopJWT string, opts ProofOptions) (Principal, error)
```

`Authenticate` verifies the session, and when `session.Binding != ""` requires a
DPoP proof whose `jkt` matches. `apikey.Verify` remains separate (different store,
different wire format).

`apikey` gains first-class service-account support and per-tenant listing:

```go
func (m *Manager) Issue(ctx context.Context, t TenantID, ownerID string, kind Kind, name string, scopes []string, ttl time.Duration) (APIKey, error)
func (m *Manager) ListTenantKeys(ctx context.Context, t TenantID) ([]APIKeyRecord, error)
```

New connectrpc adapter subpackage (keeps the connectrpc dependency out of the core
`net/http` packages):

```go
package connectrpc

type ResolveTenant func(context.Context, connect.Spec, proto.Message) (kagi.TenantID, error)

type Options struct {
    Authenticator *kagi.Authenticator
    APIKeys       *apikey.Manager
    DPoP          *dpop.Verifier
    ResolveTenant ResolveTenant
    IsPublic      func(connect.Spec) bool
    BaseURL       string   // reconstructs the DPoP htu
    CookieName    string   // reads the session token from a cookie (browser clients)
}

func New(o Options) connect.Interceptor
```

The interceptor applies the two-mode tenant rule: a machine principal's tenant is
pinned by the credential and never taken from the request; a user principal's
tenant is resolved by `ResolveTenant` and later authorized by the application
(RLS/RBAC), not trusted.

The backup-code feature adds `CredentialBackupCode`/`MethodBackupCode` and a
`backupcode` subpackage with `Generate`/`Normalize`/`Hash` pure functions and a
`Manager` (`GenerateCodes`, `Consume`, `Login`, `List`, `Count`, `Delete`). The
atomic delete-on-use guarantee lives in a new `CredentialStore`
`ConsumeCredentialBySubject` method.

## DPoP-bound token protocol (RFC 9449)

Machine requests (nk, nokkud) present two headers:

```
Authorization: Bearer <access-token>
DPoP: <proof-jwt>
```

- The client holds its key (TPM or software), exposes it as a JWK, and computes
  the thumbprint `jkt = base64url(SHA256(JWK thumbprint))`.
- The access token stays **opaque**; its binding (`jkt`) is stored server-side in
  the session record rather than as a `cnf` claim in the token. This is the
  standard adaptation for opaque tokens.
- The DPoP proof is a JWT with header `typ: dpop+jwt` and the public `jwk`, and
  claims `htm` (HTTP method), `htu` (request URL, which carries the connectrpc
  procedure), `iat`, `jti`, `nonce`, and `ath` (hash of the access token).

Server verification:

1. Verify the DPoP proof signature against the embedded `jwk`.
2. Check `htm`/`htu` match the actual request, `iat` is fresh, and the `nonce` is
   one the server issued within its rotation window.
3. Check `ath` matches the presented access token.
4. Reject a `jti` already seen within the nonce window (bounded seen-cache).
5. Verify the session and confirm `session.Binding == jkt`.

Nonce handling (RFC 9449 section 8):

- The server derives a nonce as an HMAC over a time bucket (rotates every few
  minutes, default 5m) from a shared `NonceSecret`. The nonce is **not a
  secret**; it is a freshness marker that prevents replaying a captured proof
  once the nonce rotates. Because it is stateless, any instance sharing the
  secret validates it — no shared cache or cross-instance coordination — and a
  proof survives a rotation boundary (the previous bucket is accepted too).
- A request whose proof carries a missing or stale `nonce` gets `401` with
  `DPoP-Nonce: <current>` and `error=use_dpop_nonce`. The client caches the nonce,
  attaches it to its next proof, and retries once. nk and nokkud both already have
  retry plumbing to hang this on.

Properties:

- A stolen token is useless without the key.
- A captured proof is useless after the nonce rotates, and `jti` tracking closes
  the in-window gap.
- Revocation is a single session row delete (delete the daemon, or reset its
  sessions), and works because the token is opaque and server-side.

## Device flow with DPoP (replaces StreamCLILogin)

1. `nk` has (or creates) its TPM/software key.
2. `nk` calls `deviceauth.Begin`, a plain RFC 8628 device-authorization request:
   the server returns `device_code`, `user_code`, `verification_uri`, and
   `verification_uri_complete`.
3. `nk` auto-opens `verification_uri_complete` (the code is embedded), so the UX
   is unchanged — and now also works when the browser is on another machine.
4. The user approves at the verification URI using any login method.
5. `nk` polls `deviceauth.Poll` with a DPoP proof over the `device_code`; the
   grant records the `jkt` at this step (RFC 9449 section 5 binds DPoP at token
   issuance, not device authorization). `Poll` returns a kagi session with
   `Kind = device`, `SubjectID = user`, `IdentityID = device`, and `Binding = jkt`.
6. Subsequent requests send `Authorization: Bearer <session>` plus a `DPoP` proof.

Headless mode is unchanged: a service-account token skips the device flow entirely.

## Daemon enrollment (any platform)

The enrollment token is the universal mechanism because the daemon must deploy on
on-prem VMs, cloud VPS, or anywhere with an SSH server. Cloud instance identity
(IMDS) is a possible later convenience, not the foundation.

1. The operator provisions a daemon with a tenant-scoped, single-use, time-limited
   enrollment token, injected at deploy time by whatever provisioner is in use
   (cloud-init, Terraform, Packer, or a hand-typed `--enroll`). This is the
   existing `EnrollDaemon` shape; only what follows changes.
2. `EnrollDaemon(token, jwk, DPoP proof)` verifies the token is valid for the
   tenant, unused, and unexpired, verifies the key proof, and issues a daemon
   identity carrying `{tenant, daemon_id, jkt}` plus a DPoP-bound access token.
3. Ongoing control-plane traffic uses the DPoP-bound token; the tenant comes from
   the credential, never a client hint.

The daemon's token is **non-expiring**: an enrolled daemon must run indefinitely
and is removed by deleting it, not by a clock. Deleting a daemon deletes its
sessions (cascade), which revokes the token. Because the token is DPoP-bound, an
exfiltrated token is useless without the TPM key, and a compromised machine is
handled by kicking the daemon rather than by token rotation.

## Service accounts

- `apikey.Issue(..., kind=KindServiceAccount, ...)` replaces nokku's
  `CreateServiceAccount` token minting; hashing and verification move to kagi.
- `apikey.Verify` returns `Principal{Kind: KindServiceAccount, SubjectID: <sa id>}`.
- Expiry lives **in the key**, enforced at verification time. The
  `service_accounts.expires_at` column (if kept at all) is display-only and no
  longer has any security meaning.
- nokku keeps the `service_accounts` table for name, role, and display expiry; the
  authz interceptor resolves the role from `Principal.Kind` + id, exactly as it
  does today.
- Wire format migrates to kagi's `keyID.secret`; `nk`'s `IsServiceAccount`
  detection becomes the presence of the `--token` flag rather than the `nks_`
  prefix.

## nokku data model

New `sessions` table, not RLS-enforced (global token lookup in a system
transaction, matching today's service-account lookup). `subject_id` is the
authorization subject; `identity_id` is the authenticated entity when it differs
(CLI devices). `workspace_id` is null for user sessions — nokku users are global
and their workspace is resolved and authorized per request — and set for machine
credentials:

```sql
CREATE TABLE sessions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash   bytea NOT NULL UNIQUE,  -- sha256 of the opaque token, never stored raw
    subject_id   uuid NOT NULL,          -- user, daemon, or device subject
    identity_id  uuid,                   -- device id when the subject is a user on a device
    workspace_id uuid,                   -- null for user sessions, set for machine creds
    kind         text NOT NULL,          -- user | daemon | device
    method       text NOT NULL,
    binding      text,                   -- DPoP jkt, null for humans
    expires_at   timestamptz,            -- null = never expires (daemons)
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_subject ON sessions (subject_id);
```

Service accounts do not use the sessions table; their token is an API key.

Migrations alongside the session table:

- `user_identities`, `passkeys`, and `backup_codes` collapse into kagi
  `credentials` rows (`type = oidc|oauth2|saml|passkey|backup_code`).
- The password hash moves from `users.password_hash` into a password credential
  (kagi stores the PHC hash in `Credential.Data`).
- PASETO tokens are dropped; the refresh-token flow and `user_devices`-gated
  refresh go away.
- A new `saml_sp_keys` singleton holds the shared SAML SP keypair; the
  per-workspace `saml_providers.sp_*` columns and the cert-rotation job are
  removed.

Non-session PASETO uses get their own replacement: the `verification` token type
(email verification and password reset) becomes an opaque single-use token,
hashed at rest in a small `one_time_tokens` table (token_hash, user_id, purpose,
expires_at). The `cli` token type disappears with `StreamCLILogin`. The
web-device `nkv_` cookie is a known-device marker for security alerting, not an
auth credential; it stays as-is and is decoupled from refresh.

The certificate side (CA, `principal -> [uuid, ...]` policy, host certs) is
unchanged in structure; the backend keeps signing and pushing, the daemon keeps
verifying offline.

## Offline behavior

What the daemon does when the backend is unreachable:

- **SSH user access keeps working**: user certs are verified against the cached
  CA public key and principal map, both local. Availability is bounded by cert
  TTL, so user and host cert TTLs are tuned to the maximum tolerated outage.
- **Host certs renew early** with backoff, and the previous-CA grace window covers
  rollover during an outage.
- **Principal policy** is stale but functional until the next sync.
- **Control plane** (sync, recordings, audit) pauses and resumes on reconnect;
  recordings queue locally and flush later.

The `AuthorizeFunc` hook in `sshd` (device trust, MFA) is the place to add
offline revocation later, e.g. a locally cached deny-list refreshed on sync.

## Rollout

Each phase lands independently (compiles and passes tests), but there is no
compatibility window and no dual-read: the old mechanism is deleted in the same
phase that introduces its replacement.

1. kagi: `Kind`, subject/identity split, session `Binding`, non-expiring sessions,
   `Authenticator`, `dpop` verifier with nonce rotation, connectrpc adapter,
   service-account `apikey` support. No behavior change for existing callers.
2. nokku: `sessions` + `one_time_tokens` tables, store implementations against
   sqlc, web auth migrated onto kagi handlers. PASETO, the refresh flow, the
   challenge header, and `StreamCLILogin` are removed here.
3. Device flow backend + `nk` polling client (removes the `StreamCLILogin` client).
4. Daemon DPoP enrollment and control-plane auth, backend + `nokkud`.
5. Service accounts onto `apikey`.
6. Backup codes onto `kagi/backupcode`.
7. Optional later: real TPM attestation via `github.com/google/go-attestation`
   (EK/AK/PCR quotes); net-new on both sides, currently out of scope.

## Consequences

Positive:

- One generic authentication engine, one session model, one binding standard for all
  three apps.
- Instant, reliable revocation, including stolen machine tokens.
- Hardware binding retained via DPoP without per-request custom signatures.
- CLI onboarding becomes the standard RFC 8628 flow with true headless support.
- The decentralized model is explicit: certs for the SSH plane, backend as CA and
  policy distributor only.
- Less hand-rolled crypto: PASETO, `StreamCLILogin`, the refresh split, and the
  custom challenge all disappear from nokku.
- kagi stays reusable: the nokku-shaped parts (kinds, tenant resolution, RBAC)
  live in nokku or in kagi subpackages.

Negative:

- A session table plus one lookup per authenticated control-plane request.
- A schema migration (identities, passkeys, password hash, sessions).
- Stateless PASETO is gone; horizontal scaling now needs the session store shared
  (Postgres is already the source of truth).
- The two-token split's refresh-reuse detection is dropped for web sessions (the
  property is preserved for machines via DPoP).
- kagi gains a connectrpc and a JWT dependency, both confined to subpackages.

## What shipped vs. what remains

Completed (all code lands, builds, and tests green):

- **kagi**: `Kind`/subject-identity split, DPoP-bound non-expiring sessions,
  `Authenticator`, the `dpop` verifier (RFC 9449 + stateless HMAC nonce), the
  `dpop.Proofer` client signer (round-trip tested against the verifier), the
  `connectrpc` adapter (with `CookieName` for browser sessions and `BaseURL` for
  `htu`), the `deviceauth` flow (with an optional per-flow `SessionTTL` and a
  `/auth/nonce` endpoint), the `backupcode` package, and `apikey` with
  first-class kinds. `backupcode` and `CredentialStore.ConsumeCredentialBySubject`
  landed last, with delete-on-use semantics.
- **nokku backend**: the `sessions`/`api_keys`/`credentials`/`one_time_tokens`/
  `saml_sp_keys` tables, the sqlc-backed kagi `Store`, the `auth.Service` wiring
  (Kagi/Store/Authenticator/APIKeys/DPoP/Passwords/BackupCodes/Tokens), the SSO
  policy hooks, the shared SAML SP, and full migration of password/passkey/OIDC/
  OAuth2/SAML/device/backup-code handlers. The old challenge-based authn service
  (`internal/authn`, PASETO), `StreamCLILogin`, the refresh flow, `user_devices`,
  `user_identities`, `passkeys`, `users.password_hash`, and the per-workspace
  SAML SP columns/job are all deleted.
- **nokku frontend**: auth is fixed onto the new model — the refresh-token
  interceptor is gone (sessions are single opaque tokens), the removed RPCs and
  fields are cleaned up (no `verifyCLILogin`, no device panel, no passkey
  rename), and a `/device` page implements the RFC 8628 verification-URI UX
  (code prefill, sign-in-first with a `pendingDeviceCode` round-trip, then
  `POST /auth/device/verify`).

Machine auth migrated (daemons and service accounts):

- **daemon enrollment** (`EnrollDaemon`) now verifies a DPoP proof over the
  enrollment request and issues a non-expiring, DPoP-bound `KindDaemon` session,
  returning its token. The `daemons.auth_method`/`auth_pubkey` columns and the
  legacy challenge verifier are deleted (migration `006`).
- **service accounts** are issued as kagi API keys (`apikey.Issue` with
  `KindServiceAccount`); `service_accounts.token_hash` and the `nks_` token
  path (`crypto.NewServiceAccountToken`, `PrefixSA`, prefix parsing) are
  deleted. Deleting a service account revokes its keys.
- **Whoami** resolves the authenticated principal: a user for browser sessions,
  or the service account (with its pinned workspace) for `nk --token` headless
  mode, so a headless CLI discovers its identity without parsing the token.
- **nokkud** enrolls with a DPoP proof, persists the returned session token, and
  signs every control-plane request (`SyncDaemon`, control stream `Connect`,
  `Session`) with a DPoP proof, retrying once on a stale nonce. The daemon has
  no signing identity for SSH certs beyond this key.
- **nk** replaces `StreamCLILogin` with the RFC 8628 device flow: `POST
  /auth/device` → browser → poll `POST /auth/device/token` for a DPoP-bound
  session (7d TTL), persisted to disk (0600) and re-logged-in on expiry.
  Headless mode (`--token`) uses the service-account API key with no signing
  identity and no DPoP. The client DPoP interceptor learns the nonce from the
  `DPoP-Nonce` response header and retries once.

Remaining (optional follow-ups, none blocking):

- TPM attestation (phase 7, `github.com/google/go-attestation`) is still
  net-new and out of scope.
- The seen-`jti` DPoP replay cache (RFC 9449 §4.4) is a known hardening gap;
  acceptable for TLS-bound control planes.
- The `kagi` dependency in `nk`/`nokkud` currently uses a `replace` directive
  until kagi is tagged and published.

## Edge cases and how they were handled

These are the non-obvious corners encountered during the refactor, worth keeping
in the record:

1. **Session cookie name in the connectrpc adapter.** Browser clients send the
   session in an HttpOnly cookie, not an `Authorization` header. The connectrpc
   adapter must read the cookie (`CookieName: "session"`) or every browser RPC is
   a 401. This surfaced as a symptom ("whoami/listWorkspaces 401, username
   empty") after the web auth rewrite, not a compile error.
2. **`Secure` cookies on plain-HTTP localhost.** The session cookie sets
   `Secure: true` unconditionally; browsers treat `localhost` as a
   trustworthy origin, so local HTTP dev works, but any non-localhost plain-HTTP
   host drops the cookie. This is left as a documented sharp edge (production is
   HTTPS) rather than branching `Secure` on `FullURL()`.
3. **DPoP `htu` for connectrpc.** connectrpc interceptors do not see the full
   request URL, so the adapter needs `BaseURL` to reconstruct the `htu` the
   client must sign. The client must sign the same origin.
4. **The stale nonce / retry cycle.** A proof with a stale nonce must produce a
   `401` + `DPoP-Nonce` header + `error=use_dpop_nonce`, and the client retries
   once with the fresh nonce. The connectrpc adapter special-cases
   `dpop.ErrStaleNonce` to set that header.
5. **Non-expiring sessions encode as zero `ExpiresAt`.** Daemons must never
   expire by a clock. The store maps zero `ExpiresAt` to `NULL` and back, and
   every consumer treats the zero value as "no expiry".
6. **Tenant pinning for machine principals.** A machine principal's tenant is
   pinned in the credential; the actor interceptor refuses to let a request's
   `workspace_id` field override it (the request value is ignored for machine
   actors). User principals resolve their workspace per-request.
7. **SAML SP on first boot.** The shared SP keypair is generated and persisted on
   first boot (a singleton `saml_sp_keys` row). `EnsureSAMLSPKey` is idempotent,
   so multi-instance deployments race to the same row safely via
   `ON CONFLICT DO NOTHING`, and the `metadata`/`certificate` endpoints serve
   whatever won.
8. **Backup codes are credentials, deleted on use.** No `used_at` column: a
   consumed code is deleted atomically (`ConsumeCredentialBySubject`), so the
   credential count is the remaining-count. Regeneration deletes the old set
   first (the previous behavior kept `used_at` rows around for display, which the
   credential model has no room for — acceptable since only the *count* was ever
   shown). The atomic consume also enforces single-use across concurrent
   requests.
9. **Email-as-identity means no username at signup.** Every user-creation site
   (register, passkey signup, SSO JIT) derives the `username` column from the
   email via `auth.UsernameFromEmail`, so the display column is never left empty
   and never a login input.
10. **Credential ID synthesis.** kagi credentials are keyed by `(tenant, id)`;
    nokku synthesizes stable IDs (`userID + ":password"`, `provider + ":" +
    subject`, `userID + ":backup:" + hash`) so upserts are idempotent and the
    unique `(tenant, type, provider, subject)` index covers identity linking.
11. **Deleted passkey/device/identity surfaces on the frontend.** The removed
    RPCs (`UpdatePasskey`, `ListUserDevices`, `DeleteUserDevice`, `VerifyCLILogin`)
    and fields (`Passkey.name`, `OAuthIdentity.provider_email/username`) left
    dead frontend code that had to be excised in the same change — the build is
    the only thing that catches these, since the protos regenerate silently.
12. **Client DPoP nonce bootstrap.** The `connectrpc` interceptor only sees the
    *response* header, and `deviceauth.Poll`/`EnrollDaemon` are unauthenticated
    so the connect interceptor never runs for them. The client fetches `GET
    /auth/nonce` up front, and the interceptor retries once on a `401` whose
    `connect.Error.Meta()` carries a `DPoP-Nonce` header. The device-flow poll
    loop also consumes a fresh `DPoP-Nonce` from a rejected `Poll` and re-signs.
13. **The tpm signer's crypto.Signer contract.** The client `tpm.Signer` hashes
    then signs (`Sign(ctx, data)`), which is the wrong shape for go-jose. An
    adapter (`CryptoSigner()`) exposes the raw key as a digest-signing
    `crypto.Signer` (TPM template pins SHA-256), and `dpop.Proofer` wraps it
    with `cryptosigner.Opaque` + `EmbedJWK`. A round-trip test signs with the
    proofer and verifies with the verifier to keep the `jkt` definitions in
    sync.
14. **Headless nk has no signing identity.** A service-account API key carries
    no identity, so `nk --token` skips signer creation entirely. `Whoami` was
    extended to return the authenticated principal (user *or* service account,
    with its pinned workspace) so the headless CLI resolves "who am I" without
    parsing the token. The `nks_` prefix detection was replaced by the `.`
    separator, matching the server's dispatch rule.
15. **Device sessions persist to disk.** The nk device session token is a bearer
    shape but useless without the bound signing key; it is persisted (0600) with
    its expiry so the CLI works across invocations and can re-login proactively,
    unlike the deliberately-ephemeral service-account token.

## Open questions

- DPoP nonce rotation cadence (default 5m) and whether the seen-`jti` cache should
  be mandatory or a hardening toggle.
- Attestation scope for phase 7: key provenance only, or full PCR policy.

# Nokku product reference

This is the canonical agent-facing doc for the Nokku ecosystem. Read it before
working across repos. Each repo root also has an `AGENTS.md` with its own
commands, layout, and danger points.

## What Nokku is

Nokku is a decentralized SSH access platform built on SSH certificates.
Access is granted per principal (a local account on a target) to subjects
identified by UUID, and the SSH certificate principal is always the subject
UUID.
The data plane is plain SSH: once certs and host trust are in place, sessions
work even when the backend is down.

## Ecosystem

Five repos, usually checked out as siblings.

| Repo | Module | Role | Size (rough) |
| --- | --- | --- | --- |
| `nokku` | `github.com/nokku-sh/nokku` | Go control plane. PostgreSQL via pgx/v5 and sqlc, Connect RPC with vanguard transcoding, SvelteKit UI embedded into the binary. | ~33k hand-written Go lines |
| `nokkud` | `github.com/nokku-sh/nokkud` | Edge daemon. Embedded SSH server on :4022, recording, host certs. | ~6k lines |
| `nk` | `github.com/nokku-sh/nk` | Operator and user CLI. Cert minting, ssh config generation, manual sync. | ~4k lines |
| `mon` | `github.com/nokku-sh/mon` | Shared primitives: `tpm`, `dpop`, `dpopclient`, `fsutil`, `id`. Consumed by nokkud and nk, not by nokku. | ~1.5k lines |
| `protos` | buf module | All 16 `.proto` files under `nokku/v1`. Read-only for everyone else. | tiny |

### The proto model

Proto source lives only in `../protos`, in the buf module rooted at
`protos/nokku` with package path `nokku/v1` (`protos/nokku/nokku/v1` from
that repo's root).
Every app repo checks in generated code under its own `internal/gen`, so the
same protos are compiled three times: once in nokku, nokkud, and nk.
Any proto change means editing `../protos`, then running `task gen` in all
three app repos and committing the regenerated code in each.
There is no CI lock-step check yet, so this is on you. See
`docs/ROADMAP.md`.

### Backend layering

The request path through nokku is strictly layered:

- `cmd/nokku` boots, `internal/config` loads settings.
- `internal/api` holds the Connect services. It is the only place
  permissions and plan gates resolve.
- `internal/daemon` is an in-memory pool of live daemon control streams,
  relays, and web sessions.
- `internal/db` is RLS-scoped sqlc over pgx/v5. Two pools: `nokku_app` for
  tenant traffic, `nokku_system` (BYPASSRLS) for bootstrap work.
- Identity lives in `internal/iam` and never answers may-X. Authorization is
  `internal/db/roles.go` plus `internal/api/authz.go`. Plan gating is
  `internal/entitlement`.
- Crypto is split: `internal/crypto` (at-rest, tokens, Tink/KMS),
  `internal/ssh` (SSH CA signing), `internal/pki` (X.509).

## Glossary

- **Workspace**: the tenant. Row-level security is scoped to it through the
  GUC `nokku.workspace_id`, which fails closed when unset.
- **Target**: one machine. Either has a daemon or is manual.
- **Daemon target**: a host running nokkud. It syncs itself, presents host
  certificates, and serves SSH on :4022.
- **Daemonless or manual target**: a host nobody installed a daemon on. The
  operator runs `nk sync` from their own machine over their own ssh. Trust is
  a pinned raw host key, not a host cert.
- **Principal**: a local account on a target, like `deploy` or `root`.
- **Grant**: a row linking a principal to a subject (user, team, or service
  account). The ACL is `principal_grants`, teams expand through `team_members`.
- **Subject UUID**: the id of a user, team, or service account. It is what an
  SSH certificate carries as its principal.
- **CA**: a workspace SSH certificate authority. One CA signs both user and
  host certs for the workspace.
- **Daemon**: short for nokkud, the edge agent.
- **Relay**: two bidi Connect streams spliced in the backend so a user can
  reach a daemon behind NAT. The backend is a byte pipe, sessions stay
  end-to-end encrypted.
- **Web terminal**: a browser SSH session. The backend mints an ephemeral
  user cert and connects through a relay like any other client.
- **Enrollment token**: `<workspace-uuid>_<32-byte-secret>`, 24h expiry,
  stored hashed. Mints a daemon session that does not expire.

### Data model

Core tables, all RLS-scoped to the workspace:

- `workspaces` are the tenants.
- `targets` carry a nullable `daemon_id` (null means manual) and a nullable
  `host_public_key` (the pin, manual mode only). `metadata` is a jsonb bag
  for signals like `last_manual_sync`.
- `principals(target_id, username)` is one local account.
- `principal_grants(principal_id, subject_kind, subject_id)` is the ACL.
  Teams expand through `team_members`.
- The CA row sets `user_default_ttl` (120h) and `user_max_ttl` (168h). One
  CA signs both user and host certs.

The schema is a single squashed migration,
`nokku/internal/db/migrations/001_base.sql`, applied by tern.

## Trust model

One workspace SSH CA signs both user and host certificates.

- The user cert principal is the subject UUID, never a username. The host
  only decides "is this UUID allowed for this account", which is exactly what
  `AuthorizedPrincipalsFile` and the daemon's cache both encode.
- Daemon targets present host certs with the target UUID as principal, so
  users verify them through `@cert-authority`.
- Manual targets pin a raw host public key instead. The pin is read over the
  operator's own ssh on first sync and updated on every sync.
- Sessions are DPoP-bound (RFC 9449). Daemon sessions never expire, they are
  revoked by deleting the daemon. User sessions follow the workspace CA TTL
  rules.
- Machine signing identities come from `mon/tpm`, TPM-backed when available,
  otherwise a machine-wrapped software key. Salts namespace the derived keys
  and are a registry documented in `mon/README.md`: `nokku-daemon`,
  `nokku-daemon-host`, `nokku-cli`, `nokku-cli-ssh`.
- The database enforces tenant isolation through RLS, fail-closed. The app
  never hand-rolls workspace filters.
- Principal files on manual hosts are deny-by-default: an account with no
  grants gets an empty file, and sshd refuses an empty principals list.

### Auth methods

`nokku/internal/iam` is the largest backend package and carries: password,
passkey, backup codes, OIDC, OAuth2 social seeds, SAML, the device flow
(RFC 8628, the CLI login path), DPoP (RFC 9449), and SCIM 2.0. No LDAP, no
TOTP.

## Invariants, never break

1. The SSH certificate principal is the subject UUID.
2. Revocation is map removal plus daemon sync. For manual targets it is
   TTL-bounded plus operator re-sync: cert TTL defaults to 120h and maxes at
   168h, so a stale grant on a manual host dies when its certs do.
3. The backend being down never takes down the data plane. The daemon serves
   from its cached principals, the CLI from cached state and valid certs.
4. System sshd on port 22 stays untouched on daemon hosts. nokkud owns :4022.
5. Manual sync transport is the operator's own system ssh. No agent, no
   credentials, no Nokku SSH client on manual hosts, ever. That rules out any
   backend push to manual hosts, which is a product decision, not a gap.
6. Tokens and secrets never appear on argv or in URLs. Enrollment reads the
   env or a no-echo prompt.
7. Account lists only ever create anchors, never delete. A failed report must
   not be able to lock anyone out.

## Flows

Each flow names its entry point. Paths are relative to their repo.

### Daemon enrollment

An admin mints a token in the UI: `nokku/internal/api/daemon.go`
`DaemonService.RefreshEnrollToken` stores it hashed with a 24h expiry. On the
host, `sudo nokkud --enroll` (or `NOKKUD_ENROLL_TOKEN`) carries the token to
`DaemonService.EnrollDaemon`, a public endpoint that still demands a DPoP
proof. Identity is the key thumbprint, so re-enrollment is stable across
token rotation. The daemon starts PENDING unless `settings.enroll_auto_approve`.
On approval `nokku/internal/iam` issues a session with no expiry, pinned to
the workspace and the key binding.

### Daemon sync

`nokkud/internal/client/client.go` `Run` holds a bidi control stream open to
`DaemonControlService.Connect`, registered on the pool in
`nokku/internal/api/server.go`. Heartbeats every 5 minutes carry an in-memory
per-workspace state version that resets on server restart, so every daemon
re-syncs once after a backend restart. `SyncDaemon` pushes the principals map,
the CA public key, and daemon config. The daemon caches all of it under
`/var/lib/nokkud` so auth decisions survive a backend outage.

### Manual sync (`nk sync`)

`nk/internal/cmd/target.go` `syncManualTarget` drives it. It resolves the
workspace and CA, finds or creates the target (reading the host key over the
operator's ssh pins it), lists local accounts with `getent passwd`, and pulls
grants from `nokku/internal/api/target.go` `GetTargetPrincipals`. It renders
host files with `nk/internal/manual` (`HostFiles`): the CA at
`/etc/ssh/nokku_ca.pub`, a drop-in at `/etc/ssh/sshd_config.d/60-nokku.conf`
setting `TrustedUserCAKeys` and a per-account `AuthorizedPrincipalsFile`, one
principals file per account under `/etc/ssh/nokku_principals`. It reports to
the backend with `SyncTargetUsers`, which also stamps
`metadata.last_manual_sync`, then writes everything through an idempotent
`sh -s` script (`WriteScript`) that stages with tmp+mv, validates with
`sshd -t`, reloads sshd, and verifies with `sshd -T` that the drop-in is live.

The `/etc/ssh` layout constants are shared with nokkud and the web UI, so all
three agree on where trust material lives.

### User connect

`nk/internal/client/client.go` `sync` generates `~/.config/nk/ssh_config`
(one Host block per target with `ProxyCommand nk proxy %h %p`, the cert file,
the agent socket, and `HostKeyAlias <targetID>`) plus `known_hosts`.
The agent socket serves a `mon/tpm` signer. Certs are minted by
`EnsureCert` against the backend's CertificateService.
`nk/internal/cmd/proxy.go` `proxyCMD` (hidden) dials the target endpoints
directly with a 2s timeout and falls back to the backend relay stream.
Daemon targets verify host certs via `@cert-authority`, manual targets via
the pinned raw key. The backend is consulted on every connection so grants
apply immediately. The cache and valid certs cover outages.

### Relay

`nokku/internal/daemon/handler.go` `Pool.DaemonRelay` and `RequestRelay`
pair two bidi Connect streams: the user's `RelayService` stream and the
daemon's own dial-back. `nokku/internal/daemon/relaybridge.go` `BridgeRelay`
splices the bytes. The daemon dials its own loopback sshd. The backend sees
ciphertext.

### Web terminal

`nokku/internal/api/daemon.go` `DaemonService.CreateSession` mints an
ephemeral 1h user cert (principal is the actor id), opens a relay, and has
the pool dial the daemon's sshd over it. Sessions cap at 8h TTL with a 30m
idle timeout.

### Recording

`nokkud/internal/recording` records asciicast v3 gz locally and streams
chunks to `nokku/internal/api/recording.go`
`RecordingService.UploadRecording`. Frames are stored encrypted in blob
storage (`nokku/internal/storage`, local or S3), scrubbed for detected
secrets on completion, and evicted by retention and byte caps per plan.

## Product rules for change

- The simplicity gate: a feature must be worth deleting something else.
- One behavior per change.
- The dependency bar: a new dependency must replace more logic than it adds.
- Boring tech first. Postgres, plain SSH, stock sshd primitives.
- LOC goes down over time, or the change needs a reason.

## Non-goals

- No agent or credentials on manual hosts. This is why there is no backend
  push to them, only operator-pulled sync.
- No LDAP, no TOTP today.
- No custom PAM.
- No password auth to daemons. Certificates only.

## Working with agents here

1. Read this doc.
2. Read the repo's `AGENTS.md`.
3. Scout the code before editing.
4. Verify with the repo's `task lint` before handing over.
5. Pick work from `docs/ROADMAP.md` and mark it done there when finished.

### Verifying changes

- Go repos: plain `go build ./...` and `go test ./...` always work. The
  `task lint` variants add fmt, vet, govulncheck, race, and golangci-lint.
- Backend DB tests need PostgreSQL: `docker compose -f compose.test.yml up -d`
  from the nokku root. Tests skip without it.
- Web UI: `pnpm check` and `pnpm build` from `web/ui`.
- Generated code (`internal/gen`, sqlc output) is never hand-edited. Change
  the source in `../protos` or `internal/db/queries` and regenerate.

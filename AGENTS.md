# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

nokku is the Nokku control plane. One Go binary owns PostgreSQL, the Connect
RPC API, the embedded web UI, and every trust decision (CAs, grants,
entitlements, sessions). It runs as a single instance. Daemon streams, relays
and single-use state live in the process.

The ecosystem is five sibling repos, usually checked out next to each other:
`nokku` (this one), `nokkud` (edge daemon, SSH on :4022), `nk` (CLI), `mon`
(shared TPM and DPoP primitives, not used here), and `protos` (proto source
and the generated Go API code). A `go.work` in the parent directory points
them at the local protos. CI has no `go.work` and uses what `go.mod` pins.

## Commands

```bash
task dev            # backend + web/ui dev server
task backend        # go run ./cmd/nokku
task frontend       # web/ui dev server (Vite, :5173)
task gen            # sqlc + the web client from the pinned protos
task lint           # tidy, GOWORK=off build, fmt, vet, govulncheck, test -race, golangci-lint --fix, web/ui fmt+lint
task build          # UI build, then bin/nokku
task build:ui       # web/ui into web/ui/build
task build:email    # email templates into web/email/out
task migrate:up     # tern, dev only. Production migrates at boot
```

Tests:

```bash
docker compose -f compose.test.yml up -d postgres   # keycloak and vault too for the SSO and KMS tests
go test ./...
go test ./internal/api -run TestName -count=1
```

DB-backed packages call `testdb.Setup` in `TestMain` and get a fresh
`nokku_test_<pkg>` database, so tests never touch the dev database. Without a
reachable Postgres those tests skip locally. In CI that is a failure. The
Keycloak and Vault tests behave the same way.

Frontend, from `web/ui`: `pnpm check`, `pnpm fmt`, `pnpm lint`.

The Go build works without node. `web/ui/build` and `web/email/out` hold a
committed `.gitkeep` and are embedded by `web/embed.go`.

## Architecture

- `cmd/nokku` is the entrypoint, plus the `rotate-secrets` subcommand.
- `internal/config` wires every service together in `config.New`. Background
  jobs live in the package that owns them and stop with the root ctx.
- `internal/api` holds the Connect services and the plain HTTP routes
  (auth callbacks, avatars, `/terminal/ws`, the Stripe webhook). It is the
  only place permissions and plan gates resolve. Handlers return errors as
  they come, `errorInterceptor` maps them onto connect codes. Interceptor
  order in `server.go` matters: authn, audit, error mapping, authz,
  entitlement guard, validation. Audit wraps authz so denied calls are
  recorded.
- `internal/db` is sqlc queries plus migrations, all RLS-scoped. Pick the
  entry point by what the query may see: `WithWorkspace` (tenant rows, the
  request path), `WithTx` and `Sys()` (role `nokku_system`, BYPASSRLS, only
  boot, SaaS signup, webhooks and jobs). The owner role only migrates at
  startup.
- `internal/tenant` resolves the workspace from the request host before
  authentication. Self-hosted serves one workspace created at boot. SaaS
  (billing on) gives each workspace a subdomain of `NOKKU_BASE_URL`.
- `internal/iam` is identity: passkeys, email links, OIDC, device flow, DPoP,
  SCIM. Accounts live inside a workspace, there are no global users. It
  answers who, never may.
- `internal/daemon` is the in-memory pool of live daemon control streams,
  relays (two bidi streams spliced, the backend only sees ciphertext), and
  web terminal sessions.
- `internal/entitlement` is plan gating, the self-hosted license, and the 30
  day hold on data limits after a plan or license ends.
- `internal/billing` is Stripe. One `sync` writer mirrors a subscription into
  `workspace_subscriptions`. Stripe stays the source of truth.
- `internal/crypto` is at-rest crypto, tokens, and the Tink keyset with
  optional KMS wrap. `EncryptedBytes` and `HashedToken` column types are
  mapped in `sqlc.yaml`.
- `internal/ssh` signs SSH certs. `internal/pki` is X.509 and CA rollover.
- `internal/recording` and `internal/storage` handle encrypted recording
  ingest, secret scrubbing, retention, and blob storage (local or S3).
- `web/ui` is the SvelteKit SPA. `web/ui/README.md` has the UI conventions
  (tokens in `src/routes/layout.css`, `ui` vs `ext` vs `blocks` components,
  tone colors, copy rules). Read it before UI work. `web/ui/AGENTS.md` asks
  for a TanStack intent skill check before substantial edits.
- `web/email` is react-email templates, exported to `web/email/out`. Colors
  are hex copies of the UI tokens.

Two modes, picked at startup in `internal/config`. Self-hosted is the
default and the plan comes from the license key. SaaS is on when the
`STRIPE_*` settings are present and the plan comes from the workspace
subscription. Three plans: `community`, `pro`, `enterprise`. The catalog is
`internal/entitlement/plan.go`.

Daemon sync: DB triggers bump `workspace_state` on every change that alters
what a daemon enforces and fire `pg_notify('nokku_state', workspace_id)`.
`Pool.Listen` turns that into a poke on the control stream and the daemon
calls `SyncDaemon`.

## Conventions

- Who may call an RPC is declared on the RPC itself, `option (access)` in the
  protos repo (`access.proto`). RPCs without it are denied.
  `internal/api/authz.go` enforces it, with roles from `internal/db/roles.go`.
- Everything a daemon calls lives in `DaemonControlService`
  (`internal/api/daemon_control.go`), and nothing else does but the public
  `EnrollDaemon`. A new daemon RPC goes there, never as a second mode of a
  user RPC. `authz_test.go` checks it.
- Daemon state changes notify through the DB triggers. Never hand-roll a
  daemon poke in a handler.
- Tenant isolation is RLS via `Conn.WithWorkspace`. Never hand-roll workspace
  filters, never bypass RLS for tenant data.
- A new RPC means a proto edit in `../protos` with its `(access)` option,
  pushed, then
  `go get github.com/nokku-sh/protos@$(git -C ../protos rev-parse HEAD)` and
  `task gen` here. That pins the pushed commit. `task lint` builds with
  `GOWORK=off`, so an unpushed protos change shows before the push.
- sqlc queries live in `internal/db/queries`. The `*.sql.go` files,
  `models.go`, `querier.go` and `web/ui/src/lib/gen` are generated, never
  hand-edited.
- Schema changes go straight into `internal/db/migrations/001_base.sql`
  while there is no release. No new migration files.
- Plan gating lives only in `internal/entitlement`.
- Prices are stated only on the docs pricing page
  (`../docs/src/pages/pricing.astro`). Never in code, UI copy, emails,
  READMEs, or other docs pages.
- Never log secrets. See `SECURITY.md`.
- `BACKLOG.md` (gitignored, local) is the work queue when it exists.

## Product invariants

- An SSH certificate principal is `<subject uuid>@<target uuid>:<account>`,
  built only by `ssh.LoginPrincipal`. The subject is a user or a service
  account, a team grant resolves to its members. A bare username or a bare
  subject id is never a principal, either would open every host that trusts
  the CA.
- A user certificate is signed for one target and only with a grant on it.
  Hosts compare principals as whole strings and never parse them.
- The backend being down never takes down the data plane. Daemons serve from
  cached principals, the CLI from cached state and valid certs.
- Revocation is grant removal plus daemon sync, which is immediate. A host
  that misses the sync (offline, a daemon that is unapproved or deleted, a
  manual target before its next `nk sync`) is bounded by the certificate
  lifetime, since nothing is signed without the grant. The backend never
  pushes to manual hosts.
- Tokens and secrets never appear on argv or in URLs.

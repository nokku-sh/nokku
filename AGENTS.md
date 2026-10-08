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
task lint           # tidy, GOWORK=off build, fmt, vet, govulncheck, unit tests -race, golangci-lint --fix, web/ui fmt+lint
task test           # unit tests, no services
task test:integration  # internal/integration, starts its own containers, needs Docker
task build          # UI build, then bin/nokku
task build:ui       # web/ui into web/ui/build
task build:email    # email templates into web/email/out
task migrate:up     # tern, dev only. Production migrates at boot
task seed           # fake users, teams, servers and daemons in the dev database
```

Tests:

```bash
go test ./...                                          # unit tests, no services
go test -tags integration ./internal/integration/...   # needs Docker
go test -tags integration ./internal/integration/api -run TestName -count=1
```

Tests next to the code are unit tests. They call functions directly and never
open a connection, so `go test ./...` takes about a second and needs nothing
running.

Everything that needs Postgres, Keycloak or Vault lives in
`internal/integration/<area>`, behind the `integration` build tag. Those are
external test packages, they only use what the package under test exports.
`testenv.Postgres` in `TestMain` starts a container for that test binary and
sets the `PG*` environment. `testenv.Keycloak` and `testenv.Vault` start
theirs for the test that asks. Nothing reads `compose.dev.yml`, it is only
the dev stack, and the dev database is never touched. The images are pinned
in `testenv` and in `compose.dev.yml`, keep the two on the same versions. CI sets the tag in the
prepare action, so the shared workflow lints and runs both kinds. An editor
needs `-tags=integration` in the gopls build flags to work on that tree.

Frontend, from `web/ui`: `pnpm check`, `pnpm fmt`, `pnpm lint`.

The Go build works without node. `web/ui/build` and `web/email/out` hold a
committed `.gitkeep` and are embedded by `web/embed.go`.

## Architecture

- `cmd/nokku` is the entrypoint, plus the `admin-link` and `rotate-secrets`
  subcommands. They wire only what they need and never call `config.New`,
  the server may be running next to them.
- `cmd/seed` fills the first workspace of a dev database with fake data. It
  is not part of the release.
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
  entry point by what the query may see: `Tenant()` and `TenantTx` (tenant
  rows, the request path), `Sys()` and `SysTx` (role `nokku_system`,
  BYPASSRLS, a pool of its own, only boot, webhooks and jobs). The owner role
  only migrates at startup.
- `internal/tenant` resolves the workspace from the request host before
  authentication. Self-hosted serves one workspace created at boot. SaaS
  (`NOKKU_SAAS`) gives each workspace a subdomain of `NOKKU_BASE_URL`.
  `tenant.Create` is the one way a workspace comes to be.
- `internal/iam` is identity: passkeys, email links, OIDC, device flow, DPoP,
  SCIM. Accounts live inside a workspace, there are no global users. It
  answers who, never may. `iam.New` gets everything it calls out to in
  `iam.Deps` (audit, the mail functions), nothing is set on it afterwards.
- `internal/daemon` is the in-memory pool of live daemon control streams,
  relays (two bidi streams spliced, the backend only sees ciphertext), and
  web terminal sessions.
- `internal/live` tells the open consoles when to read again. Triggers
  announce a changed table on `nokku_change`, the hub paces that into hints
  on `WorkspaceService.SubscribeChanges`, and the UI refetches the queries
  of the services a hint names. No data travels on it.
- `internal/entitlement` is plan gating, the self-hosted license, and the 30
  day hold on data limits after a plan or license ends.
- `internal/billing` is Stripe, nil on a self-hosted server. One `sync` writer
  mirrors a subscription into `workspace_subscriptions`. Stripe stays the
  source of truth.
- `internal/crypto` is at-rest crypto, tokens, and the Tink keyset with
  optional KMS wrap. `EncryptedBytes` and `HashedToken` column types are
  mapped in `sqlc.yaml`.
- `internal/ssh` signs SSH certs and rolls CAs over.
- `internal/recording` and `internal/storage` handle encrypted recording
  ingest, secret scrubbing, retention, and blob storage (local or S3).
- `web/ui` is the SvelteKit SPA. `web/ui/README.md` has the UI conventions
  (tokens in `src/routes/layout.css`, `ui` vs `ext` vs `blocks` components,
  tone colors, copy rules). Read it before UI work. `web/ui/AGENTS.md` asks
  for a TanStack intent skill check before substantial edits.
- `web/email` is react-email templates, exported to `web/email/out`. Colors
  are hex copies of the UI tokens.

Two modes, set by `NOKKU_SAAS` and read as `cfg.SaaS`. Self-hosted is the
default and the plan comes from the license key. SaaS is the hosted service,
it needs every `STRIPE_*` setting and the plan comes from the workspace
subscription. The mode is never guessed: Stripe settings that do not fit it
fail the start. Three plans: `community`, `pro`, `enterprise`. The catalog is
`internal/entitlement/plan.go`.

Daemon sync: DB triggers bump `workspace_state` on every change that alters
what a daemon enforces and fire `pg_notify('nokku_state', workspace_id)`.
`Pool.Listen` turns that into a poke on the control stream and the daemon
calls `SyncDaemon`.

## Conventions

- Who may call an RPC is declared on the RPC itself, `option (access)` in the
  protos repo (`access.proto`). RPCs without it are denied.
  `internal/api/authz.go` enforces it.
- A role is the `WorkspaceRole` enum of the protos everywhere: in the API, in
  Go, in the UI, and as its number in the database. The values are ordered,
  so "at least" is `>=` and the zero value passes nothing. Never keep a
  second list of roles or compare role names as strings.
- Everything a daemon calls lives in `DaemonControlService`
  (`internal/api/daemon_control.go`), and nothing else does but the public
  `EnrollDaemon`. A new daemon RPC goes there, never as a second mode of a
  user RPC. `authz_test.go` checks it.
- Daemon state changes notify through the DB triggers. Never hand-roll a
  daemon poke in a handler.
- Tenant isolation is RLS, and nothing else. The request pool pins the
  workspace of the context every time a connection leaves it
  (`pinWorkspace` in `internal/db/connection.go`) and refuses a context
  without one. A tenant query has no `workspace_id` filter and a tenant
  insert no `workspace_id` column, the column default takes it from the pin.
  Never hand-roll workspace filters, never bypass RLS for tenant data.
- One statement is a plain call, `cfg.Conn.Tenant().GetTeam(ctx, id)`.
  `TenantTx` is for statements that belong together: several writes, a read
  the write depends on, or a write whose result decides a rollback
  (`TransferOwnership`). Never wrap a single statement in it.
- The pin is session state, so the server needs direct connections to
  Postgres. A pooler in transaction mode would hand a pinned connection to
  the wrong query.
- A query names the workspace only when system code calls it (billing, the
  plan lookup, retention jobs). Those say so in a comment. System code
  (`SysTx`, `Sys()`) must never call a query that does not: with RLS
  bypassed it would reach every workspace.
- Work outside a request that belongs to one workspace pins it with
  `actor.WithWorkspace` and uses `TenantTx`, like `iam.Bootstrap` and
  `tenant.Create` do. Tests seed the same way.
- A new tenant table needs `workspace_id UUID NOT NULL DEFAULT
  current_workspace_id ()`, its name in the policy list in `001_base.sql`,
  and a seed row in `seedEveryTable`. `internal/integration/db/rls_test.go`
  reads the tables from the catalog and fails on a table that misses any of
  them.
- A tenant table the console shows goes into the `notify_change` list in
  `001_base.sql`, anything else into `silentTables` in
  `internal/integration/db/change_test.go`, which fails on a table in
  neither. A table
  that changes with nobody clicking also names its readers in
  `internal/live`, without them every console refetches everything. The UI
  never polls a list.
- The workspace on the context (`actor.Workspace`) only holds what never
  changes: id, slug, base URL. Read the name and the settings from the row.
- Every row in `access_tokens` is a credential. What only remembers something
  about an account, like the browsers and terminals in `known_devices`, gets
  a table of its own, so nothing has to tell it apart from a login.
- A new RPC means a proto edit in `../protos` with its `(access)` option,
  pushed, then
  `go get github.com/nokku-sh/protos@$(git -C ../protos rev-parse HEAD)` and
  `task gen` here. That pins the pushed commit. `task lint` builds with
  `GOWORK=off`, so an unpushed protos change shows before the push.
- sqlc queries live in `internal/db/queries`. The `*.sql.go` files,
  `models.go` and `web/ui/src/lib/gen` are generated, never
  hand-edited.
- Schema changes go straight into `internal/db/migrations/001_base.sql`
  while there is no release. No new migration files.
- Plan gating lives only in `internal/entitlement`.
- Prices are stated only on the docs pricing page
  (`../docs/src/pages/pricing.astro`). Never in code, UI copy, emails,
  READMEs, or other docs pages.
- Never log secrets. See `SECURITY.md`.
- A test that needs a real service goes into `internal/integration`, never
  next to the code. When it needs something a package does not export, reach
  it through the public path first and export a small seam only when there is
  none.
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

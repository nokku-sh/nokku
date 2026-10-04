# nokku

nokku is the Nokku control plane: a Go server owning PostgreSQL, the Connect
RPC API, the web UI, and all trust decisions (CAs, grants, entitlements,
sessions). The ecosystem is five sibling repos: `nokku` (this one, the
backend), `nokkud` (edge daemon), `nk` (CLI), `mon` (shared primitives), and
`protos` (proto source). Read `../nokku/docs/PRODUCT.md` before cross-repo
work.

## Commands

```bash
task dev            # backend + frontend concurrently
task backend        # go run ./cmd/nokku
task frontend       # web/ui dev server
task gen            # sqlc + web client from the pinned protos
task lint           # tidy, fmt, vet, govulncheck, test -race, golangci-lint, web/ui fmt+lint
task seed           # seed demo data (cmd/seed)
task build          # UI build, then the binary into bin/
task build:ui       # web/ui into web/ui/build
task build:email    # email templates into web/email/out
task migrate:up     # apply migrations (tern, dev only, production auto-migrates)
```

Plain `go test ./...` works. DB-backed tests need
`docker compose -f compose.test.yml up -d`. Each such package calls
`testdb.Setup` in its `TestMain` and gets a fresh `nokku_test_<pkg>` database,
so tests never touch the dev database.

## Layout

- `cmd/nokku` - entrypoint. `cmd/seed` - demo data.
- `internal/config` - wires the services together. Background jobs live in
  the package that owns them and stop with the root ctx.
- `internal/api` - Connect services. The only place permissions and plan
  gates resolve. Handlers return errors as they come, `errorInterceptor`
  maps them onto connect codes.
- `internal/daemon` - in-memory pool of live daemon control streams, relays,
  and web sessions.
- `internal/db` - sqlc queries and migrations. RLS-scoped. Four entry
  points: `WithWorkspace` (tenant rows), `WithActor` (the user's own rows),
  `WithTx` and `Sys()` (nokku_system, BYPASSRLS, for pre-auth and jobs). The
  owner role only migrates at startup.
- `internal/iam` - identity: passwords, passkeys, OIDC, SAML, device flow,
  DPoP, SCIM. Never answers may-X.
- `internal/entitlement` - plan gating, the self-hosted license, and the 30
  day hold on data limits after a plan or license ends.
- `internal/billing` - Stripe. One `sync` writer mirrors a subscription into
  `workspace_subscriptions`, Stripe stays the source of truth.
- `internal/crypto` - at-rest crypto, tokens, Tink/KMS.
- `internal/ssh` - SSH CA signing. `internal/pki` - X.509.
- `internal/recording`, `internal/storage` - encrypted recording ingest and
  blob storage.
- `web/ui` - SvelteKit UI, embedded via `web/embed.go`. Tokens in
  `src/routes/layout.css`, shell in `lib/components/layout`, shared blocks in
  `lib/components/blocks`. See `web/ui/README.md` for the UI conventions.
- `web/email` - react-email templates, exported to `web/email/out` and
  embedded. Colors are hex copies of the UI tokens.

## Backlog

`BACKLOG.md` is the work queue for all Nokku repos. Tick what you finish,
add what you find. Unattended work follows the `unattended-pass` skill.

## Conventions

- Who may call an RPC is declared on the RPC itself, `option (access)` in
  the protos repo (`access.proto`). RPCs without it are denied.
  `internal/api/authz.go` enforces it.
- Everything a daemon calls lives in `DaemonControlService`
  (`internal/api/daemon_control.go`), and nothing else does but the public
  `EnrollDaemon`. A new daemon RPC goes there, never as a second mode of a
  user RPC. `authz_test.go` checks it.
- Daemon state changes notify through DB triggers. Never hand-roll a
  daemon poke in a handler.
- Tenant isolation is RLS via `Conn.WithWorkspace`. Never hand-roll workspace
  filters.
- A new RPC means a proto edit in `../protos` with its `(access)` option,
  pushed, then `go get github.com/nokku-sh/protos@$(git -C ../protos rev-parse HEAD)`
  and `task gen` here. That pins the pushed commit, tags are only for
  published binaries. nokkud and nk only need the `go get` when they use what
  changed. Locally a `go.work` in the parent directory points all repos at
  the local protos, CI never does. `task lint` builds with `GOWORK=off`, so
  an unpushed protos change shows before the push.
- sqlc queries live in `internal/db/queries` and are regenerated, never
  hand-edited.
- Schema changes go straight into `internal/db/migrations/001_base.sql`
  while there is no release. No new migration files.
- Plan gating lives only in `internal/entitlement`.
- Three plans (`community`, `pro`, `enterprise`) and two modes: self-hosted,
  where the plan comes from the license, and SaaS (the `STRIPE_*` settings
  are present), where it comes from the workspace subscription.
- Prices are stated only on the docs pricing page (`../docs/src/pages/pricing.astro`).
  Never in code, UI copy, emails, READMEs, or other docs pages.
- Authorization is `internal/db/roles.go` plus `internal/api/authz.go`.
  `internal/iam` answers who, never may.

## Danger points

- Never bypass RLS.
- Never log secrets. See SECURITY.md.

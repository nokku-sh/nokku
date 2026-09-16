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
task gen            # buf generate + sqlc generate
task lint           # tidy, fmt, vet, govulncheck, test -race, golangci-lint, web/ui fmt+lint
task seed           # seed demo data (cmd/seed)
task build:server   # binary into bin/
task build:web      # both web frontends
task migrate:up     # apply migrations (tern, dev only, production auto-migrates)
```

Plain `go test ./...` works. DB-backed tests need
`docker compose -f compose.test.yml up -d`.

## Layout

- `cmd/nokku` - entrypoint. `cmd/seed` - demo data.
- `internal/config` - config load.
- `internal/api` - Connect services. The only place permissions and plan
  gates resolve. `authz.go` holds `ProcedurePermissions`.
- `internal/daemon` - in-memory pool of live daemon control streams, relays,
  and web sessions.
- `internal/db` - sqlc queries and migrations. RLS-scoped, two pools:
  `nokku_app` for tenant traffic, `nokku_system` (BYPASSRLS) for bootstrap.
- `internal/iam` - identity: passwords, passkeys, OIDC, SAML, device flow,
  DPoP, SCIM. Never answers may-X.
- `internal/entitlement` - plan gating.
- `internal/crypto` - at-rest crypto, tokens, Tink/KMS.
- `internal/ssh` - SSH CA signing. `internal/pki` - X.509.
- `internal/recording`, `internal/storage` - encrypted recording ingest and
  blob storage.
- `web/ui` - SvelteKit UI, embedded via `web/embed.go`. See `web/ui/README.md`.
- `internal/gen` - generated proto code. Never hand-edit.

## Conventions

- Permissions are declared in exactly one place:
  `internal/api/authz.go` `ProcedurePermissions`.
- Tenant isolation is RLS via `Conn.WithWorkspace`. Never hand-roll workspace
  filters.
- A new RPC means a proto edit in `../protos`, then `task gen` in all three
  app repos (nokku, nokkud, nk).
- sqlc queries live in `internal/db/queries` and are regenerated, never
  hand-edited.
- Plan gating lives only in `internal/entitlement`.
- Authorization is `internal/db/roles.go` plus `internal/api/authz.go`.
  `internal/iam` answers who, never may.

## Danger points

- Never bypass RLS.
- Never log secrets. See SECURITY.md.

# Contributing

Thanks for your interest in Nokku! It's the backend and web application for
certificate-based access. Backend and frontends ship together, so there's a
bit more tooling than the CLI repos.

## Prerequisites

- Go 1.x (see `go.mod`)
- [Task](https://taskfile.dev)
- PostgreSQL (16+), `docker compose -f compose.dev.yml up -d` brings up a dev instance
- Docker, for the integration tests
- Node.js + `pnpm` (frontends)
- [`buf`](https://buf.build) and [`sqlc`](https://sqlc.dev) (codegen)
- [`golangci-lint`](https://golangci-lint.run), [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), `golines`
- [GoReleaser](https://goreleaser.com) (snapshots/releases only)

## Getting started

Start a local PostgreSQL (ephemeral/tmpfs):

```bash
docker compose -f compose.dev.yml up -d postgres
```

Set the required environment (the repo's `.envrc` and Task env vars cover the
defaults, e.g. `DB_URL`). Then run backend and frontends together:

```bash
task dev
```

This runs the backend (`go run ./cmd/nokku`) and the `web/ui` frontend via
Vite. Open `http://localhost:3000`, the backend's address. The backend takes
the UI from Vite (`task dev` sets `NOKKU_UI_DEV` for it), so edits show up
at once, and links, cookies and passkeys use the same address a real install
has. Leave `NOKKU_BASE_URL` unset.

`task backend` alone serves the UI that was built into the binary.

To work on the built-in TLS, add `NOKKU_TLS=internal`. The app is then on
`https://localhost:3000`. Run `nk --api https://localhost:3000 --pin ... login`
once with the pin from the start log, it installs the CA for your browser.

## Regenerating generated code

```bash
task gen
```

Runs `sqlc generate`, and regenerates the web client in `web/ui/src/lib/gen`
from the `.proto` files of the protos version `go.mod` pins. The Go API code
itself comes from the [nokku-sh/protos](https://github.com/nokku-sh/protos)
module. Re-run after changing SQL or bumping that module.

For cross-repo work, use a `go.work` in the parent directory so nokku builds
against your local protos checkout. CI never sees it and uses the version in
`go.mod`, so release and bump protos before pushing here. The protos README
has the full workflow. `GOWORK=off go build ./...` shows what CI will see.

## Code style

Follow the conventions already in the codebase. Before opening a PR, run:

```bash
task lint
```

which runs `go fmt`, `go vet`, `golines`, `govulncheck`, the Go unit tests,
`golangci-lint`, and `pnpm fmt`/`pnpm lint` for the frontend.

## Tests

```bash
go test ./...            # unit tests, no services needed
task test:integration    # needs Docker
```

Unit tests live next to the code and never open a connection. Tests that need
PostgreSQL, Keycloak or Vault live in `internal/integration` behind the
`integration` build tag and start their own containers, so nothing has to run
on your machine first. CI runs both.

Please add tests for new behavior and keep the existing suite green.
Database-backed changes should include the relevant migration and regenerate
with `sqlc`.

## Releases

Releases are cut via GoReleaser on version tags. To preview a local build
without publishing (this also builds and scans the container image with
`grype` if present):

```bash
task snapshot
```

## Submitting changes

1. Fork the repo and create a branch off `main`.
2. Make focused changes and run `task lint`.
3. Open a pull request describing what and why.

Keep changes small and scoped. If a change alters behavior or UI, update the
README and CHANGELOG accordingly. Avoid leaking secrets (e.g. `NOKKU_SECRET`,
license keys, OIDC client secrets) in code, config, or commits.

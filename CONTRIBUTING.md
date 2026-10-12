# Contributing

Thanks for your interest in Nokku! The core, the daemon and the CLI live in
this one repository. It is one Go module, so a change that crosses parts is
one pull request.

| Folder      | What it is                                          |
| ----------- | --------------------------------------------------- |
| `core/`     | Backend and web application, binary `nokku`         |
| `nokkud/`   | The daemon for servers                              |
| `nk/`       | The CLI                                             |
| `internal/` | Go packages `nokkud` and `nk` share                 |
| `proto/`    | The API schema, `gen/` is the Go code built from it |

## Prerequisites

- Go 1.x (see `go.mod`)
- [Task](https://taskfile.dev)
- [`golangci-lint`](https://golangci-lint.run), [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- [`buf`](https://buf.build), for changes in `proto/`
- [GoReleaser](https://goreleaser.com) (snapshots/releases only)

The core ships backend and frontends together, so it needs a bit more:

- PostgreSQL (16+), `docker compose -f compose.dev.yml up -d` in `core/` brings up a dev instance
- Docker, for the integration tests
- Node.js + `pnpm` (frontends)
- [`sqlc`](https://sqlc.dev) (codegen)

## Tasks

Run `task --list` in the repo root. Tasks of one part carry its name,
`task core:dev` or `task nk:build`. Inside a part the same task runs without
the prefix, `cd core && task dev`.

## The CLI and the daemon

```bash
task nk:build
task nokkud:build
```

`nk` is built into `~/.local/bin/`, `nokkud` is installed to `/usr/local/bin`.
Both are static (`CGO_ENABLED=0`). The move of `nokkud` needs root, so the task
calls `sudo`.

`internal/` holds what the two share. Every change there ships in both
binaries. Never change a registered salt (see `internal/README.md`). It
silently rotates every machine identity derived from it.

## The core

Start a local PostgreSQL (ephemeral/tmpfs):

```bash
cd core
docker compose -f compose.dev.yml up -d postgres
```

Set the required environment (the `.envrc` in `core/` and Task env vars cover
the defaults, e.g. `DB_URL`). Then run backend and frontends together:

```bash
task dev
```

This runs the backend (`go run ./cmd/nokku`) and the `web/ui` frontend via
Vite. Open `http://localhost:3000`, the backend's address. The backend takes
the UI from Vite (the `backend` task sets `NOKKU_DEV_UI` for it), so edits
show up at once, and links, cookies and passkeys use the same address a real
install has. Leave `NOKKU_BASE_URL` unset.

Without `NOKKU_DEV_UI`, as in a plain `go run ./cmd/nokku`, the backend serves
the UI that was built into the binary.

To work on the built-in TLS, give this machine a name, like a line
`127.0.0.1 nokku.test` in `/etc/hosts`, and set `NOKKU_BASE_URL=nokku.test:3000`.
The app is then on `https://nokku.test:3000`. Run
`nk --api https://nokku.test:3000 --pin ... login` once with the pin from the
start log, it installs the CA for your browser.

## Regenerating generated code

```bash
task gen
```

From the `.proto` files in `proto/` this writes the Go API code in `gen/`
and the web client in `core/web/ui/src/lib/gen`. It also runs `sqlc generate`
for the core. Re-run after changing a `.proto` file or SQL, and commit the
result with the change.

## Code style

Follow the conventions already in the codebase. Before opening a PR, run:

```bash
task lint
```

which runs `go mod tidy`, `buf lint`, `go fmt`, `go vet`, `govulncheck`, the
Go unit tests with the race detector and `golangci-lint run --fix` (the
config enables golines formatting). `task core:lint` adds `pnpm fmt` and
`pnpm lint` for the frontend.

## Tests

```bash
go test ./...                 # unit tests, no services needed
task core:test:integration    # needs Docker
```

Unit tests live next to the code and never open a connection. The core's
email tests read the built templates, run `task core:build:email` once. Tests
that need PostgreSQL, Keycloak or Vault live in `core/internal/integration`
behind the `integration` build tag and start their own containers, so nothing
has to run on your machine first. The TPM tests in `internal/tpm` run against
the go-tpm simulator and skip when it cannot start. CI runs all of them.

Please add tests for new behavior and keep the existing suite green.
Database-backed changes should include the relevant migration and regenerate
with `sqlc`.

## Releases

All binaries share one version. Releases are cut via GoReleaser on version
tags. To preview a local build without publishing:

```bash
task snapshot
```

`task core:snapshot` also tags the core image and scans it with `grype`.

## Submitting changes

1. Fork the repo and create a branch off `main`.
2. Make focused changes and run `task lint`.
3. Open a pull request describing what and why.

Keep changes small and scoped. If a change alters behavior or UI, update the
README of that part. Release notes are generated from conventional commit
messages with git-cliff, so prefix commits with `feat:`, `fix:`, and so on.
Avoid leaking secrets (e.g. `NOKKU_SECRET`, license keys, OIDC client
secrets) in code, config, or commits.

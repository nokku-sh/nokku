# Contributing

Thanks for your interest in Nokku! The core, the daemon and the CLI live in
this one repository. It is one Go module, so a change that crosses parts is
one pull request.

| Folder      | What it is                                          |
| ----------- | --------------------------------------------------- |
| `core/`     | Backend and web application, binary `nokku`         |
| `daemon/`   | The daemon for servers, `nokkud`                    |
| `cli/`      | The CLI, `nk`                                       |
| `internal/` | Go packages `nk`, `nokkud` and the core share       |
| `proto/`    | The API schema, `gen/` is the Go code built from it |

## Prerequisites

- Go 1.x (see `go.mod`)
- [Task](https://taskfile.dev)
- [`golangci-lint`](https://golangci-lint.run), [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- [`buf`](https://buf.build), `protoc`, and the `protoc-gen-go` and `protoc-gen-es` plugins, for changes in `proto/`. `protoc-gen-connect-go` comes from `go tool`.
- [GoReleaser](https://goreleaser.com) (snapshots/releases only)

The core ships backend and frontend together, so it needs a bit more:

- PostgreSQL 18 or newer, `docker compose -f compose.dev.yml up -d` in `core/` brings up a dev instance
- Docker, for the integration tests
- Node.js + `pnpm` (frontend)
- [`sqlc`](https://sqlc.dev) (codegen)

## Tasks

Run `task --list` in the repo root. Tasks of one part carry its name,
`task core:dev` or `task cli:build`. Inside a part the same task runs without
the prefix, `cd core && task dev`.

## The CLI and the daemon

```bash
task cli:build
task daemon:build
```

`nk` is built into `~/.local/bin/`, `nokkud` is installed to `/usr/local/bin`.
Both are static (`CGO_ENABLED=0`). The move of `nokkud` needs root, so the task
calls `sudo`.

`internal/` holds what the two share, and the core uses some of it. Every
change there ships in both binaries. Never change the state file format of `internal/tpm` without a
migration. A key that no longer loads means every machine re-enrolls.

## The core

In `core/`, set `NOKKU_SECRET` to any 32 characters or more, or use the dev
Vault's transit key, which `task dev` creates:

```bash
export KMS_URI="hcvault://localhost:8200/transit/keys/nokku"
export VAULT_CACERT="$PWD/data/vault/vault-ca.pem"
export VAULT_TOKEN="root"
```

The database defaults already match the dev PostgreSQL. Then run:

```bash
task dev
```

This starts the containers of `compose.dev.yml`, then the backend
(`go run ./cmd/nokku`) and the `web` frontend via Vite, and seeds the users to
sign in as (see below). Every container keeps its data in memory,
`task dev:reset` wipes them all and runs `task dev` again. Do that too if Vault
restarts on its own, its new key can't open the keyset in PostgreSQL.

Open `http://localhost:3000`, the backend's address. The backend takes
the UI from Vite (the `backend` task sets `NOKKU_DEV_UI` for it), so edits
show up at once, and links, cookies and passkeys use the same address a real
install has. Leave `NOKKU_BASE_URL` unset.

Without `NOKKU_DEV_UI`, as in a plain `go run ./cmd/nokku`, the backend serves
the UI that was built into the binary.

### Users to sign in as

`compose.dev.yml` runs Pocket ID at http://localhost:1411 for OIDC and SCIM.
`task dev` runs `task seed:idp` next to the server. It waits until the server
is up, adds Pocket ID as a provider, fills Pocket ID with the users below and
has it send them over SCIM.

Set `NOKKU_ADMIN_EMAIL=admin@nokku.test`, the owner is linked to
the first Pocket ID user. Point mail at Mailpit: `NOKKU_SMTP_HOST=localhost`,
`NOKKU_SMTP_PORT=1025` and no username or password. Mailpit keeps every mail,
whoever it is for, at http://localhost:8025.

Pocket ID has no passwords. On nokku's login page pick Pocket ID, then
Alternative Sign In Methods, Email Login, and enter the address. The code
lands in Mailpit. A passkey you register in Pocket ID skips that next time.

| User                | In nokku                                     |
| ------------------- | -------------------------------------------- |
| `admin@nokku.test`  | the owner, and admin of Pocket ID            |
| `editor@nokku.test` | editor, team Platform                        |
| `member@nokku.test` | member, team Platform                        |
| `viewer@nokku.test` | viewer, team SRE                             |
| `gone@nokku.test`   | sent deactivated, cannot sign in             |

Pocket ID syncs five minutes after a change and every hour. Its admin page
has Sync now on the nokku client. It owns the directory: a nokku user it does
not know, say from `task seed` or an invite, is deprovisioned on the next sync.

## Regenerating generated code

```bash
task gen
```

From the `.proto` files in `proto/` this writes the Go API code in `gen/`
and the web client in `core/web/src/lib/gen`. It also runs `sqlc generate`
for the core. Re-run after changing a `.proto` file or SQL, and commit the
result with the change.

## Code style

Follow the conventions already in the codebase. Before opening a PR, run:

```bash
task lint
```

which runs `go mod tidy`, `buf format` and `buf lint`, `go fmt`, `go vet`, a
dead code check, `govulncheck`, the Go unit tests with the race detector and
`golangci-lint run --fix` (the config enables golines formatting).
`task core:lint` is the core on its own, with `pnpm fmt` and `pnpm lint` for
the frontend. It reports problems but never fails.

## Tests

```bash
go test ./...                 # unit tests, no services needed
task core:test:integration    # needs Docker
task core:test:hosted         # the API tests in hosted mode, needs Docker
```

Unit tests live next to the code and never open a connection. Tests
that need PostgreSQL, Keycloak or Vault live in `core/internal/integration`
behind the `integration` build tag and start their own containers, so nothing
has to run on your machine first. The TPM tests in `internal/tpm` run against
the go-tpm simulator, which is C code built with cgo. With a C compiler it
needs the OpenSSL headers (`libssl-dev` or `openssl-devel`), or the build
fails. Without one, or with `CGO_ENABLED=0`, the TPM tests skip. CI runs all
of them.

`NOKKU_TEST_HOSTED=1` runs the API tests the way the hosted service runs: with
`NOKKU_SAAS`, a Vault KMS and workspace hosts. A test that only means something
self-hosted says why it skips. Where the hosted answers differ from the
self-hosted ones, they have their own `hosted_*.golden` file.

`task smoke` is the end-to-end check, and it needs Docker. It builds the real
`nokku`, `nk` and `nokkud`, the daemon into a local `nokkud:smoke` image, and
starts its own Postgres and Mailpit on random ports. Then it walks one owner
through it all: the admin link, a daemon that enrolls, `nk login`, ssh direct
and through the relay, the web terminal, the recordings, a revoke that ends a
live session, and the audit log. Last, a CI job signs in with `nk login --ci`
against a stand-in for GitHub Actions and reaches the server. nk and ssh run in
a HOME of their own, so your `~/.ssh`, `~/.config/nk` and ssh agent stay
untouched.

Please add tests for new behavior and keep the existing suite green.
Database-backed changes should include the relevant migration and regenerate
with `sqlc`.

## Releases

All binaries share one version. Releases are built with GoReleaser by the
release workflow, which is started by hand. To preview a local build without
publishing:

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

<p align="center">
    <picture>
        <source media="(prefers-color-scheme: light)" srcset="./.github/logo_dark.svg">
        <source media="(prefers-color-scheme: dark)" srcset="./.github/logo_light.svg">
        <img src="./.github/logo_light.svg" width="80">
    </picture>
</p>

<p align="center">
  <a href="https://github.com/nokku-sh/nokku/releases"><img src="https://img.shields.io/github/v/tag/nokku-sh/nokku?label=Version" alt="Version"></a>
  <a href="https://github.com/nokku-sh/nokku/actions"><img src="https://img.shields.io/github/actions/workflow/status/nokku-sh/nokku/ci.yaml?branch=main&label=Build" alt="Build"></a>
  <a href="https://github.com/nokku-sh/nokku/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nokku-sh/nokku?label=License" alt="License"></a>
</p>

# Nokku

Nokku gives people short-lived SSH certificates instead of long-lived keys. You decide who may log in to which server as which account, and Nokku signs a certificate for exactly that.

This repository is the core: one Go binary with the API, the web app and the certificate authorities. It needs PostgreSQL and nothing else.

Your servers keep working when the core is down. They enforce what they last synced, and a valid certificate still logs in.

| Part       | Repository                                     | What it does                                           |
| ---------- | ---------------------------------------------- | ------------------------------------------------------ |
| **Core**   | `nokku` (this one)                             | Users, access, certificate authorities, SSO, audit log |
| **Daemon** | [`nokkud`](https://github.com/nokku-sh/nokkud) | Runs on a server and keeps its SSH access in sync      |
| **CLI**    | [`nk`](https://github.com/nokku-sh/nk)         | Signs you in on your machine, then plain `ssh` works   |

## Quick start

Try it on your machine with Docker. This runs the core and PostgreSQL on port 3000.

```bash
git clone https://github.com/nokku-sh/nokku && cd nokku
cp .env.prod.example .env
```

Set four values in `.env`:

```bash
NOKKU_BASE_URL=localhost:3000
NOKKU_SECRET=          # openssl rand -hex 32
POSTGRES_PASSWORD=     # anything, it stays inside the stack
NOKKU_ADMIN_EMAIL=you@example.com
```

Start it and get your sign-in link:

```bash
docker compose -f compose.min.yml up -d
docker compose -f compose.min.yml logs nokku | grep "sign in"
```

Open the link. You are signed in as the owner. Add a passkey under **Profile, Security**, and the dashboard walks you through your first server.

There is no password. Until the owner has a passkey, every start prints a fresh link that works for 24 hours.

## Deploy

All three options need the same three things:

- **PostgreSQL.** The core creates and updates its tables on start.
- **`NOKKU_SECRET`.** At least 32 characters. It protects the CA keys at rest.
- **`NOKKU_BASE_URL`.** The public host name, like `nokku.example.com`, with the port when it is not 443. No scheme, the core is always reached over https. It ends up in links, cookies and passkeys, so pick it before you invite anyone. Passkeys are bound to the name, so it has to be a name and not an IP address, and renaming it later means everyone registers a new passkey.

### Docker Compose

`compose.prod.yml` runs the core, PostgreSQL and Caddy with automatic HTTPS.

```bash
cp .env.prod.example .env    # set NOKKU_BASE_URL to your domain, plus the values above
docker compose -f compose.prod.yml up -d
```

Point your domain at the host and open ports 80 and 443. Caddy gets the certificate by itself.

### Kubernetes

A Helm chart is in [`charts/nokku`](./charts/nokku). Its `values.yaml` lists every option.

The chart ships no default secret and no default database password. Set `secrets.secret`, or point `secrets.existingSecret` at your own, and set `postgresql.auth.password` for the bundled PostgreSQL.

### Binary

Download it from the [releases page](https://github.com/nokku-sh/nokku/releases).

```bash
export NOKKU_BASE_URL=nokku.example.com
export NOKKU_SECRET=...
export PGHOST=db.internal PGUSER=nokku PGPASSWORD=...
./nokku
```

It listens on port 3000 with plain HTTP, so put a reverse proxy in front for TLS, or let the core [serve https itself](#without-a-proxy). The proxy has to:

- forward with HTTP/2 without TLS (h2c), because `nk` and `nokkud` speak gRPC
- allow WebSockets, for the terminal in the browser

The [Caddyfile](./Caddyfile) is a working example. Set `NOKKU_TRUSTED_PROXIES` to the proxy's address, or the audit log shows the proxy as the source of every request.

### Without a proxy

For a test or a home lab the core can serve https by itself:

```bash
export NOKKU_TLS=internal
export NOKKU_BASE_URL=nokku.lan:3000
```

The core makes a CA of its own and issues its certificate from it. There is nothing to renew by hand. The CA key is stored encrypted in the database. The CA can only sign for the host name in `NOKKU_BASE_URL`, so a machine that installs it trusts it for Nokku and nothing else. Leave `NOKKU_TRUSTED_PROXIES` unset.

No machine knows that CA at first. The start log shows its pin. The web app shows it too: the full `nk login` command is under **Profile, Security**, and the bare pin under **Settings**. Before your first sign-in, run this on your own machine with the pin from the log:

```bash
nk --api https://nokku.lan:3000 --pin sha256:... login
```

`nk` checks the CA against the pin and offers to install it for your browser. After that the sign-in link from the log opens without a warning. A passkey does not work on a page with a certificate warning, so the browser needs that step.

Anything beyond a test belongs behind a reverse proxy. You can move there later without touching a client, as long as the address stays the same, host and port. A certificate from Let's Encrypt at the proxy is accepted by every `nk` and `nokkud` that pinned the built-in CA.

### A proxy with a certificate from your own CA

When the proxy's certificate comes from a private CA, like a company CA or Caddy's `tls internal`, machines that do not have that CA refuse the connection. Give the core the CA certificate and it hands out a pin:

```bash
export NOKKU_TLS_CA=/etc/nokku/company-ca.pem   # the certificate only, never the key
```

The web app then adds the pin to the commands it shows: `nk login --pin sha256:...` under **Profile, Security**, and `NOKKUD_API_PIN=sha256:...` in the enroll commands under **Infrastructure, Daemons**. Each tool fetches the CA from `/ca.crt`, checks it against the pin, and keeps it. `nk` also offers to install it into the system trust store for the browser.

When that CA is replaced one day, give the tools the new one with `nk --ca-file` and `NOKKUD_CA_FILE`.

## Connect a server and your terminal

Both tools talk to the hosted service unless told otherwise. Point them at your core once:

```bash
nk --api https://nokku.example.com login
sudo nokkud --api https://nokku.example.com enroll
```

The web app shows the exact commands, with a token, under **Infrastructure, Daemons**.

## Configuration

Everything is set with environment variables. Most installs only touch these:

| Variable                                          | Purpose                                                              |
| ------------------------------------------------- | -------------------------------------------------------------------- |
| `NOKKU_SECRET`                                    | **Required.** At least 32 characters                                 |
| `NOKKU_BASE_URL`                                  | Public host name, with the port if the proxy uses an unusual one     |
| `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`    | Where PostgreSQL is                                                  |
| `NOKKU_ADMIN_EMAIL`                               | Creates the owner account on the first start                         |
| `NOKKU_TRUSTED_PROXIES`                           | Your reverse proxy, as IPs or CIDRs                                  |
| `NOKKU_SMTP_HOST`, `NOKKU_EMAIL_SENDER`           | Turns on email sign-in links and mailed invitations                  |

The rest is below, grouped by topic. Open what you need.

<details>
<summary><b>Core</b></summary>

| Variable                | Default                 | Purpose                                                              |
| ----------------------- | ----------------------- | -------------------------------------------------------------------- |
| `NOKKU_SECRET`          |                         | **Required**, at least 32 characters                                 |
| `NOKKU_BASE_URL`        | `localhost:3000`        | Public host name, for links, cookies and passkeys. Never an IP       |
| `NOKKU_TLS`             |                         | `internal` serves https with a built-in CA. Unset behind a proxy     |
| `NOKKU_TLS_CA`          |                         | PEM file with the private CA of your proxy, so `nk` and `nokkud` can pin it |
| `NOKKU_PORT`            | `3000`                  | Port the core listens on                                             |
| `NOKKU_TRUSTED_PROXIES` |                         | Comma-separated proxy IPs or CIDRs whose client-IP headers count     |
| `NOKKU_DEBUG`           | `false`                 | Debug logging, same as `--debug`                                     |
| `NOKKU_LICENSE_KEY`     |                         | License key. It can also be activated in the web app                 |
| `NOKKU_LICENSE_OFFLINE` | `false`                 | Never ask `license.nokku.sh` for the renewed key                     |

</details>

<details>
<summary><b>Database</b></summary>

| Variable                | Default      | Purpose                                                    |
| ----------------------- | ------------ | ---------------------------------------------------------- |
| `PGHOST`                | `localhost`  | Host                                                       |
| `PGPORT`                | `5432`       | Port                                                       |
| `PGDATABASE`            | `nokku`      | Database name                                              |
| `PGUSER`                | `postgres`   | User. It owns the schema and runs the migrations           |
| `PGPASSWORD`            | `postgres`   | Password                                                   |
| `PGSSLMODE`             | `disable`    | libpq SSL mode                                             |
| `NOKKU_DB_APP_PASSWORD` | `PGPASSWORD` | Password of the two runtime roles, set at start            |
| `NOKKU_DB_MAX_CONNS`    | `20`         | Largest pool size                                          |
| `NOKKU_DB_MIN_CONNS`    | `0`          | Smallest pool size                                         |
| `NOKKU_DB_AUTOMIGRATE`  | `true`       | Apply migrations on start. Turn off to run them yourself   |

Connect directly, or through a pooler in session mode. A pooler in transaction mode, like PgBouncer with `pool_mode = transaction`, does not work. Nokku keeps state on the connection.

</details>

<details>
<summary><b>First start: workspace, owner and sign-in providers</b></summary>

A self-hosted core is one workspace. It is created on the first start, together with the owner.

| Variable                                                                | Purpose                                                        |
| ----------------------------------------------------------------------- | -------------------------------------------------------------- |
| `NOKKU_WORKSPACE_NAME`                                                  | Name on the sign-in page. Default `Nokku`                      |
| `NOKKU_ADMIN_EMAIL`                                                     | Creates the owner while the workspace has no users             |
| `NOKKU_ADMIN_NAME`                                                      | The owner's name                                               |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`                              | Adds Google as a sign-in provider                              |
| `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID` | Adds Microsoft. The tenant must be yours, `common` is refused  |

Other OIDC providers are added in the web app.

Lost every passkey? Run `./nokku admin-link` on the server, with the same environment the server runs with. It prints a fresh sign-in link for the owner.

</details>

<details>
<summary><b>Email</b></summary>

| Variable               | Default | Purpose                                   |
| ---------------------- | ------- | ----------------------------------------- |
| `NOKKU_SMTP_HOST`      |         | SMTP relay. Mail is off while this is unset |
| `NOKKU_SMTP_PORT`      | `587`   | 465 is implicit TLS, 587 is STARTTLS      |
| `NOKKU_SMTP_USERNAME`  |         | Username                                  |
| `NOKKU_SMTP_PASSWORD`  |         | Password. A login the relay rejects fails the start |
| `NOKKU_EMAIL_SENDER`   |         | From address, required with SMTP          |
| `NOKKU_EMAIL_COOLDOWN` | `15m`   | Wait between two mails of the same kind to one person |

Any SMTP relay works. Without email, people sign in with passkeys or an identity provider, and invitations are links you hand over yourself.

</details>

<details>
<summary><b>File storage</b></summary>

Avatars and session recordings go to a local folder by default. Recordings are encrypted before they are stored, whichever you pick.

| Variable                     | Default        | Purpose                                         |
| ---------------------------- | -------------- | ----------------------------------------------- |
| `NOKKU_STORAGE`              | `local`        | `local` or `s3`                                 |
| `NOKKU_LOCAL_STORAGE_PATH`   | `data`         | Folder for local storage                        |
| `NOKKU_S3_ENDPOINT`          |                | Any S3-compatible endpoint                      |
| `NOKKU_S3_ACCESS_KEY_ID`     |                | Access key                                      |
| `NOKKU_S3_SECRET_ACCESS_KEY` |                | Secret key                                      |
| `NOKKU_S3_BUCKET`            | `nokku-assets` | Bucket                                          |
| `NOKKU_S3_REGION`            | `auto`         | Region                                          |
| `NOKKU_S3_USE_PATH_STYLE`    | `false`        | Path-style addressing, for MinIO                |
| `NOKKU_S3_PUBLIC_URL`        |                | Public base URL, to serve avatars from the bucket |

Read [the note on bucket permissions](./SECURITY.md#file-storage) before you set `NOKKU_S3_PUBLIC_URL`.

</details>

<details>
<summary><b>Operator details</b></summary>

Who runs this server. The web app footer, the sign-up consent line and the email footer show what you set and leave out the rest.

| Variable                       | Purpose                                       |
| ------------------------------ | --------------------------------------------- |
| `NOKKU_OPERATOR_NAME`          | Company name in the copyright line and emails |
| `NOKKU_OPERATOR_ADDRESS`       | Postal address in the email footer            |
| `NOKKU_OPERATOR_SUPPORT_EMAIL` | Support contact in emails and the sidebar     |
| `NOKKU_OPERATOR_WEBSITE_URL`   | Website link                                  |
| `NOKKU_OPERATOR_TERMS_URL`     | Terms, also shown where accounts are created  |
| `NOKKU_OPERATOR_PRIVACY_URL`   | Privacy policy                                |
| `NOKKU_OPERATOR_IMPRINT_URL`   | Imprint                                       |

</details>

<details>
<summary><b>Telemetry</b></summary>

The log only carries warnings and errors. Traces, metrics and request logs go to your collector.

| Variable                      | Purpose                                                              |
| ----------------------------- | -------------------------------------------------------------------- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Turns on OTLP export of traces, metrics and logs                     |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` by default, `grpc` for a collector that expects gRPC |
| `OTEL_EXPORTER_OTLP_HEADERS`  | Extra headers for the exporter                                       |
| `OTEL_TRACES_SAMPLER`         | Every request is traced by default, see below for a share            |

The other standard `OTEL_*` variables work too. To trace one request in ten, set `OTEL_TRACES_SAMPLER=parentbased_traceidratio` and `OTEL_TRACES_SAMPLER_ARG=0.1`.

</details>

Three things live in [SECURITY.md](./SECURITY.md#running-nokku-securely) instead: key management with a KMS, rotating the secret, and `NOKKU_ALLOW_PRIVATE_NETWORKS`, which you need when your identity provider or SIEM is on a private address.

## Before you go live

- **Back up PostgreSQL and `NOKKU_SECRET` together.** The database holds the encrypted CA keys and the secret unlocks them. Losing the secret means losing the CAs.
- **Run one instance.** The core keeps daemon connections, relays and half-finished sign-ins in memory. A restart ends open browser terminals and sign-ins in progress.
- **Set up email**, or make sure everyone has a passkey or an identity provider.
- **Watch `/healthz`.** It answers while the core is up.
- **Read [SECURITY.md](./SECURITY.md#running-nokku-securely)** for the settings worth a second look.

## Plans

Nokku has three plans: Community (free), Pro and Enterprise. What each includes is on the [pricing page](https://nokku.sh/pricing).

A self-hosted core starts on Community. A license key unlocks the rest. Activate it in the web app under **Settings, Billing**, or set `NOKKU_LICENSE_KEY`. Keys are checked offline, so this works without internet access. An expired key never stops the core.

A core that holds a key asks `license.nokku.sh` once a day for the renewed one. It sends the key and nothing else. A core without a key never asks. Set `NOKKU_LICENSE_OFFLINE=true` to turn it off and paste the renewed key yourself.

## More

- [Documentation](https://nokku.sh/docs), with guides for servers, access, SSO and certificates
- [SECURITY.md](./SECURITY.md), for hardening and for reporting a vulnerability
- [CONTRIBUTING.md](./CONTRIBUTING.md), for building from source

<p align="center">
    <picture>
        <source media="(prefers-color-scheme: light)" srcset="../.github/nokku_dark.svg">
        <source media="(prefers-color-scheme: dark)" srcset="../.github/nokku_light.svg">
        <img src="../.github/nokku_light.svg" width="80">
    </picture>
</p>

<p align="center">
  <a href="https://github.com/nokku-sh/nokku/releases"><img src="https://img.shields.io/github/v/tag/nokku-sh/nokku?label=Version" alt="Version"></a>
  <a href="https://github.com/nokku-sh/nokku/actions"><img src="https://img.shields.io/github/actions/workflow/status/nokku-sh/nokku/ci.yaml?branch=main&label=Build" alt="Build"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-FCL--1.0--ALv2-blue" alt="License"></a>
</p>

# Nokku core

The core decides who may log in to which server, and signs short-lived SSH certificates for exactly that. It is one Go binary with the API, the web app and the certificate authority. It needs PostgreSQL and nothing else.

| Part       | Folder                | What it does                                         |
| ---------- | --------------------- | ---------------------------------------------------- |
| **Core**   | `core` (this one)     | Users, access, the CA, SSO, audit log, web app       |
| **Daemon** | [`daemon`](../daemon) | Runs on a server and keeps its SSH access in sync    |
| **CLI**    | [`cli`](../cli)       | Signs you in on your machine, then plain `ssh` works |

## Quick start

Try it on your machine with Docker:

```bash
git clone https://github.com/nokku-sh/nokku && cd nokku/core
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
docker compose -f compose.min.yml exec nokku nokku admin-link
```

Open the link and you are signed in as the owner. There is no password. Add a passkey on your profile, and the dashboard walks you through your first server.

## What it does

- Keeps your people, teams, service accounts and who may log in where.
- Signs a short-lived SSH certificate for one person, one server and the accounts they were granted.
- Keeps every daemon's access list in sync, and relays SSH to servers behind NAT. The relay can't read sessions.
- Serves the web app, with a terminal in the browser, the audit log and session recordings.
- Is not needed for a login. Servers check logins on their own, so a short outage locks nobody out. A new certificate and the relay do need it.

## Deploy

You need three things:

- **PostgreSQL 18 or newer.** The core creates and updates its tables on start.
- **`NOKKU_SECRET`**, at least 32 characters. It protects the CA keys at rest. With a [KMS](./SECURITY.md#using-a-kms), set `KMS_URI` instead.
- **`NOKKU_BASE_URL`**, the public host name, like `nokku.example.com`. No scheme, add the port only when it is not 443. Passkeys are bound to it, so it must be a name, not an IP address. Pick it before you invite anyone.

**Docker Compose.** `compose.prod.yml` runs the core, PostgreSQL and Caddy with automatic HTTPS. Point your domain at the host, open ports 80 and 443, and run:

```bash
docker compose -f compose.prod.yml up -d
```

**Kubernetes.** There is no chart. Run one replica with the `Recreate` strategy, a volume or bucket for recordings, and a PostgreSQL of your own. Let only your ingress reach the core, see [Client addresses](#client-addresses).

**Binary.** Download it from the [releases page](https://github.com/nokku-sh/nokku/releases) and run it under something that restarts it, like systemd:

```bash
export NOKKU_BASE_URL=nokku.example.com NOKKU_SECRET=...
export PGHOST=db.internal PGUSER=nokku PGPASSWORD=...
./nokku
```

The core listens on port 3000 and speaks plain HTTP. Put a reverse proxy in front that:

- holds the TLS certificate and sends `X-Forwarded-Proto`
- forwards with HTTP/2 without TLS (h2c), because `nk` and `nokkud` speak gRPC
- allows WebSockets, for the terminal in the browser

The [Caddyfile](./Caddyfile) is a working example. No domain? See [Without a domain](#without-a-domain).

## Connect a server and your terminal

`nk` and `nokkud` talk to the hosted service unless told otherwise. Point them at your core once:

```bash
nk --api https://nokku.example.com login
sudo nokkud --api https://nokku.example.com enroll
```

The web app shows these commands with a token when you enroll servers on the **Servers** page. If your proxy's certificate comes from a private CA, pass it with `--ca-file` to `nk` and `NOKKUD_CA_FILE` to `nokkud`. Both keep it.

## Before you go live

- **Back up PostgreSQL, the recordings storage and `NOKKU_SECRET` together.** One is no use without the others. Losing the secret means losing the CA. With a KMS, its key takes the place of the secret.
- **Run one instance.** The core keeps connections in memory. A restart ends browser terminals and relayed sessions. Direct `ssh` is untouched.
- **Set up email**, or make sure everyone has a passkey or an identity provider.
- **Watch `/healthz`.** It answers once the core is fully up.
- **Pin the image version** and back up before an upgrade. A restore undoes every revoke made after the backup, so check access after one. See [Upgrade and restore](#upgrade-and-restore).
- **Read [SECURITY.md](./SECURITY.md#running-nokku-securely)** for the settings worth a second look.

## Reference

### Configuration

Everything is set with environment variables. Most installs only touch these:

| Variable                                       | Purpose                                                      |
| ---------------------------------------------- | ------------------------------------------------------------ |
| `NOKKU_SECRET`                                 | **Required** without `KMS_URI`. At least 32 characters       |
| `NOKKU_BASE_URL`                               | Public host name, with the port when it is not 443           |
| `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` | Where PostgreSQL is                                          |
| `NOKKU_ADMIN_EMAIL`                            | Creates the owner account                                    |
| `NOKKU_TRUSTED_PROXIES`                        | Your reverse proxies as IPs or CIDRs, to tighten the default |
| `NOKKU_SMTP_HOST`, `NOKKU_EMAIL_SENDER`        | Turns on email sign-in links and mailed invitations          |

The rest, grouped by topic. Key management, rotating the secret and `NOKKU_ALLOW_PRIVATE_NETWORKS` are in [SECURITY.md](./SECURITY.md#running-nokku-securely).

<details>
<summary><b>Core</b></summary>

| Variable                | Default              | Purpose                                                                                     |
| ----------------------- | -------------------- | ------------------------------------------------------------------------------------------- |
| `NOKKU_SECRET`          |                      | **Required** without `KMS_URI`, at least 32 characters                                      |
| `NOKKU_BASE_URL`        | `localhost` and port | Public host name, for links, cookies and passkeys. Never an IP                              |
| `NOKKU_PORT`            | `3000`               | Port the core listens on, plain HTTP for the reverse proxy                                  |
| `NOKKU_TRUSTED_PROXIES` | private networks     | Comma-separated proxy IPs or CIDRs that may name the client, see [below](#client-addresses) |
| `NOKKU_DEBUG`           | `false`              | Debug logging, same as `--debug`                                                            |
| `NOKKU_LICENSE_KEY`     |                      | License key. It can also be activated in the web app                                        |
| `NOKKU_LICENSE_OFFLINE` | `false`              | Never ask `license.nokku.sh` for the renewed key                                            |

</details>

<details>
<summary><b>Database</b></summary>

| Variable             | Default     | Purpose                                          |
| -------------------- | ----------- | ------------------------------------------------ |
| `PGHOST`             | `localhost` | Host                                             |
| `PGPORT`             | `5432`      | Port                                             |
| `PGDATABASE`         | `nokku`     | Database name                                    |
| `PGUSER`             | `postgres`  | User. It owns the schema and runs the migrations |
| `PGPASSWORD`         | `postgres`  | Password                                         |
| `PGSSLMODE`          | `disable`   | libpq SSL mode                                   |
| `NOKKU_DB_MAX_CONNS` | `20`        | Largest pool size                                |

`PGUSER` is the only user you create. On start the core makes two more roles for itself, `nokku_app` and `nokku_system`, and gives them the same password. The user of the official PostgreSQL image is a superuser and just works. A user you create yourself needs to own the database and have `CREATEROLE` and `BYPASSRLS`:

```sql
CREATE ROLE nokku LOGIN PASSWORD '...' CREATEROLE BYPASSRLS;
CREATE DATABASE nokku OWNER nokku;
```

Connect directly, or through a pooler in session mode. A pooler in transaction mode, like PgBouncer with `pool_mode = transaction`, does not work. Nokku keeps state on the connection.

When the database is gone for more than a minute the core exits, so run it under something that restarts it.

</details>

<details>
<summary><b>Workspace, owner and sign-in providers</b></summary>

A self-hosted core is one workspace, created on the first start. The owner is created on any start that finds none.

| Variable                                                                | Purpose                                                                                   |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `NOKKU_WORKSPACE_NAME`                                                  | Name on the sign-in page. Default `Nokku`                                                 |
| `NOKKU_ADMIN_EMAIL`                                                     | Creates the owner while the workspace has none                                            |
| `NOKKU_ADMIN_NAME`                                                      | The owner's name                                                                          |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`                              | Adds Google for existing users. New accounts need an invite                               |
| `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID` | Adds Microsoft for your tenant, `common` is refused. Anyone in the tenant gets an account |

Other OIDC providers are added in the web app.

`nokku admin-link` prints a fresh sign-in link for the owner whenever you run it, with the same environment the server runs with. It replaces the links before and works even when single sign-on is required. The log reminds you to run it until the owner has a passkey or a linked provider, but never logs the link itself. [SECURITY.md](./SECURITY.md#the-owner-account) lists every way into the owner account.

</details>

<details>
<summary><b>Email</b></summary>

| Variable              | Default | Purpose                                             |
| --------------------- | ------- | --------------------------------------------------- |
| `NOKKU_SMTP_HOST`     |         | SMTP relay. Mail is off while this is unset         |
| `NOKKU_SMTP_PORT`     | `587`   | 465 is implicit TLS, 587 is STARTTLS                |
| `NOKKU_SMTP_USERNAME` |         | Username                                            |
| `NOKKU_SMTP_PASSWORD` |         | Password. A login the relay rejects fails the start |
| `NOKKU_EMAIL_SENDER`  |         | From address, required with SMTP                    |

Any SMTP relay works. Without email, people sign in with passkeys or an identity provider. Invites still work: an admin gets the invite link to hand over, and vouches for whoever opens it.

</details>

<details>
<summary><b>File storage</b></summary>

Session recordings go to a local folder by default. They are encrypted before they are stored, wherever that is.

| Variable                | Default         | Purpose                                   |
| ----------------------- | --------------- | ----------------------------------------- |
| `NOKKU_STORAGE_URL`     | `file://./data` | Where recordings go, a folder or a bucket |
| `AWS_ACCESS_KEY_ID`     |                 | S3 access key, with an `s3://` URL        |
| `AWS_SECRET_ACCESS_KEY` |                 | S3 secret key                             |

- **A folder** is `file:///var/lib/nokku/recordings`, created when it is missing. The image runs as user 65532, so that user must own it.
- **A bucket** is `s3://nokku?region=auto&endpoint=https%3A%2F%2Fs3.example.com&use_path_style=true`. Leave out `endpoint` for AWS itself, `use_path_style` is for MinIO. The URL takes the parameters of [gocloud's S3 driver](https://gocloud.dev/howto/blob/#s3).
- **Stores other than AWS** often want `request_checksum_calculation=when_required`. On Scaleway that is `s3://nokku?region=fr-par&endpoint=https%3A%2F%2Fs3.fr-par.scw.cloud&request_checksum_calculation=when_required`.
- **Startup.** The core starts while a bucket can't be reached and logs a warning, daemons keep their recordings until it is back. A bucket that refuses the credentials stops the start.
- **Lifecycle rules.** Add two on `videos/`: expire objects after 400 days, longer than any recording is kept, and abort incomplete multipart uploads after a few days. The core deletes recordings itself, these only catch what a crash leaves behind.

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

The log stays quiet: a line at start, then warnings and errors. Traces, metrics and the warnings go to your collector.

| Variable                      | Purpose                                               |
| ----------------------------- | ----------------------------------------------------- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Turns on OTLP export of traces, metrics and logs      |
| `OTEL_EXPORTER_OTLP_HEADERS`  | Extra headers for the exporter                        |
| `OTEL_TRACES_SAMPLER`         | Requests are traced by default, see below for a share |

The other standard `OTEL_*` variables work too. To trace one request in ten, set `OTEL_TRACES_SAMPLER=parentbased_traceidratio` and `OTEL_TRACES_SAMPLER_ARG=0.1`.

</details>

### Client addresses

Nokku takes the client's address from `X-Forwarded-For`. By default it trusts a proxy on the same machine or on a private network, like a Docker network or a cluster's pod network. Docker and Kubernetes need nothing set.

That address goes into the audit log, rate limits and sign-in mails, and a certificate's `source-address` is checked against it. So **let only the proxy reach port 3000**: keep the port on the proxy's Docker network, as `compose.prod.yml` does, or use a NetworkPolicy in a cluster.

<details>
<summary><b>When to set <code>NOKKU_TRUSTED_PROXIES</code></b></summary>

Set it to your proxies, as IPs or CIDRs. It replaces the default, and only those may name the client. Set it when:

- you want only your proxy trusted, not every private address
- your proxy reaches Nokku from a public address, like a Docker network or cluster on public IPv6, or from `100.64.0.0/10` like over Tailscale
- more than one proxy sits in front, like a CDN or a cloud load balancer before your ingress

Behind more than one proxy, your own proxy has to trust the outer one too, or it drops the client address. That is `trusted_proxies` in Caddy and `forwardedHeaders.trustedIPs` in Traefik. Then list all of them here, the CDN's published ranges and your own proxy too. In Docker, give the proxy's network a fixed subnet and list that. In a cluster, list the pod network.

A wrong setting does not stop Nokku from working. It gets addresses wrong:

| Setting                                                               | What happens                                                                                                                                                                  |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Your proxy is not trusted                                             | Every client shows up as the proxy. They all share one rate limit, and a `source-address` on a certificate refuses browser and relayed sessions. The core logs a warning once |
| A CDN or load balancer in front is not trusted, here or by your proxy | Every client shows up as the CDN, the load balancer or your proxy, with the same effects                                                                                      |
| The list covers your users too, like `10.0.0.0/8` with users in it    | They are taken for proxies. They show up as your proxy, or behind a proxy that keeps what the client sent, like plain nginx, they can claim any address                       |

</details>

<details>
<summary><b>Traefik, in Docker and Kubernetes</b></summary>

Traefik sends `X-Forwarded-Proto` and `X-Forwarded-For` by itself, and drops those headers when a client sends them, as long as `forwardedHeaders.insecure` stays off on the entrypoint. Leave it off, unless another proxy you control sits in front.

**Docker.** Put Traefik and Nokku on one network and keep anything else off it:

```yaml
networks:
  proxy:

services:
  nokku:
    networks: [proxy]
    labels:
      traefik.enable: "true"
      traefik.http.routers.nokku.rule: Host(`nokku.example.com`)
      traefik.http.routers.nokku.tls.certresolver: letsencrypt
      traefik.http.services.nokku.loadbalancer.server.port: "3000"
      traefik.http.services.nokku.loadbalancer.server.scheme: h2c
```

**Kubernetes.** Nokku sees the Traefik pod's address, which is trusted as it is. Every other pod is on that network too, so let only Traefik reach Nokku with a NetworkPolicy. It needs a network plugin that enforces policies.

- Name the namespace Traefik runs in, or the one a gateway's proxy pods run in. A wrong one cuts Nokku off, and Traefik answers 502 or 504.
- Anything else that calls Nokku directly, like a scraper, needs a rule of its own. Health probes come from the node, most plugins let them through.
- A controller on the host network, common for ingress-nginx on bare metal, comes from the node's address. Add the nodes as an `ipBlock`, if your plugin matches node addresses that way.
- Cilium's own ingress and gateway reach pods as Cilium's `ingress` identity, which a NetworkPolicy cannot name. Use a CiliumNetworkPolicy there.
- Annotate the Service with `traefik.ingress.kubernetes.io/service.serversscheme: h2c`.
- Traefik only sees real client addresses when its own Service keeps them, with `externalTrafficPolicy: Local` on a LoadBalancer or NodePort.

</details>

### Without a domain

To try Nokku on other machines without a domain, `compose.min.yml` runs Caddy with a CA of its own. Give the host a name every machine resolves, through DNS, the router or `/etc/hosts`, and leave out the port:

```bash
NOKKU_BASE_URL=nokku.lan
```

Start it, copy Caddy's root certificate out, and give it to every machine that talks to Nokku:

```bash
docker compose -f compose.min.yml up -d
docker compose -f compose.min.yml cp caddy:/data/caddy/pki/authorities/local/root.crt nokku-ca.crt

nk --api https://nokku.lan --ca-file nokku-ca.crt login
sudo NOKKUD_API_URL=https://nokku.lan NOKKUD_CA_FILE=nokku-ca.crt nokkud enroll
```

Both keep the CA, so this is needed once per machine. Add it to your browser too, a passkey does not work on a page with a certificate warning.

> [!WARNING]
> This is for trying Nokku out. Caddy's root can vouch for any site, not only for Nokku, and its key sits in the `caddy-data` volume. Add it only to machines you test with, and remove it afterwards. For real use, give Nokku a domain and run `compose.prod.yml`.

### Upgrade and restore

<details>
<summary><b>Upgrade</b></summary>

```bash
docker compose -f compose.prod.yml pull nokku
docker compose -f compose.prod.yml up -d --no-deps nokku
```

The pull happens while the old core still serves, and the new version is up quickly. Pin `NOKKU_IMAGE` to a version so going back means changing the tag. That only holds while the schema stays the same. An older image refuses to start on a database a newer one migrated, so back up before an upgrade and restore that backup to go back. Leave Caddy out of it, a new Caddy ends every web terminal.

</details>

<details>
<summary><b>Restore</b></summary>

Stop the core, put back the database and the storage, set the same `NOKKU_SECRET` or `KMS_URI`, and start it. Daemons reconnect and take the state they find. Everything since the backup is gone: a revoke made after it is undone, so check access first, and a server enrolled after it enrolls again.

</details>

### License key

A self-hosted core is free to run and needs no key. A license key turns on more features and raises the limits. Activate it in the web app on the **Billing** settings page, or set `NOKKU_LICENSE_KEY`. Keys are checked offline, and an expired key never stops the core.

A core that holds a key asks `license.nokku.sh` for the renewed one about once a day, and again when an admin opens the **Billing** page, at most every 30 seconds. It sends the key and nothing else. A core without a key never asks. Set `NOKKU_LICENSE_OFFLINE=true` to turn it off and paste the renewed key yourself.

## More

- [Documentation](https://nokku.sh/docs), with guides for servers, access, SSO and the CA
- [SECURITY.md](./SECURITY.md), for running Nokku safely and how it is built
- [CONTRIBUTING.md](../CONTRIBUTING.md), for building from source

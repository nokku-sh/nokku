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

# Nokku

Nokku gives people short-lived SSH certificates instead of long-lived keys. You decide who may log in to which server as which account, and Nokku signs a certificate for exactly that.

This folder is the core: one Go binary with the API, the web app and the certificate authorities. It needs PostgreSQL and nothing else.

Your servers keep working when the core is down. They enforce what they last synced, and a valid certificate still logs in directly. A new certificate and a relayed connection need the core.

| Part       | Folder                | What it does                                           |
| ---------- | --------------------- | ------------------------------------------------------ |
| **Core**   | `core` (this one)     | Users, access, one CA per workspace, SSO, audit log    |
| **Daemon** | [`daemon`](../daemon) | Runs on a server and keeps its SSH access in sync      |
| **CLI**    | [`cli`](../cli)       | Signs you in on your machine, then plain `ssh` works   |

## Quick start

Try it on your machine with Docker. This runs the core on port 3000, with PostgreSQL and Caddy next to it.

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

Open the link. You are signed in as the owner. Add a passkey under **Profile, Security**, and the dashboard walks you through your first server.

There is no password. Until the owner has a passkey, `admin-link` prints a fresh link that works for 24 hours. The log only says that one is needed, so the link never ends up where your logs go.

## Deploy

All three options need the same three things:

- **PostgreSQL 18 or newer.** The core creates and updates its tables on start.
- **`NOKKU_SECRET`.** At least 32 characters. It protects the CA keys at rest. With a [KMS](./SECURITY.md#using-a-kms), set `KMS_URI` instead.
- **`NOKKU_BASE_URL`.** The public host name, like `nokku.example.com`, with the port when it is not 443. No scheme, the core is always reached over https. It ends up in links, cookies and passkeys, so pick it before you invite anyone. Passkeys are bound to the name, so it has to be a name and not an IP address, and renaming it later means everyone registers a new passkey.

### Docker Compose

`compose.prod.yml` runs the core, PostgreSQL and Caddy with automatic HTTPS.

```bash
cp .env.prod.example .env    # set NOKKU_BASE_URL to your domain, plus the values above
docker compose -f compose.prod.yml up -d
```

Point your domain at the host and open ports 80 and 443. Caddy gets the certificate by itself.

### Kubernetes

There is no chart. The image runs fine in a cluster with the settings on this page: one replica, a volume or bucket for recordings, and a PostgreSQL of your own. Stop the old pod before the new one starts, the core keeps its connections in memory, so use the `Recreate` strategy.

### Binary

Download it from the [releases page](https://github.com/nokku-sh/nokku/releases).

```bash
export NOKKU_BASE_URL=nokku.example.com
export NOKKU_SECRET=...
export PGHOST=db.internal PGUSER=nokku PGPASSWORD=...
./nokku
```

It listens on port 3000 and speaks plain HTTP only. A reverse proxy in front holds the certificate. The proxy has to:

- send `X-Forwarded-Proto`, which Caddy and Traefik do by themselves
- forward with HTTP/2 without TLS (h2c), because `nk` and `nokkud` speak gRPC
- allow WebSockets, for the terminal in the browser

The [Caddyfile](./Caddyfile) is a working example.

### Client addresses

Nokku takes the client's address from `X-Forwarded-For`. Out of the box it trusts a proxy on the same machine or on a private network, like a Docker network or the pod network of a cluster, and takes the address that proxy added. Docker and Kubernetes need nothing set.

That address goes into the audit log, sessions, sign-in mails and rate limits, and the `source-address` on a certificate is checked against it. Anything on a private network that reaches port 3000 directly could claim any address. So let only the proxy reach Nokku: keep the port on the proxy's Docker network, as `compose.prod.yml` does, or use a NetworkPolicy in a cluster.

To tighten it, set `NOKKU_TRUSTED_PROXIES` to your proxies, as IPs or CIDRs. That replaces the default, and only those may name the client. Set it when:

- you want only your proxy trusted, not every private address
- your proxy reaches Nokku from a public address, like a Docker network or cluster on public IPv6, or from `100.64.0.0/10` like over Tailscale
- more than one proxy sits in front, like a CDN or a cloud load balancer before your ingress

Behind more than one proxy, your own proxy has to trust the outer one too, or it drops the client address the outer one sent. That is `trusted_proxies` in Caddy and `forwardedHeaders.trustedIPs` in Traefik. Then list all of them here, the CDN's published ranges and your own proxy too, since the list replaces the default. In Docker, give the proxy's network a fixed subnet and list that. In a cluster, list the pod network.

A wrong setting does not stop Nokku from working. It gets addresses wrong:

| Setting                                                               | What happens                                                                                                                                                      |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Your proxy is not trusted                                             | Every client shows up as the proxy. They all share one rate limit, and a `source-address` on a certificate refuses browser and relayed sessions. The core logs a warning once |
| A CDN or load balancer in front is not trusted, here or by your proxy | Every client shows up as the CDN, the load balancer or your proxy, with the same effects                                                                          |
| The list covers your users too, like `10.0.0.0/8` with users in it    | They are taken for proxies. They show up as your proxy, or behind a proxy that keeps what the client sent, like plain nginx, they can claim any address           |

### Traefik

Traefik sends `X-Forwarded-Proto` and `X-Forwarded-For` by itself. It drops those headers when a client sends them, as long as you leave `forwardedHeaders.insecure` off on the entrypoint. Leave it off, unless another proxy you control sits in front.

**Docker.** Put Traefik and Nokku on one network and keep anything else off it. Nothing else to set.

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

**Kubernetes.** Nokku sees the address of the Traefik pod. It is on the pod network, so it is trusted as it is. Every other pod is on that network too, so let only Traefik reach Nokku with a NetworkPolicy. It needs a network plugin that enforces policies.

Name the namespace Traefik runs in. A wrong one cuts Nokku off, and Traefik answers 502 or 504. The same works with a gateway: name the namespace its proxy pods run in. Anything else in the cluster that calls Nokku directly, like a scraper, needs a rule of its own. The health probes come from the node, most plugins let them through.

Two setups need more than a namespace. A controller on the host network, common for ingress-nginx on bare metal, comes from the node's address. Add the nodes as an `ipBlock`, if your plugin matches node addresses that way. Cilium's own ingress and gateway reach pods as Cilium's `ingress` identity, which a NetworkPolicy cannot name. Use a CiliumNetworkPolicy there.

Traefik has to speak h2c to Nokku, so annotate the Service with `traefik.ingress.kubernetes.io/service.serversscheme: h2c`.

Traefik only sees real client addresses when its own Service keeps them, with `externalTrafficPolicy: Local` on a LoadBalancer or NodePort. Otherwise every client shows up as a node address.

### Without a domain

To try Nokku on other machines without a domain, `compose.min.yml` runs Caddy with a CA of its own, `tls internal`. Give the host a name that every machine resolves, through DNS, the router or `/etc/hosts`, and leave out the port:

```bash
NOKKU_BASE_URL=nokku.lan
```

Start it and copy Caddy's root certificate out of the container:

```bash
docker compose -f compose.min.yml up -d
docker compose -f compose.min.yml cp caddy:/data/caddy/pki/authorities/local/root.crt nokku-ca.crt
```

Give that file to every machine that talks to Nokku:

```bash
nk --api https://nokku.lan --ca-file nokku-ca.crt login
sudo NOKKUD_API_URL=https://nokku.lan NOKKUD_CA_FILE=nokku-ca.crt nokkud enroll
```

Both keep the CA, so this is needed once per machine. Add it to your browser too, in its certificate settings or the system trust store. A passkey does not work on a page with a certificate warning.

> [!WARNING]
> This is for trying Nokku out. Caddy's root can vouch for any site, not only for Nokku, and its key sits in the `caddy-data` volume. Add it only to machines you test with, and remove it afterwards. For real use, give Nokku a domain and run `compose.prod.yml`.

### A proxy with a certificate from your own CA

When the proxy's certificate comes from a private CA, like a company CA, machines that do not have that CA refuse the connection. Give it to `nk` with `--ca-file` and to `nokkud` with `NOKKUD_CA_FILE`. Both keep it. Browsers read it from the system trust store.

## Connect a server and your terminal

Both tools talk to the hosted service unless told otherwise. Point them at your core once:

```bash
nk --api https://nokku.example.com login
sudo nokkud --api https://nokku.example.com enroll
```

The web app shows the exact commands, with a token, under **Infrastructure, Daemons**.

A CI job signs in with its platform's own token, so no secret is stored. Add a rule under **CI jobs** on a service account and run `nk login --ci <name>` in the job, see [CI and headless machines](../cli#ci-and-headless-machines). A service account key stays the answer for Ansible and scripts, and always has an end date. What the exchange checks is in [SECURITY.md](./SECURITY.md#what-to-know-about-the-design).

## Configuration

Everything is set with environment variables. Most installs only touch these:

| Variable                                       | Purpose                                                          |
| ---------------------------------------------- | ---------------------------------------------------------------- |
| `NOKKU_SECRET`                                 | **Required** without `KMS_URI`. At least 32 characters           |
| `NOKKU_BASE_URL`                               | Public host name, with the port if the proxy uses an unusual one |
| `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` | Where PostgreSQL is                                              |
| `NOKKU_ADMIN_EMAIL`                            | Creates the owner account on the first start                     |
| `NOKKU_TRUSTED_PROXIES`                        | Your reverse proxies as IPs or CIDRs, to tighten the default     |
| `NOKKU_SMTP_HOST`, `NOKKU_EMAIL_SENDER`        | Turns on email sign-in links and mailed invitations              |

The rest is below, grouped by topic. Open what you need.

<details>
<summary><b>Core</b></summary>

| Variable                | Default          | Purpose                                                                         |
| ----------------------- | ---------------- | ------------------------------------------------------------------------------- |
| `NOKKU_SECRET`          |                  | **Required** without `KMS_URI`, at least 32 characters                          |
| `NOKKU_BASE_URL`        | `localhost:3000` | Public host name, for links, cookies and passkeys. Never an IP                  |
| `NOKKU_PORT`            | `3000`           | Port the core listens on, plain HTTP for the reverse proxy                      |
| `NOKKU_TRUSTED_PROXIES` | private networks | Comma-separated proxy IPs or CIDRs that may name the client, see above          |
| `NOKKU_DEBUG`           | `false`          | Debug logging, same as `--debug`                                                |
| `NOKKU_LICENSE_KEY`     |                  | License key. It can also be activated in the web app                            |
| `NOKKU_LICENSE_OFFLINE` | `false`          | Never ask `license.nokku.sh` for the renewed key                                |

</details>

<details>
<summary><b>Database</b></summary>

| Variable                | Default      | Purpose                                                  |
| ----------------------- | ------------ | -------------------------------------------------------- |
| `PGHOST`                | `localhost`  | Host                                                     |
| `PGPORT`                | `5432`       | Port                                                     |
| `PGDATABASE`            | `nokku`      | Database name                                            |
| `PGUSER`                | `postgres`   | User. It owns the schema and runs the migrations         |
| `PGPASSWORD`            | `postgres`   | Password                                                 |
| `PGSSLMODE`             | `disable`    | libpq SSL mode                                           |
| `NOKKU_DB_APP_PASSWORD` | `PGPASSWORD` | Password of the two runtime roles, set at start          |
| `NOKKU_DB_MAX_CONNS`    | `20`         | Largest pool size                                        |

Connect directly, or through a pooler in session mode. A pooler in transaction mode, like PgBouncer with `pool_mode = transaction`, does not work. Nokku keeps state on the connection.

</details>

<details>
<summary><b>First start: workspace, owner and sign-in providers</b></summary>

A self-hosted core is one workspace. It is created on the first start, together with the owner.

| Variable                                                                | Purpose                                                       |
| ----------------------------------------------------------------------- | ------------------------------------------------------------- |
| `NOKKU_WORKSPACE_NAME`                                                  | Name on the sign-in page. Default `Nokku`                     |
| `NOKKU_ADMIN_EMAIL`                                                     | Creates the owner while the workspace has no users            |
| `NOKKU_ADMIN_NAME`                                                      | The owner's name                                              |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`                              | Adds Google for existing users. New accounts need an invite   |
| `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID` | Adds Microsoft. The tenant must be yours, `common` is refused |

Other OIDC providers are added in the web app.

Lost every passkey? Run `./nokku admin-link` on the server, with the same environment the server runs with, or `docker compose exec nokku nokku admin-link`. It prints a fresh sign-in link for the owner. The link works even when single sign-on is required, see [SECURITY.md](./SECURITY.md#the-owner-account) for every way into the owner account.

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

Any SMTP relay works. Without email, people sign in with passkeys or an identity provider. Invites still work: an admin gets the invite link to hand over instead of Nokku mailing it, and vouches for whoever opens it.

</details>

<details>
<summary><b>File storage</b></summary>

Session recordings go to a local folder by default. They are encrypted before they are stored, wherever that is.

| Variable                | Default         | Purpose                                   |
| ----------------------- | --------------- | ----------------------------------------- |
| `NOKKU_STORAGE_URL`     | `file://./data` | Where recordings go, a folder or a bucket |
| `AWS_ACCESS_KEY_ID`     |                 | S3 access key, with an `s3://` URL        |
| `AWS_SECRET_ACCESS_KEY` |                 | S3 secret key                             |

A folder is `file:///var/lib/nokku/recordings`, created when it is missing. The image runs as user 65532, so that user must own the folder. The core starts while a bucket can't be reached and logs a warning, daemons keep their recordings until it is back. A bucket that refuses the credentials stops the start. A bucket is `s3://nokku?region=auto&endpoint=https%3A%2F%2Fs3.example.com&use_path_style=true`. Leave out `endpoint` for AWS itself, `use_path_style` is for MinIO. The URL takes the parameters of [gocloud's S3 driver](https://gocloud.dev/howto/blob/#s3).

Stores other than AWS often want `request_checksum_calculation=when_required`, which leaves out the checksums newer AWS SDKs add by default. Recordings are authenticated by their encryption either way. On Scaleway Object Storage that is `s3://nokku?region=fr-par&endpoint=https%3A%2F%2Fs3.fr-par.scw.cloud&request_checksum_calculation=when_required`, with an API key in `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

On a bucket, add two lifecycle rules on `videos/`: expire objects after 400 days, past the longest retention of 365 days, and abort incomplete multipart uploads after 7 days. The core deletes recordings itself, these only catch what a crash leaves behind, which is also an object no row names yet. Raise the 400 if a plan ever keeps recordings longer. Check that your store really applies the abort rule, recordings over 16 MiB go up as multipart.

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
| `OTEL_EXPORTER_OTLP_HEADERS`  | Extra headers for the exporter                                       |
| `OTEL_TRACES_SAMPLER`         | Every request is traced by default, see below for a share            |

The other standard `OTEL_*` variables work too. To trace one request in ten, set `OTEL_TRACES_SAMPLER=parentbased_traceidratio` and `OTEL_TRACES_SAMPLER_ARG=0.1`.

</details>

Three things live in [SECURITY.md](./SECURITY.md#running-nokku-securely) instead: key management with a KMS, rotating the secret, and `NOKKU_ALLOW_PRIVATE_NETWORKS`, which you need when your identity provider is on a private address.

## Before you go live

- **Back up PostgreSQL, `NOKKU_STORAGE_URL` and `NOKKU_SECRET` together.** The database holds the encrypted CA keys and the secret unlocks them. Losing the secret means losing the CAs. With `KMS_URI`, the KMS key takes the place of the secret. Recordings live in the storage, and their keys live in the database, so one is no use without the other.
- **Know how to restore.** Stop the core, put back the database and the storage, set the same `NOKKU_SECRET` or `KMS_URI`, and start it. Daemons reconnect and take the state they find. Everything since the backup is gone: a revoke made after it is undone, so check access first, and a server enrolled after it enrolls again.
- **Run one instance.** The core keeps daemon connections, relays and half-finished sign-ins in memory. A restart ends open browser terminals, relayed `nk` sessions and sign-ins in progress. A direct `ssh` is untouched. People stay signed in and daemons reconnect by themselves.
- **Set up email**, or make sure everyone has a passkey or an identity provider.
- **Watch `/healthz`.** It answers while the core is up, and only once it has fully started.
- **Deploy with `docker compose pull nokku`, then `docker compose up -d --no-deps nokku`.** The pull then happens while the old core still serves, and a new version is up in about a second. Pin `NOKKU_IMAGE` to a version so going back means changing the tag. That only holds while the schema stays the same. An older image refuses to start on a database a newer one migrated, so back up before an upgrade and restore that backup to go back. Leave Caddy out of it, a new Caddy ends every web terminal.
- **Read [SECURITY.md](./SECURITY.md#running-nokku-securely)** for the settings worth a second look.

## Plans

Nokku has three plans: Community (free), Pro and Enterprise. What each includes is on the [pricing page](https://nokku.sh/pricing).

Community is self-hosted only, for up to 5 members with no cap on servers or recording storage. Hosted Nokku has no free plan, a workspace starts on a 30 day trial of Pro and then needs a subscription.

A self-hosted core starts on Community. A license key unlocks the rest. Activate it in the web app under **Settings, Billing**, or set `NOKKU_LICENSE_KEY`. Keys are checked offline, so this works without internet access. An expired key never stops the core.

A core that holds a key asks `license.nokku.sh` once a day for the renewed one. It sends the key and nothing else. A core without a key never asks. Set `NOKKU_LICENSE_OFFLINE=true` to turn it off and paste the renewed key yourself.

## More

- [Documentation](https://nokku.sh/docs), with guides for servers, access, SSO and certificates
- [SECURITY.md](./SECURITY.md), for hardening and for reporting a vulnerability
- [CONTRIBUTING.md](../CONTRIBUTING.md), for building from source

<p align="center">
    <picture>
        <source media="(prefers-color-scheme: light)" srcset="./.github/logo_dark.svg">
        <source media="(prefers-color-scheme: dark)" srcset="./.github/logo_light.svg">
        <img src="./.github/logo_light.svg" width="80">
    </picture>
</p>

<p align="center">
  <a href="https://github.com/nokku-sh/nokku/releases"><img src="https://img.shields.io/github/v/tag/nokku-sh/nokku?label=Version" alt="Version"></a>
  <a href="https://github.com/nokku-sh/nokku/actions"><img src="https://img.shields.io/github/actions/workflow/status/nokku-sh/nokku/test.yaml?branch=main&label=Build" alt="Build"></a>
  <a href="https://github.com/nokku-sh/nokku/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nokku-sh/nokku?label=License" alt="License"></a>
</p>

# Nokku: Decentralized Identity & Access Engine

Nokku is the control plane for certificate-based access to SSH targets and X.509 workloads. Unlike traditional access tools that funnel all traffic through a central proxy, Nokku utilizes a decentralized architecture. You define the policies here, and the daemons cache and enforce them at the edge—meaning if the backend goes down, your infrastructure remains fully accessible as long as certificates are valid.

## The Nokku Ecosystem

| Component  | Repository                                     | Purpose                                                         |
| ---------- | ---------------------------------------------- | --------------------------------------------------------------- |
| **Core**   | `nokku`                                        | Control plane for users, policies, CA management, and SSO/OIDC. |
| **Daemon** | [`nokkud`](https://github.com/nokku-sh/nokkud) | Server agent for SSH configuration and host certificates.       |
| **CLI**    | [`nk`](https://github.com/nokku-sh/nk)         | Workstation CLI for authentication and local SSH configuration. |

## Architecture Topology

```text
[ Developer Machine ]                    [ Nokku Backend ]                    [ Target Server ]
      (nk CLI)       ---- HTTPS/OIDC ---> (Control Plane) <--- gRPC/HTTPS ---- (nokkud Daemon)
         |                                       |                                    |
         +------------- Direct P2P SSH (Port 4022) - Bypasses Backend ----------------+

```

## Editions & Licensing

Nokku has three plans: **Community** (free), **Pro**, and **Enterprise**. What each includes and what it costs is on the [pricing page](https://nokku.sh/pricing).

The core runs in one of two modes:

- **Self-hosted** is the default. Every instance starts on Community, and an Enterprise license key unlocks the rest. Keys are Ed25519-signed and verified offline against a public key compiled directly into the binary, ensuring fully air-gapped activation.
- **SaaS** is how the hosted service runs. Each workspace gets its plan from its subscription.

A license key is activated in the UI under Billing or set as `NOKKU_LICENSE_KEY`. A renewed key applies without a restart. An expired key never stops the core: licensed features turn off, and data beyond the Community limits is kept for 30 more days.

> **For in-depth documentation, advanced configuration, and production deployment guides, please visit our [Official Documentation (Link)](https://nokku.sh/docs)**

## Build and run

```bash
./nokku
```

The backend reads configuration from environment variables. Only `NOKKU_SECRET` is mandatory; everything else has a default or belongs to the integration it configures.

### Core

| Variable                | Purpose                                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------------------- |
| `NOKKU_BASE_URL`        | Public URL, used as given for links, cookies, and WebAuthn (default `http://localhost:<NOKKU_PORT>`) |
| `NOKKU_PORT`            | Port the backend listens on (default `3000`)                                                         |
| `NOKKU_SECRET`          | **Required**, at least 32 characters. Wraps the at-rest keyset and keys the DPoP nonces              |
| `NOKKU_TRUSTED_PROXIES` | Comma-separated reverse-proxy IPs/CIDRs (e.g. Traefik) whose forwarded client-IP headers are honored |
| `NOKKU_DEBUG`           | Debug logging (`--debug`)                                                                            |
| `NOKKU_LICENSE_KEY`     | License key activating licensed self-host features. Optional, a key can also be activated in the UI  |
| `NOKKU_ALLOW_PRIVATE_NETWORKS` | Let SSO providers and audit webhooks reach private addresses (default `false`). Keep it off when hosting for other people. |

### Database (PostgreSQL, required)

| Variable                | Default     | Purpose                                                      |
| ----------------------- | ----------- | ------------------------------------------------------------ |
| `PGHOST`                | `localhost` | Database host                                                |
| `PGPORT`                | `5432`      | Database port                                                |
| `PGDATABASE`            | `nokku`     | Database name                                                |
| `PGUSER`                | `postgres`  | Database user                                                |
| `PGPASSWORD`            | `postgres`  | Database password                                            |
| `PGSSLMODE`             | `disable`   | libpq SSL mode                                               |
| `NOKKU_DB_APP_PASSWORD` | generated   | Password for the RLS-constrained app role, set on first boot |
| `NOKKU_DB_MAX_CONNS`    | `10`        | Max pool size                                                |
| `NOKKU_DB_MIN_CONNS`    | `0`         | Min pool size                                                |
| `NOKKU_DB_AUTOMIGRATE`  | `true`      | Apply embedded migrations at boot                            |

Schema migrations are embedded and applied automatically under an advisory lock; disable with `NOKKU_DB_AUTOMIGRATE=false` if you run migrations out of band.

### Single instance

Nokku runs as a single instance. Daemon control streams, relays and single-use state (DPoP replay markers, login flow state, email cooldowns, web session tickets) live in the process. A second instance would not see them, and the single-use state is lost on a restart.

### Storage (object storage, optional)

| Variable                     | Default        | Purpose                                           |
| ---------------------------- | -------------- | ------------------------------------------------- |
| `NOKKU_STORAGE`              | `local`        | `local` or `s3`                                   |
| `NOKKU_LOCAL_STORAGE_PATH`   | `data`         | Local storage directory                           |
| `NOKKU_S3_ENDPOINT`          |                | S3-compatible endpoint (Scaleway, R2, MinIO, AWS) |
| `NOKKU_S3_ACCESS_KEY_ID`     |                | S3 access key                                     |
| `NOKKU_S3_SECRET_ACCESS_KEY` |                | S3 secret key                                     |
| `NOKKU_S3_BUCKET`            | `nokku-assets` | S3 bucket                                         |
| `NOKKU_S3_REGION`            | `auto`         | S3 region                                         |
| `NOKKU_S3_USE_PATH_STYLE`    | `false`        | Path-style addressing (MinIO)                     |
| `NOKKU_S3_PUBLIC_URL`        |                | Public base URL for objects                       |

S3-compatible storage holds avatars and session recordings. Recordings are encrypted before upload regardless of the backend. With `NOKKU_S3_PUBLIC_URL` set, grant public read on the `avatars/` prefix only, never on the whole bucket, since recordings live under `videos/`.

### Email (recommended)

| Variable               | Default                   | Purpose                                  |
| ---------------------- | ------------------------- | ---------------------------------------- |
| `NOKKU_SMTP_HOST`      |                           | SMTP relay host. Mail is off when unset. |
| `NOKKU_SMTP_PORT`      | `587`                     | 465 implicit TLS, 587 STARTTLS           |
| `NOKKU_SMTP_USERNAME`  |                           | SMTP username                            |
| `NOKKU_SMTP_PASSWORD`  |                           | SMTP password                            |
| `NOKKU_EMAIL_SENDER`   |                           | Sender address, required with SMTP       |
| `NOKKU_EMAIL_COOLDOWN` | `15m`                     | Per-user, per-template cooldown          |

Any SMTP relay works, for example Scaleway TEM at `smtp.tem.scw.cloud`. Without email, password resets and verification links cannot be delivered.

### Operator details (optional)

Who runs this server. The UI footer, the signup consent line and the email footer show only what is set, so a self-hosted server shows no third-party company by default.

| Variable                       | Purpose                                     |
| ------------------------------ | ------------------------------------------- |
| `NOKKU_OPERATOR_NAME`          | Company name in the copyright and emails    |
| `NOKKU_OPERATOR_ADDRESS`       | Postal address in the email footer          |
| `NOKKU_OPERATOR_SUPPORT_EMAIL` | Support contact in emails and the sidebar   |
| `NOKKU_OPERATOR_WEBSITE_URL`   | Website link                                |
| `NOKKU_OPERATOR_TERMS_URL`     | Terms, also shown where accounts are created |
| `NOKKU_OPERATOR_PRIVACY_URL`   | Privacy policy                              |
| `NOKKU_OPERATOR_IMPRINT_URL`   | Imprint                                     |

### SSO provider seeds (optional)

| Variable               | Purpose                                                            |
| ---------------------- | ------------------------------------------------------------------ |
| `GOOGLE_CLIENT_ID`     | Enables Google social login instance-wide when set with the secret |
| `GOOGLE_CLIENT_SECRET` |                                                                    |
| `GITHUB_CLIENT_ID`     | Enables GitHub social login instance-wide when set with the secret |
| `GITHUB_CLIENT_SECRET` |                                                                    |

Per-workspace OIDC and SAML providers are configured in the web application, not via environment.

### Encryption and KMS (optional)

| Variable                 | Purpose                                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------------------- |
| `KMS_URI`                | Wrap the keyset with a KMS key, `hcvault://` or `scw-kms://`. Requires a license key            |
| `VAULT_TOKEN`            | Token for `hcvault://`                                                                          |
| `VAULT_SKIP_VERIFY`      | Skip Vault TLS verification (testing only)                                                      |
| `KEYSET_REWRAP_INTERVAL` | With a KMS, how often the keyset is wrapped again (minimum 1h, default 12h)                     |
| `KEYSET_ROTATE_INTERVAL` | With a KMS, how old the data key may get before the server rotates (default 2160h, 0 is off)    |

KMS schemes are `hcvault://<host>/transit/keys/<key>` and `scw-kms://regions/<region>/keys/<key-id>`.

### Admin bootstrap (optional)

| Variable               | Purpose                                      |
| ---------------------- | -------------------------------------------- |
| `NOKKU_ADMIN_EMAIL`    | Create and verify this admin account at boot |
| `NOKKU_ADMIN_PASSWORD` | Initial admin password                       |
| `NOKKU_ADMIN_NAME`     | Admin display name                           |

### Other integrations

| Variable                      | Purpose                                         |
| ----------------------------- | ----------------------------------------------- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Enable OTLP export of traces, metrics, and logs |
| `OTEL_EXPORTER_OTLP_HEADERS`  | Extra headers for the OTLP exporter             |

## Secret rotation

The secrets in the database (CA private keys, SSO client secrets, the SAML signing key) are encrypted by one keyset, which is stored in the database too. The keyset is wrapped by a key derived from `NOKKU_SECRET`, or by the KMS key when `KMS_URI` is set. Each recording is encrypted with its own key, and that key is one more secret in the database.

A rotation adds a new data key to the keyset, re-encrypts the secrets in the database with it, and drops the older keys, all in one transaction. The keyset never holds more than two keys. Recordings are not re-encrypted, only their keys are.

To change `NOKKU_SECRET`, or to move to a KMS, stop the server and run:

```bash
./nokku rotate-secrets --new secret:NEW_SECRET
# or, to a KMS:
./nokku rotate-secrets --new kms:hcvault://vault:8200/transit/keys/nokku
```

Then set `NOKKU_SECRET` or `KMS_URI` to the new value and start the server. It refuses to start with the old one.

With a KMS nothing has to be run by hand. The server rotates every `KEYSET_ROTATE_INTERVAL` while it runs, and wraps the keyset again every `KEYSET_REWRAP_INTERVAL`, which follows a key rotation inside the KMS.

A rotation does not un-leak anything. If the old secret and an old database dump both leaked, roll over the CAs as well.

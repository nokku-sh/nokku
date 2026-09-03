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

Self-hosted instances default to the **Community** plan.
For unlimited quotas, SAML, and SSO enforcement, we offer an **Enterprise** plan. Enterprise license keys are Ed25519-signed and verified offline against a public key compiled directly into the binary, ensuring fully air-gapped activation.

> **For in-depth documentation, advanced configuration, and production deployment guides, please visit our [Official Documentation (Link)](https://nokku.sh/docs)**

## Build and run

```bash
./nokku
```

The backend reads configuration from environment variables. Only `NOKKU_SECRET` is mandatory; everything else has a default or belongs to the integration it configures.

### Core

| Variable                | Purpose                                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------------------- |
| `NOKKU_BASE_URL`        | Public base URL (default `http://localhost`), used for links, cookies, and WebAuthn                  |
| `NOKKU_PORT`            | Port the backend listens on (default `3000`)                                                         |
| `NOKKU_SECRET`          | **Required.** Keys at-rest encryption (SSO secrets, SAML keys, CA keys) and DPoP nonces              |
| `NOKKU_TRUSTED_PROXIES` | Comma-separated reverse-proxy IPs/CIDRs (e.g. Traefik) whose forwarded client-IP headers are honored |
| `NOKKU_ALLOWED_ORIGINS` | Additional allowed CORS origins                                                                      |
| `NOKKU_DEBUG`           | Debug logging (`--debug`)                                                                            |
| `NOKKU_LICENSE_KEY`     | License key activating licensed self-host features                                                   |

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

### Cache (Redis, optional)

| Variable         | Purpose                                                                |
| ---------------- | ---------------------------------------------------------------------- |
| `REDIS_ADDR`     | Redis address; enables a shared cache across replicas                  |
| `REDIS_PASSWORD` | Redis password                                                         |
| `REDIS_DB`       | Redis database number; must be set explicitly when `REDIS_ADDR` is set |

Without Redis, the core uses a bounded in-process cache. Single-use state (DPoP nonces, login flow state) is then per-instance, so run one core instance without Redis.

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

S3-compatible storage holds avatars and session recordings. Recordings are encrypted before upload regardless of the backend.

### Email (recommended)

| Variable               | Default                   | Purpose                         |
| ---------------------- | ------------------------- | ------------------------------- |
| `NOKKU_EMAIL_DRIVER`   | `noop`                    | `noop`, `smtp`, or `scaleway`   |
| `NOKKU_EMAIL_SENDER`   | `noreply@system.nokku.sh` | Sender address                  |
| `NOKKU_EMAIL_TIMEOUT`  | `10s`                     | Send timeout                    |
| `NOKKU_EMAIL_COOLDOWN` | `15m`                     | Per-user, per-template cooldown |
| `NOKKU_SMTP_HOST`      |                           | SMTP host (`smtp` driver)       |
| `NOKKU_SMTP_PORT`      | `587`                     | SMTP port                       |
| `NOKKU_SMTP_USERNAME`  |                           | SMTP username                   |
| `NOKKU_SMTP_PASSWORD`  |                           | SMTP password                   |

Scaleway TEM uses the standard Scaleway credentials. The `noop` driver cannot deliver password resets.

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
| `KMS_URI`                | Envelope encryption through `aws-kms://`, `hcvault://`, or `scw-kms://`. Requires a license key |
| `VAULT_TOKEN`            | Token for `hcvault://`                                                                          |
| `VAULT_SKIP_VERIFY`      | Skip Vault TLS verification (testing only)                                                      |
| `KEYSET_REWRAP_INTERVAL` | How often the wrapped keyset is re-wrapped (minimum 1h, default 12h)                            |

KMS schemes are `aws-kms://<key-id>`, `hcvault://<host>/transit/keys/<key>`, and `scw-kms://<key-id>`. Google Cloud KMS is not currently supported.

### Admin bootstrap (optional)

| Variable               | Purpose                                      |
| ---------------------- | -------------------------------------------- |
| `NOKKU_ADMIN_EMAIL`    | Create and verify this admin account at boot |
| `NOKKU_ADMIN_PASSWORD` | Initial admin password                       |
| `NOKKU_ADMIN_NAME`     | Admin display name                           |

### Other integrations

| Variable                      | Purpose                                                            |
| ----------------------------- | ------------------------------------------------------------------ |
| `IP2LOCATION_TOKEN`           | Download token for the IP geolocation DB used in new-device emails |
| `IP2LOCATION_DB_PATH`         | Local path of the geolocation DB (default `data/ip2location.bin`)  |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Enable OTLP export of traces, metrics, and logs                    |
| `OTEL_EXPORTER_OTLP_HEADERS`  | Extra headers for the OTLP exporter                                |

## Secret rotation

Stop the backend before rotating encrypted data:

```bash
./nokku rotate-secrets --new secret:NEW_SECRET
# or, in KMS mode:
./nokku rotate-secrets --new kms:hcvault://vault:8200/transit/keys/nokku
```

The command re-encrypts every stored secret (CA private keys, SSO client secrets, the SAML signing key) in one transaction. Update the runtime environment (NOKKU_SECRET, or the KMS keyset reference) after a successful rotation, then start the core.

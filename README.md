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

# Nokku

Nokku is the backend and web application for certificate-based access to SSH targets and X.509 workloads.

The backend is the control plane for:

- Users, workspaces, teams, and service accounts
- Targets, Linux principals, and access assignments
- SSH and X.509 certificate authorities
- SSH certificate signing and X.509 CSR signing
- Daemon enrollment and synchronization
- Browser authentication and terminal sessions

The other components are:

- [`nk`](https://github.com/nokku-sh/nk): workstation CLI for authentication, SSH certificates, SSH configuration, and X.509 issuance
- [`nokkud`](https://github.com/nokku-sh/nokkud): target-server daemon for SSH configuration, host certificates, and principal synchronization

## Development requirements

- Go
- PostgreSQL

The backend also uses the integrations configured for the selected environment, such as email, OIDC, KMS, and billing.

## Build and run

```bash
./nokku
```

The backend reads configuration from environment variables. Common settings include:

| Variable                                    | Purpose                                                                                              |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `NOKKU_BASE_URL`                            | Public base URL                                                                                     |
| `NOKKU_PORT`                                | Port the backend listens on                                                                         |
| `NOKKU_SECRET`                              | 32-byte encryption secret                                                                           |
| `KMS_URI`                                   | External key-management URI                                                                         |
| `NOKKU_TRUSTED_PROXIES`                     | Comma-separated reverse-proxy IPs/CIDRs (e.g. Traefik) whose forwarded client IP headers are honored |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OIDC                                                                                          |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OIDC                                                                                          |

## Secret rotation

Stop the backend before rotating encrypted data:

```bash
./nokku rotate-secrets --new secret:NEW_SECRET
```

The command also supports `kms:<URI>` destinations. Update the runtime environment after a successful rotation.

## Development

```bash
go test ./...
```

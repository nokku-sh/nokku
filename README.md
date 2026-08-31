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

The backend reads configuration from environment variables. Common settings include:

| Variable                | Purpose                                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------------------- |
| `NOKKU_BASE_URL`        | Public base URL                                                                                      |
| `NOKKU_PORT`            | Port the backend listens on                                                                          |
| `NOKKU_SECRET`          | Master secret for at-rest encryption (SSO secrets, SAML keys, DPoP nonce, CA keys)                   |
| `KMS_URI`               | External key-management URI (Enterprise): routes at-rest encryption through KMS                      |
| `NOKKU_TRUSTED_PROXIES` | Comma-separated reverse-proxy IPs/CIDRs (e.g. Traefik) whose forwarded client IP headers are honored |

## Secret rotation

Stop the backend before rotating encrypted data:

```bash
./nokku rotate-secrets --new secret:NEW_SECRET
# or, in KMS mode:
./nokku rotate-secrets --new kms:hcvault://vault:8200/transit/keys/nokku
```

Update the runtime environment (NOKKU_SECRET, or the KMS keyset reference) after a successful rotation.

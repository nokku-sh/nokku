# Security

This file has two parts. The first is for reporting a vulnerability. The second is for people who run Nokku and want to do it safely.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private reporting instead:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Tell us as much of this as you can:
   - The Nokku version and how it runs (self-hosted or hosted, which plan)
   - What the issue is and what an attacker gains
   - Steps to reproduce, or a minimal proof of concept
   - Logs that help, with secrets and tokens removed

Reports are handled confidentially. If you would like credit in the advisory or the changelog, say so.

What to expect:

- **Acknowledgement** within 48 hours
- **Triage** and a severity within 5 business days
- **A fix or clear guidance** within 30 days, depending on complexity and impact

### Supported versions

Only the latest release gets security fixes. Older releases are not patched. On a self-hosted install, pull the newest release and restart the core.

### In scope

- The **core**: sign-in and OIDC, authorization, SSH certificate signing, daemon enrollment and sync, licensing, the audit log and secret management
- The bundled **web app**, including browser sign-in and terminal sessions
- External integrations **as the core uses them** (email, OIDC providers, KMS, billing)
- The Helm chart and the deployment files in this repository

### Out of scope

- The [`nk`](../cli/SECURITY.md) CLI and the [`nokkud`](../daemon/SECURITY.md) daemon. Each has its own policy in its folder.
- The SSH protocol itself, and vulnerabilities in OpenSSH or `sshd`
- Operating system, container runtime and database engine issues
- The infrastructure behind the hosted service, and outages of third-party providers

## Running Nokku securely

The core holds the signing keys of your SSH certificate authorities. Whoever controls it controls access to every server. These are the settings that deserve care. Setup and the full list of settings are in the [README](./README.md).

### The secret

`NOKKU_SECRET` protects everything the core encrypts at rest: CA private keys, the key of the built-in TLS CA, SSO client secrets and the keys of session recordings.

- Use at least 32 random characters, for example `openssl rand -hex 32`. The core refuses less.
- Keep it in a secret manager, never in the repository or an image.
- Back it up together with the database. One is useless without the other.
- Treat license keys and OIDC client secrets the same way.

How it works: the secrets in the database are encrypted by one keyset, which is stored in the database too. The keyset is wrapped by a key derived from `NOKKU_SECRET`, or by a KMS key when `KMS_URI` is set. Each recording is encrypted with its own key in Tink's AES-GCM-HKDF streaming format, with the recording's id as associated data, so a cut or swapped object fails to play. That key is one more secret in the database.

### Rotating the secret

Stop the core, then run the rotation with the same environment the core runs with:

```bash
NOKKU_NEW_SECRET="secret:$(cat new-secret.txt)" ./nokku rotate-secrets
```

Then set `NOKKU_SECRET` to the new value and start the core. It refuses to start with the old one.

The new secret can also be passed as `--new secret:...`. The environment variable keeps it out of the process list and your shell history.

A rotation adds a new data key to the keyset, re-encrypts the secrets in the database with it and drops the older keys, all in one transaction. The keyset never holds more than two keys. Recordings are not re-encrypted, only their keys are.

A rotation does not un-leak anything. If the old secret and an old database dump both leaked, roll over the CAs as well.

### Using a KMS

With a KMS, the key that unlocks everything lives in the KMS and not in an environment variable. This needs an Enterprise license. Community installs use `NOKKU_SECRET`.

| Variable                 | Purpose                                                                             |
| ------------------------ | ----------------------------------------------------------------------------------- |
| `KMS_URI`                | The KMS key that wraps the keyset                                                   |
| `VAULT_TOKEN`            | Token for `hcvault://`                                                              |
| `VAULT_SKIP_VERIFY`      | Skips Vault TLS verification. For testing only                                      |
| `KEYSET_REWRAP_INTERVAL` | How often the keyset is wrapped again. Default 12h, at least 1h                     |
| `KEYSET_ROTATE_INTERVAL` | How old the data key may get before the core rotates it. Default 2160h, 0 turns it off |

`KMS_URI` takes one of:

- `hcvault://<host>/transit/keys/<key>` for HashiCorp Vault
- `scw-kms://regions/<region>/keys/<key-id>` for Scaleway

To move an existing install to a KMS, stop the core and run:

```bash
./nokku rotate-secrets --new kms:hcvault://vault:8200/transit/keys/nokku
```

Then set `KMS_URI` to the same value and start the core.

With a KMS nothing has to be rotated by hand. The core rotates the data key every `KEYSET_ROTATE_INTERVAL`, and wraps the keyset again every `KEYSET_REWRAP_INTERVAL`, which picks up a key rotation inside the KMS.

### The owner account

A workspace has exactly one owner, and nobody else can hand the workspace on. Whoever signs in as the owner has all of it, so know every way in:

- **A passkey.** Always works for the owner, also when single sign-on is required.
- **An email sign-in link.** Always works for the owner too. Whoever reads the owner's mailbox is the owner, so give that mailbox a strong second factor. Without `NOKKU_SMTP_HOST` no links are mailed.
- **The link in the log.** Until the owner has a passkey or a linked provider, every start prints a 24 hour sign-in link, and `./nokku admin-link` prints one on demand. Anyone who reads the server's log or runs commands on the machine can become the owner. Keep both to people you trust with the workspace, and add a passkey right after the first sign-in.
- **A linked identity provider.** A provider never becomes the owner by matching the email address. The owner links it once while signed in, under **Profile, Security**. After that, whoever controls that account at the provider is the owner.

Requiring single sign-on closes passkeys and email links for everyone else, and signs out the sessions they started, in the browser and in `nk`. It leaves them open for the owner on purpose, so a broken provider can still be fixed.

### Identity providers

- **An account links by address only when the provider vouches for it.** A provider that sends `email_verified: true` links to the account with that address. One that sends `false` never does. Entra sends nothing at all, so it only links when the owner turns on **Trust addresses it does not verify** for that provider. Do that only for a directory you run, like your own Entra tenant, never for one where people pick their own address.
- **New ways in need a fresh sign-in.** Adding a passkey or changing the email address takes a session from the last 10 minutes. An older one is signed out and has to sign in again, so a stolen session cookie cannot turn into a lasting passkey.

### Network

- **The core is only reached over TLS.** It answers https on its port with a CA of its own. Plain HTTP on the same port is served only to a trusted proxy that holds the certificate, `compose.prod.yml` runs Caddy for this. Anyone else who asks in plain HTTP is sent to https. `nk` and `nokkud` never skip certificate verification. A private CA reaches them through a pin, see the README.
- **Set `NOKKU_TRUSTED_PROXIES` to exactly your proxy.** The core takes plain HTTP and forwarded client-IP headers from these addresses only. Unset, that is the machine itself and the private ranges, so a proxy in a container network works as it is. It also means any machine in such a network can fake its address in the audit log and dodge rate limits. Without a proxy set it to `127.0.0.1`.
- **Leave `NOKKU_ALLOW_PRIVATE_NETWORKS` off unless you need it.** Workspace owners choose SSO provider URLs, so the core refuses to connect to private, loopback and link-local addresses. Set it to `true` only when every such address is trusted, like a self-hosted install with its identity provider on an internal network. Never turn it on when you host for other people.

### File storage

Recordings are encrypted before they are stored, on local disk and on S3 alike. Nothing in the bucket has to be public, the core serves everything itself.

### Database

- The core uses three roles. The owner (`PGUSER`) only runs migrations at start. Requests run as `nokku_app`, under row-level security. Work that spans workspaces, like the first start, billing webhooks and background jobs, runs as `nokku_system`, which bypasses it.
- Set `NOKKU_DB_APP_PASSWORD` to give the two runtime roles a password of their own instead of sharing the owner's.
- Use `PGSSLMODE=verify-full` when PostgreSQL is on another host.

### Releases

Releases are built with GoReleaser and come with checksums and signatures. Verify a download before you run it.

The container image is signed with cosign and carries an SPDX SBOM. Check an image before you deploy it:

```bash
cosign verify ghcr.io/nokku-sh/nokku:<version> \
  --certificate-identity https://github.com/nokku-sh/.github/.github/workflows/go-release.yaml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository nokku-sh/nokku
```

## What to know about the design

**The core is down, access is not.** Daemons enforce the access they last synced, and a certificate stays valid until it expires. Revoking access is immediate on servers that are in sync. A server that missed the sync is bounded by the certificate lifetime, so keep user certificates short. They default to 16 hours, and `nk` renews them on its own.

**CA keys never expire.** Like OpenSSH's own CA keys, they change only when you rotate them. Every CA has two Ed25519 keys: a user key that signs logins and a host key that signs the host certificates of daemons, so neither can stand in for the other. **Rotate** replaces both and keeps the old ones trusted until the certificates they signed run out. **Emergency rollover** distrusts the old keys at once, for a key that may have leaked. Servers set up with `nk sync` learn the new user key at their next `nk sync`. A KMS keeps the keys safe at rest, but the core decrypts them to sign, so a compromised core is what a rollover is for.

**Session recordings.** Daemons stream recordings to the core, where each is encrypted with a key of its own. Nothing is redacted: a secret printed on the terminal is in the recording, so treat recordings like the servers they come from. Typed passwords are not recorded, the daemon records input only while the terminal echoes. Every playback is written to the audit log.

**Row-level security is a safety net, not a wall.** Every tenant row belongs to one workspace, and a request only sees the rows of its own. The policy is the only workspace filter, queries name none. A connection with no workspace set sees nothing. This protects against application bugs. It does not protect against a compromised core: it holds the password of `nokku_system` too, and the workspace setting is an ordinary session variable. Queries are parameterized through sqlc, which is the defense against injection.

**Licensing.** A self-hosted core starts on the Community plan. License keys are Ed25519-signed and verified offline against a public key compiled into the binary. An expired key never stops the core. Licensed features turn off, and data beyond the Community limits is kept for 30 more days. A core that holds a key sends it to `license.nokku.sh` once a day and gets the renewed key back. The answer has to verify like any key before it is kept. Nothing else is sent, a core without a key never asks, and `NOKKU_LICENSE_OFFLINE=true` turns it off.

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
- The deployment files in this repository

### Out of scope

- The [`nk`](../cli/SECURITY.md) CLI and the [`nokkud`](../daemon/SECURITY.md) daemon. Each has its own policy in its folder.
- The SSH protocol itself, and vulnerabilities in OpenSSH or `sshd`
- Operating system, container runtime and database engine issues
- The infrastructure behind the hosted service, and outages of third-party providers

## Running Nokku securely

The core holds the signing keys of your workspace's SSH certificate authority. Whoever controls it controls access to every server. These are the settings that deserve care. Setup and the full list of settings are in the [README](./README.md).

### The secret

`NOKKU_SECRET` protects everything the core encrypts at rest: CA private keys, SSO client secrets and the keys of session recordings. With `KMS_URI`, a KMS key does that job and you leave `NOKKU_SECRET` out.

- Use at least 32 random characters, for example `openssl rand -hex 32`. The core refuses less.
- Keep it in a secret manager, never in the repository or an image.
- Back it up together with the database. One is useless without the other.
- Treat license keys and OIDC client secrets the same way.

How it works: the secrets in the database are encrypted by one keyset, which is stored in the database too. The keyset is wrapped by a key derived from `NOKKU_SECRET`, or by a KMS key when `KMS_URI` is set. Every secret is tied to the row it is stored in: its table, column, workspace and row are part of the encryption, so a ciphertext copied into another row or workspace does not open. The code opens a secret with an explicit call, never as a side effect of reading its row. The private keys of a CA sit in a table of their own, read only to sign. Each recording is encrypted with its own key in Tink's AES-GCM-HKDF streaming format, with the recording's id and its object's id as associated data, so a cut or swapped object fails to play. That key is one more secret in the database. A deleted recording can't be read from the moment its row goes, since its key goes with it. The core then deletes the object from storage within about 10 minutes, and tries again later if storage refuses.

### Rotating the secret

Stop the core, then run the rotation with the same environment the core runs with:

```bash
NOKKU_NEW_SECRET="secret:$(cat new-secret.txt)" ./nokku rotate-secrets
```

Then set `NOKKU_SECRET` to the new value and start the core. It refuses to start with the old one.

The new secret can also be passed as `--new secret:...`. The environment variable keeps it out of the process list and your shell history.

A rotation adds a new data key to the keyset, re-encrypts the secrets in the database with it and drops the older keys, all in one transaction. The keyset never holds more than two keys. Recordings are not re-encrypted, only their keys are.

A rotation does not un-leak anything. If the old secret and an old database dump both leaked, roll over the CA of each workspace as well.

### Using a KMS

With a KMS, the key that unlocks everything lives in the KMS and not in an environment variable. Every install can use one. Set `KMS_URI` or `NOKKU_SECRET`, not both. With both, the KMS wins and the core warns about the unused secret.

| Variable                           | Purpose                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------- |
| `KMS_URI`                          | The KMS key that wraps the keyset                                         |
| `VAULT_TOKEN`                      | Token for `hcvault://`, periodic, see [the Vault token](#the-vault-token) |
| `VAULT_SKIP_VERIFY`                | Skips Vault TLS verification. For testing only                            |
| `SCW_ACCESS_KEY`, `SCW_SECRET_KEY` | Credentials for `scw-kms://`                                              |

`KMS_URI` takes one of:

- `hcvault://<host>/transit/keys/<key>` for HashiCorp Vault
- `scw-kms://regions/<region>/keys/<key-id>` for Scaleway

To move an existing install to a KMS, stop the core and run:

```bash
./nokku rotate-secrets --new kms:hcvault://vault:8200/transit/keys/nokku
```

Then set `KMS_URI` to the same value, remove `NOKKU_SECRET` and start the core.

Keys change only through `rotate-secrets`, with the core stopped. It does three jobs: move the keyset to another secret or KMS, make a new data key and re-encrypt every secret with it, and wrap the keyset onto the newest version of the KMS key when you pass the same `kms:` URI again. A KMS that rotates its own key keeps the old versions for decryption, so the core keeps working. Run `rotate-secrets` with the same URI before you retire old versions in the KMS, like Vault's `min_decryption_version`, or the core can't open its keyset at the next start.

The core needs the KMS to open the keyset at start, not to sign. While the KMS is down a running core keeps working, but it can't start again, so check the KMS before you deploy. The hosted service always runs with a KMS: with `NOKKU_SAAS`, the core refuses to start without `KMS_URI`.

Give the core no more than it needs. In Vault, with `transit` the mount and `nokku` the key in `KMS_URI`:

```hcl
path "transit/encrypt/nokku" {
  capabilities = ["update"]
}
path "transit/decrypt/nokku" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

The last two let the core renew its token.

At Scaleway, leave key protection on for the key in `KMS_URI`, so nobody deletes it by accident.

A move from one Vault to another needs a `VAULT_TOKEN` that works on both. Without one, go through a secret in two steps: `rotate-secrets --new secret:...`, then `--new kms:...` with the new token.

### The Vault token

Every Vault token but a root token ends unless it is renewed. Once `VAULT_TOKEN` ends, a running core keeps working, but it can't start again and `rotate-secrets` fails. The core renews it for as long as it runs, so make it periodic:

```bash
vault policy write nokku-core nokku-core.hcl
vault token create -orphan -policy=nokku-core -period=72h
```

- **Periodic.** Any other token can't be renewed past Vault's limit, 32 days by default. The core warns about one every hour.
- **Orphan.** A token is revoked with the token that made it, so one made from a personal login goes when that login does.
- **Longer than an outage.** The core renews within the hour. If the core or Vault is down for longer than the period, the token is gone and you need a new one. `72h` gets you through a weekend.

### The owner account

A workspace has exactly one owner, and nobody else can hand the workspace on. Whoever signs in as the owner has all of it, so know every way in:

- **A passkey.** Always works for the owner, also when single sign-on is required.
- **An email sign-in link.** Always works for the owner too. Whoever reads the owner's mailbox is the owner, so give that mailbox a strong second factor. Without `NOKKU_SMTP_HOST` no links are mailed.
- **`admin-link`.** `./nokku admin-link` prints a 24 hour sign-in link for the owner. Until the owner has a passkey or a linked provider, the server logs that one is needed but never the link itself, so it does not travel to a log or telemetry backend. A server started in a terminal prints the link there. Anyone who runs commands on the machine can become the owner, so keep that to people you trust with the workspace, and add a passkey right after the first sign-in.
- **A linked identity provider.** A provider never becomes the owner by matching the email address. The owner links it once while signed in, under **Profile, Security**. After that, whoever controls that account at the provider is the owner.

Requiring single sign-on closes passkeys and email links for everyone else, and signs out the sessions they started, in the browser and in `nk`. It leaves them open for the owner on purpose, so a broken provider can still be fixed.

### Identity providers

- **An account links by address only when the provider vouches for it.** A provider that sends `email_verified: true` links to the account with that address. One that sends `false` never does. Entra sends nothing at all, so it only links when the owner turns on **Trust addresses it does not verify** for that provider. Do that only for a directory you run, like your own Entra tenant, never for one where people pick their own address.
- **New ways in need a fresh sign-in.** Adding a passkey, linking a provider, approving `nk` on a device, changing the email address, handing out a join, service account or SCIM token, adding or removing a CI rule on a service account, changing an SSO provider, changing the CA or rolling it over, changing the limits of a service account, transferring ownership and deleting the workspace take a browser session from the last 10 minutes. A service account never does these, whatever its role. An older one is signed out and has to sign in again, so a stolen session cookie cannot turn into a lasting way in. `nk` can do none of these.
- **Every new way in is mailed.** A sign-in from a device the account has not used, a new passkey, a linked provider and a change of the email address each send the account a mail, one per device or credential. Someone who got hold of a session cannot add a way in without the owner of the mailbox seeing it. This needs `NOKKU_SMTP_HOST`.

### Network

- **The core only speaks plain HTTP, so it must sit behind a reverse proxy that terminates TLS.** `compose.prod.yml` runs Caddy for this. The proxy says in `X-Forwarded-Proto` which scheme the client used. The core serves `https` and sends `http` to https. A request through a proxy that names no scheme is refused, since a redirect would loop. The core takes this header from anyone. A browser never sends it, so faking it only fools the core about the faker's own connection. Session cookies are always `Secure`, and a browser ignores HSTS over plain HTTP. The one exception is a `NOKKU_BASE_URL` of `localhost`, for a try on that machine. `nk` and `nokkud` never skip certificate verification. A private CA reaches them as a file, see the README.
- **Only the proxy should reach the core.** Unset, `NOKKU_TRUSTED_PROXIES` trusts a peer on loopback or a private network (RFC 1918, `fc00::/7`) to name the client in `X-Forwarded-For`, and the core takes the rightmost entry, the one the proxy added. So anything that reaches the core's port from such an address can claim any client address: in the audit log, for rate limits, in sign-in mails, to the approver of a device login, and for the `source-address` on a certificate, which relayed and browser sessions are checked against. `compose.prod.yml` keeps the port on the Docker network. In a cluster, a NetworkPolicy that admits only the ingress or gateway does the same.
- **Set `NOKKU_TRUSTED_PROXIES` to tighten it.** A list replaces the default. Only those addresses may name the client, and they are skipped in `X-Forwarded-For` too, so a CDN in front of your proxy can be listed. Your proxy has to trust the CDN as well, or it drops the client address. Never put a network there that holds anything but proxies.
- **Leave `NOKKU_ALLOW_PRIVATE_NETWORKS` off unless you need it.** Workspace owners choose SSO provider URLs, so the core refuses to connect to private, loopback and link-local addresses. Set it to `true` only when every such address is trusted, like a self-hosted install with its identity provider on an internal network. Never turn it on when you host for other people. A core with `NOKKU_SAAS` refuses to start with it.

### File storage

Recordings are encrypted before they are stored, on local disk and on S3 alike. Nothing in the bucket has to be public, the core serves everything itself.

### Tokens

Every session, key and link the core hands out has one form, `nk_<kind>_` followed by at least 26 random and 8 checksum characters, like `nk_sess_` for a browser session, `nk_enroll_` for an enroll token or `nk_sa_` for a service account key. Secret scanners look for this kind of prefix. Add the pattern `nk_[a-z]+_[a-z2-7]{26,}[0-9a-f]{8}` to yours. The core checks the kind and the checksum before it looks a token up, and keeps only its hash.

### Database

- The core uses three roles. The owner (`PGUSER`) only runs migrations at start. Requests run as `nokku_app`, under row-level security. Work that spans workspaces, like the first start, billing webhooks and background jobs, runs as `nokku_system`, which bypasses it. `core/internal/db/testdata/bypass.golden` lists every such query, and a new one fails the tests until someone reviews it. Audit events are always written as `nokku_app` into their own workspace, `nokku_system` cannot write them.
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

**The core is down, access is not.** Daemons enforce the access they last synced, and a certificate stays valid until it expires. `nk` needs the core for a certificate it does not hold yet and for a relayed connection, so during an outage you reach the servers you used recently, and only directly. Revoking access is immediate on servers that are in sync. On a server that missed the sync, new logins end with the certificate, so keep user certificates short. An open session there runs on until it ends, a relayed one 8 hours at most. The console shows a connected server that stopped keeping up as behind, and the audit log records `DaemonBehind`. User certificates default to 16 hours, you set their lifetime once for the whole workspace on its CA, and `nk` renews them on its own. A server set up with `nk sync` hears of no revoke at all, so the core signs certificates for it for an hour at most.

**One CA per workspace, and its keys never expire.** The CA comes with the workspace and stays the only one. A server has no tie to it, so one lifetime and one rollover cover every server, and there is no separate trust root for a group of them. Like OpenSSH's own CA keys, its keys change only when you rotate them. It has two Ed25519 keys: a user key that signs logins and a host key that signs the host certificates of daemons, so neither can stand in for the other. **Rotate** replaces both and keeps the old ones trusted until the certificates they signed run out. **Emergency rollover** stops trusting the old keys, for a key that may have leaked. A daemon drops them at its next sync and closes what they signed. A server set up with `nk sync` keeps trusting them until the next `nk sync` there, so reach those first. Either one covers every server in the workspace: daemons take the new keys at their next sync, and servers set up with `nk sync` learn the new user key at their next `nk sync`. An `nk sync` during a rotate writes both keys, and that server has no way to drop one on a date, so it stays flagged until a sync after the old key ends. After a rotate, `nk` keeps the certificate it holds for such a server, an hour at most, so run `nk sync` on them right away. After an emergency rollover they refuse every certificate until someone reaches them another way, so keep a way in that is not Nokku. A KMS keeps the keys safe at rest, but the core decrypts them to sign, so a compromised core is what a rollover is for.

**Limits follow who they limit.** The CA holds one source list, for people. It goes on every certificate a person gets, the browser terminal included, and a person's certificate never has a forced command. A service account has a forced command and a source list of its own, and its certificates carry those and nothing from the CA, so an office list can't block a hosted CI runner. An account without limits has none. A forced command also turns off port forwarding, agent forwarding and `~/.ssh/rc`, since `ssh -N` would otherwise open a tunnel without ever running it. Only a person changes these limits.

**CI signs in with no stored secret.** GitHub Actions, GitLab and others give each job a signed token. An admin adds a rule to a service account, an issuer and the exact claims a job must hold. `nk login --ci` sends the token to `AuthService.ExchangeWorkloadToken`, and the core acts as the relying party, the same way it does for SSO. The call is public, its workspace comes from the host, it sits in the strict rate limit of the sign-in calls, and it needs a DPoP proof. It finds the account by name and reads the rules of the account. The unverified `iss` only picks rules. The token is then verified with `go-oidc` against the issuer of the stored rule, through the client that refuses private addresses, with the URL of the workspace as the required audience. The token must have an `exp` in the future, an `iat` less than an hour old and at most a minute ahead, and a `jti`. Every claim of one rule must match exactly, as a string. A refusal gives the caller one answer. The reason goes to the server log, and to the audit log once the issuer's signature checks out, so nobody fills the log of a workspace without a signed token. The token itself never goes to either.

A rule has to name the job. It can't match on `aud`, `iss`, `exp`, `iat`, `nbf` or `jti`, and it can't be empty. A rule for GitHub Actions needs `repository_id` plus `environment` or `ref`, since `repository_id` alone covers every branch and pull request and a repository name can be registered again by someone else. A rule for gitlab.com needs `project_id` plus `environment`, `ref_path`, or `ref` with `ref_type`, since a `ref` alone also matches a tag of that name, and any other issuer needs `sub`. What a rule can't check is how the platform is set up. An `environment` only limits a job if it is protected there, an open one lets any branch name it. On GitHub a `ref` also matches `pull_request_target` and `workflow_run` jobs on that branch, so add `event_name` if such a workflow has `id-token: write`.

The answer is a service account token of an hour at most, never past the job token's own `exp`, and bound by DPoP to the key of the proof. Every exchange writes its audit row before it answers, and a plan that stops signing refuses here too. The role of the account applies to the session, up to editor, so keep a CI account low and give it only the servers it deploys to.

**A job token works once.** The session row stores the issuer and `jti` under a unique index, so a second exchange is refused, and a retry needs a new token. The row lasts as long as the session. A revoked session keeps its row until then, without the hash that signs in, so a revoke does not free the job token. After that the `iat` check refuses the token. GitHub Actions hands out a new token per request, so `nk login --ci` can run again. GitLab's is fixed for the job, so a GitLab job over an hour can't renew. Removing a rule stops new sign-ins. A session a job already holds runs out within the hour. Revoking it under Tokens stops its calls and new certificates, the certificates it already has still log in until they run out. To end its access now, remove its grant or delete the account.

**Keys have an end date.** A service account key can't be made without one, and the schema refuses one with none. A key is sent as a plain bearer token with no key binding, so it is for Ansible and scripts that drive Nokku from a place with no signed token. CI should not hold one.

**The relay and the browser terminal.** A connection from `nk` through the relay stays encrypted end to end, the core only carries SSH ciphertext. The browser terminal is different: the core is the SSH client there, so what is on the screen passes through it in the clear.

**Session recordings.** Daemons stream recordings to the core, where each is encrypted with a key of its own. Nothing is redacted: a secret printed on the terminal is in the recording, so treat recordings like the servers they come from. Typed passwords are not recorded, the daemon records input only while the terminal echoes. Every playback is written to the audit log.

**Row-level security is a safety net, not a wall.** Every tenant row belongs to one workspace, and a request only sees the rows of its own. The policy is the only workspace filter, queries name none. A connection with no workspace set sees nothing. This protects against application bugs. It does not protect against a compromised core: it holds the password of `nokku_system` too, and the workspace setting is an ordinary session variable. Queries are parameterized through sqlc, which is the defense against injection.

**Licensing.** A self-hosted core starts on the Community plan. License keys are Ed25519-signed and verified offline against a public key compiled into the binary. An expired key never stops the core. Licensed features turn off, and data beyond the Community limits is kept for 30 more days. A core that holds a key sends it to `license.nokku.sh` once a day and gets the renewed key back. The answer has to verify like any key before it is kept. Nothing else is sent, a core without a key never asks, and `NOKKU_LICENSE_OFFLINE=true` turns it off.

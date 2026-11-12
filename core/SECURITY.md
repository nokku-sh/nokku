# Security of the core

The core holds your workspace's SSH certificate authority. Whoever controls it controls access to every server. This file is for people who run it and for anyone who has to assess it.

Found a vulnerability? Don't open a public issue. See [SECURITY.md](../SECURITY.md) for how to report it.

## In short

- **Keep `NOKKU_SECRET` safe and back it up with the database.** It unlocks the CA keys. A KMS can hold that key instead.
- **Let only your reverse proxy reach the core.** It trusts the proxy to name the client's address.
- **Protect the owner account.** The owner's passkey, mailbox and shell access to the core each open the whole workspace.
- **The core is not needed for a login.** Servers check logins on their own. A new certificate and the relay do need it.
- **A rollover is how you recover from leaked CA keys.**
- **Nothing in a recording is redacted.** Treat recordings like the servers they come from.

## Scope

In scope:

- The **core**: sign-in and OIDC, authorization, SSH certificate signing, daemon enrollment and sync, licensing, the audit log and secret management
- The bundled **web app**, including browser sign-in and terminal sessions
- External integrations **as the core uses them** (email, OIDC providers, KMS, billing)
- The deployment files in this folder

Out of scope:

- [`nk`](../cli/SECURITY.md) and [`nokkud`](../daemon/SECURITY.md), which have their own files
- The SSH protocol itself, and vulnerabilities in OpenSSH or `sshd`
- Operating system, container runtime and database engine issues
- The infrastructure behind the hosted service, and outages of third-party providers

## Running Nokku securely

Setup and the full list of settings are in the [README](./README.md).

### The secret

`NOKKU_SECRET` protects everything the core encrypts at rest: the CA's private keys, SSO client secrets and the keys of session recordings. With `KMS_URI`, a KMS key does that job and you leave `NOKKU_SECRET` out.

- Use at least 32 random characters, like `openssl rand -hex 32`. The core refuses less.
- Keep it in a secret manager, never in the repository or an image.
- Back it up together with the database. One is useless without the other.
- Treat license keys and OIDC client secrets the same way.

### Rotating the secret

Stop the core, then run the rotation with the same environment the core runs with:

```bash
NOKKU_NEW_SECRET="secret:$(cat new-secret.txt)" ./nokku rotate-secrets
```

Then set `NOKKU_SECRET` to the new value and start the core. It refuses to start with the old one. `--new secret:...` works too, the environment variable keeps the secret out of the process list and your shell history.

A rotation re-encrypts every secret in the database with a new key and drops the old ones, in one transaction. Recordings are not re-encrypted, only their keys are.

A rotation does not un-leak anything. If the old secret and a database dump both leaked, the CA's private keys are out too. Rotate the secret first, then roll over the CA, so the new keys are not sealed with what leaked.

### Using a KMS

With a KMS, the key that unlocks everything lives in the KMS, not in an environment variable. Every install can use one. Set `KMS_URI` or `NOKKU_SECRET`, not both. With both, the KMS wins and the core warns about the unused secret.

| Variable                           | Purpose                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------- |
| `KMS_URI`                          | The KMS key that wraps the keyset                                         |
| `VAULT_TOKEN`                      | Token for `hcvault://`, periodic, see [the Vault token](#the-vault-token) |
| `VAULT_SKIP_VERIFY`                | Skips Vault TLS verification. For testing only                            |
| `SCW_ACCESS_KEY`, `SCW_SECRET_KEY` | Credentials for `scw-kms://`                                              |

`KMS_URI` is `hcvault://<host>/transit/keys/<key>` for HashiCorp Vault, or `scw-kms://regions/<region>/keys/<key-id>` for Scaleway. To move an existing install to a KMS, stop the core and run:

```bash
./nokku rotate-secrets --new kms:hcvault://vault:8200/transit/keys/nokku
```

Then set `KMS_URI` to the same value, remove `NOKKU_SECRET` and start the core.

- **The core needs the KMS to start**, not to sign. While the KMS is down a running core keeps working, but it can't start again, so check the KMS before you deploy.
- **Keys change only through `rotate-secrets`**, with the core stopped. It moves the keyset to another secret or KMS, re-encrypts every secret, and with the same `kms:` URI wraps the keyset onto the newest version of the KMS key. Run that before you retire old key versions in the KMS, like Vault's `min_decryption_version`, or the core can't open its keyset at the next start.
- **At Scaleway**, leave key protection on for the key, so nobody deletes it by accident.
- **From one Vault to another** needs a `VAULT_TOKEN` that works on both. Without one, go through a secret in two steps: `rotate-secrets --new secret:...`, then `--new kms:...` with the new token.
- **The hosted service** always runs with a KMS. With `NOKKU_SAAS`, the core refuses to start without `KMS_URI`.

<details>
<summary><b>A Vault policy with no more than the core needs</b></summary>

With `transit` the mount and `nokku` the key in `KMS_URI`:

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

</details>

### The Vault token

Every Vault token but a root token ends unless it is renewed. Once `VAULT_TOKEN` ends, a running core keeps working, but it can't start again and `rotate-secrets` fails. The core renews it for as long as it runs, so make it periodic and an orphan:

```bash
vault policy write nokku-core nokku-core.hcl
vault token create -orphan -policy=nokku-core -period=72h
```

- **Periodic**, since any other token can't be renewed past Vault's limit, 32 days by default. The core keeps warning about one.
- **Orphan**, since a token is revoked with the token that made it. One made from a personal login goes when that login does.
- **Longer than an outage.** If the core or Vault is down for longer than the period, the token is gone and you need a new one. `72h` gets you through a weekend.

### The owner account

A workspace has exactly one owner, and nobody else can hand the workspace on. Whoever signs in as the owner has all of it, so know every way in:

- **A passkey.** Always works for the owner, also when single sign-on is required.
- **An email sign-in link.** Always works for the owner too. Whoever reads the owner's mailbox is the owner, so give that mailbox a strong second factor.
- **`admin-link`.** `./nokku admin-link` prints a 24 hour sign-in link for the owner. The log never shows the link, but a server started in a terminal prints it there. Anyone who runs commands on the machine can become the owner, so keep that to people you trust with the workspace.
- **A linked identity provider.** A provider never becomes the owner by matching the email address. The owner links it once while signed in, on their profile. After that, whoever controls that account at the provider is the owner.

Requiring single sign-on closes passkeys and email links for everyone else, and signs out the sessions they started, in the browser and in `nk`. It leaves them open for the owner on purpose, so a broken provider can still be fixed.

**How long a sign-in lasts.** A browser session lasts 7 days and an `nk` session 30. Where single sign-on is required, both last one day, the owner's too, and turning the requirement on shortens the sessions that are open. No certificate outlives the session it was asked with. Nothing else asks the provider again, so that day is how long someone removed at the provider can stay in.

**Removing someone.** Deactivate the account in Nokku, or let SCIM do it. That stops their sessions at once. Removing them at the provider alone only works where single sign-on is required, and then within a day, since the last certificate ends with the session. Where single sign-on is offered but not required, a passkey still signs in, so the provider removes nobody. The owner is never removed by the provider, their passkey and email link stay.

### Identity providers

- **An account links by address only when the provider vouches for it.** A provider that sends `email_verified: true` links to the account with that address. One that sends `false` never does. Entra sends nothing, so it only links when the owner turns on **Trust addresses it does not verify** for that provider. Do that only for a directory you run, never for one where people pick their own address. A Microsoft provider from `MICROSOFT_*` is your own tenant, so it starts with that setting on, and with accounts created on first sign-in.
- **The SCIM token is your identity provider's hand in the workspace.** It creates accounts and teams, sets the members of the teams it holds, and switches accounts off, the owner aside. Two things it can't do. It takes a team made by hand only after someone opened that team for it in the team's settings, so a group can't get a team's access by using its name. And it switches on only an account it switched off itself, so an account an admin stopped stays stopped whatever the provider sends. The token has no end date, an expired one would stop offboarding without a word. Its age and last use are on the SCIM page, replace it when it looks wrong.
- **New ways in and more power need a fresh sign-in**, a browser session from the last 10 minutes. That covers adding a passkey or provider, approving `nk` on a device, opening a terminal in the browser, changing the email address, inviting someone, handing out tokens, opening a team for SCIM, changing CI rules, SSO, audit streams or the CA, changing a server's address, changing a role, reactivating an account, transferring ownership and deleting the workspace. `core/internal/api/testdata/rules.golden` marks every such call with `fresh=true`, and `requestedFresh` adds the ones a single field decides. A service account and `nk` can do none of these. Deactivating an account stays quick, it is the emergency brake.
- **Every new way in is mailed**, when SMTP is set up. A sign-in from a new device, a new passkey, a linked provider and a changed email address each send the account a mail. Someone who got hold of a session can't add a way in without the mailbox owner seeing it.

### Network

- **Put a reverse proxy in front that terminates TLS.** The core only speaks plain HTTP and does not look at the scheme, so let the proxy redirect `http` to `https`. Nothing works over plain `http`: session cookies are always `Secure`, except with a `NOKKU_BASE_URL` of `localhost`, passkeys need `https`, `nk` and `nokkud` refuse a plain address, and the web app shows a notice instead of the sign-in. The core sends HSTS, so a browser that was on `https` once stays there.
- **Only the proxy should reach the core.** By default the core trusts a peer on loopback or a private network to name the client in `X-Forwarded-For`. So anything that reaches the core's port from such an address can claim any client address: in the audit log, for rate limits, in sign-in mails and for a certificate's `source-address`. It never signs anyone in. Keep the port on the proxy's Docker network, or admit only the ingress with a NetworkPolicy. A core with `NOKKU_SAAS` refuses to start without `NOKKU_TRUSTED_PROXIES`.
- **Set `NOKKU_TRUSTED_PROXIES` to tighten it.** The list replaces the default. Never put a network there that holds anything but proxies. The README covers [the cases](./README.md#client-addresses).
- **A self-hosted core calls private addresses, the hosted one never does.** The owner chooses the URLs of SSO providers and audit streams, an editor the issuer of a CI rule, and the core fetches them. Self-hosted, they may be on loopback or a private network, like an identity provider on your LAN. So these people can make the core send requests into its own network. The owner can see part of an answer in an error, an editor sees nothing of it. Link-local addresses and the other special ranges are always refused, clouds serve instance metadata there. With `NOKKU_SAAS` any workspace picks the URLs, so only public addresses pass.
- **`nk` and `nokkud` never skip certificate verification.** A private CA reaches them as a file.

### Database

- **Three roles.** The owner (`PGUSER`) runs migrations at start. Requests run as `nokku_app`, under row-level security. Work that spans workspaces, like background jobs, runs as `nokku_system`, which bypasses it. `core/internal/db/testdata/bypass.golden` lists every such query, and a new one fails the tests until someone reviews it.
- **One password.** The core sets the password of `nokku_app` and `nokku_system` to `PGPASSWORD` at every start. It holds the owner's login anyway, so a second password would protect nothing.
- **Use `PGSSLMODE=verify-full`** when PostgreSQL is on another host.

### Tokens

Every session, key and link the core hands out looks like `nk_<kind>_` followed by random and checksum characters, like `nk_sess_` for a browser session, `nk_enroll_` for an enrollment token or `nk_sa_` for a service account key. Add `nk_[a-z]+_[a-z2-7]{26,}[0-9a-f]{8}` to your secret scanner. The core keeps only a token's hash.

### File storage

Recordings are encrypted before they are stored, on local disk and on S3 alike. Nothing in the bucket has to be public.

### Releases

Releases are built with GoReleaser and come with checksums and signatures. The container image is signed with cosign and carries an SPDX SBOM. Check an image before you deploy it:

```bash
cosign verify ghcr.io/nokku-sh/nokku:<version> \
  --certificate-identity https://github.com/nokku-sh/.github/.github/workflows/go-release.yaml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository nokku-sh/nokku
```

## What to know about the design

**The core is down, access is not.** Daemons enforce the access they last synced, and a certificate stays valid until it expires. A daemon that hears nothing from the core for seven days, the longest a certificate lasts, takes no new logins until it syncs again. `nk` needs the core for a new certificate and for a relayed connection, so during an outage you reach the servers you used recently, and only directly.

**Revokes.** A revoke is immediate on daemons that are in sync, open sessions included. On a daemon that missed the sync, new logins end with the certificate. An open session there runs on until it ends, a relayed one 8 hours at most. The console shows such a daemon as behind. A server set up with `nk sync` hears of no revoke at all, so the core signs certificates for it for an hour at most. A person's certificate lasts 16 hours unless the workspace sets another lifetime on its CA, 15 minutes at least and 7 days at most. `nk` renews it in the background, so a short one costs nobody anything while the core is up. A host certificate lasts 90 days and a daemon renews its own.

**One CA per workspace, and its keys never expire.** It has two Ed25519 keys: a user key that signs logins and a host key that signs the host certificates of daemons, so neither can stand in for the other. The keys change only when you roll them over. A KMS keeps them safe at rest, but the core decrypts them to sign, so a leaked secret with a database dump, or a compromised core, is what a rollover is for.

**A rollover has no grace period**, since it would be one for whoever holds the old keys. It replaces both keys and nothing trusts the old ones after it. Daemons take the new keys at their next sync, within a minute, and close the connections that started on the old ones. In that minute a login can fail. A server set up with `nk sync` trusts only the old key until the next `nk sync` there, so run it right away. Keep a way in that is not Nokku, for the server you can't reach.

**Limits follow who they limit.** The CA holds one source list, for people. It goes on every certificate a person gets, the browser terminal included. A service account has a forced command and a source list of its own instead, so an office list can't block a CI runner. A forced command also turns off port forwarding, agent forwarding and `~/.ssh/rc`. Only a person changes these limits.

**A person's `nk` session certifies one key.** `nk login` sends the machine's SSH public key, and the session gets certificates for that key only. Whoever uses the session on the machine, malware included, can't get a certificate for a key of their own and carry it off. A new key needs a new sign-in. A service account signs whatever key it sends. A certificate never carries `no-touch-required`, so a security key login always needs a touch.

**`nk login` can't be approved from a link someone sends.** `nk` waits on `127.0.0.1` and tells the core its port. The approval hands the browser a one-time code for that port, and the token takes it together with the device code `nk` holds. Approve on another machine and the code lands where no `nk` waits. `nk login --headless` is the old device code, and the approval page only takes it typed, never from a link. `core/internal/integration/api/device_loopback_test.go` pins both.

**An `nk` session makes only the calls `nk` makes.** It signs certificates, lists the servers, teams and people it may reach, relays, asks for access and runs `nk sync`. Everything else, like changing a role, a grant, a recording setting or a token, takes the web app, whatever the person's role. `rules.golden` marks the calls open to `nk` with `cli=true`. So an `nk` session that was phished or sits on an infected machine can reach servers, but can't change who may do what.

**A service account changes no access.** Its key or CI session gets certificates for its own grants and reads what its role may read. As an editor it also runs `nk sync` and `nk rm`, so it can add a server with the grants it names, and re-sync or remove a server it added itself. It can touch no server a person, a daemon or another service account brought, so a leaked key can't delete the fleet or point a server at another host and host key. Grants, teams, daemons and other service accounts take a person, whatever the account's role. `rules.golden` marks those calls with `people_only=true`, and `TestMachinesOnlyReachTheNkSyncCalls` keeps a new editor call from machines until it is listed. So a leaked key reaches the servers it was granted and can't grant itself more.

**CI signs in with no stored secret.** An admin adds a rule to a service account: an issuer and the exact claims a job must hold. `nk login --ci` trades the job's signed token for a session of at most an hour, never past the job token's own expiry, bound by DPoP to a key on the runner. A job token works once. The role of the account applies to the session, up to editor, so keep a CI account low and give it only the servers it deploys to.

A rule has to name the job. It can't be empty or match on `aud`, `iss`, `exp`, `iat`, `nbf` or `jti`.

- **GitHub Actions** needs `repository_id` plus `environment` or `ref`, since `repository_id` alone covers every branch and pull request, and a repository name can be registered again by someone else.
- **gitlab.com** needs `project_id` plus `environment`, `ref_path`, or `ref` with `ref_type`, since a `ref` alone also matches a tag of that name.
- **Any other issuer** needs `sub`.

What a rule can't check is how the platform is set up. An `environment` only limits a job if it is protected there. On GitHub a `ref` also matches `pull_request_target` and `workflow_run` jobs on that branch, so add `event_name` if such a workflow has `id-token: write`.

<details>
<summary><b>How the token exchange works</b></summary>

- `nk login --ci` sends the token to `AuthService.ExchangeWorkloadToken`, and the core acts as the relying party, the same way it does for SSO. The call is public, its workspace comes from the host, it sits in the strict rate limit of the sign-in calls, and it needs a DPoP proof.
- It finds the account by name. The unverified `iss` only picks rules. The token is then verified with `go-oidc` against the issuer of the stored rule, through the same guarded client as SSO, with the workspace URL as the required audience.
- The token must have an `exp` in the future, an `iat` less than an hour old and at most a minute ahead, and a `jti`. Every claim of one rule must match exactly, as a string.
- A refusal gives the caller one answer. The reason goes to the server log, and to the audit log once the issuer's signature checks out, so nobody fills a workspace's log without a signed token. The token itself is never logged.
- The session row stores the issuer and `jti` under a unique index, so a second exchange is refused. A revoked session keeps its row until it would have ended, so a revoke does not free the job token.
- Every exchange writes its audit row before it answers, and a hosted workspace that stopped signing refuses here too.
- Removing a rule stops new sign-ins. A session a job already holds runs out within the hour. Revoking it stops its calls and new certificates, but the certificates it already has still log in until they run out. To end its access now, remove its grant or delete the account.

</details>

**Service account keys have an end date, a year away at most.** A key can't be made without one. It is a plain bearer token with no key binding, so it is for Ansible and scripts that run somewhere without a signed token. CI should not hold one.

**The relay and the browser terminal.** A connection from `nk` through the relay stays encrypted end to end, the core only carries SSH ciphertext. In the browser terminal the core is the SSH client, so what is on the screen passes through it in the clear.

**Session recordings.** Daemons stream recordings to the core, where each is encrypted with a key of its own. Nothing is redacted, so a secret printed on the terminal is in the recording. Typed passwords are not, the daemon records input only while the terminal echoes. Every playback is written to the audit log. Deleting a recording and switching recording on or off for a server take a person with a fresh sign-in, never a service account, so a stolen session or a CI job can't hide what it does.

<details>
<summary><b>How secrets and recordings are encrypted</b></summary>

- The secrets in the database are encrypted by one keyset, stored in the database too. The keyset is wrapped by a key derived from `NOKKU_SECRET`, or by a KMS key. It never holds more than two keys.
- Every secret is tied to the row it is stored in. Its table, column, workspace and row are part of the encryption, so a ciphertext copied into another row or workspace does not open. The code opens a secret with an explicit call, never as a side effect of reading its row.
- The CA's private keys sit in a table of their own, read only to sign.
- Each recording is encrypted with its own key in Tink's AES-GCM-HKDF streaming format, with the recording's id and its object's id as associated data, so a cut or swapped object fails to play. That key is one more secret in the database.
- A deleted recording can't be read from the moment its row goes, since its key goes with it. The core then deletes the object from storage, and tries again later if storage refuses.

</details>

**Logins in the audit log.** Each daemon reports the SSH connections on its server, their open and their close. These rows have the daemon as actor and the person as what they are about, because the core did not see the login itself. Someone with root on a server can forge or withhold that server's reports, and nobody else's. What the core signed, a certificate for a person and a server, is logged by the core itself. One daemon's reports are paced at 20 events a second after a burst of 200, so a server that floods fills its own spool.

**Audit log retention.** The log keeps rows for the workspace's retention. An enabled audit stream holds back what it has not sent, up to 365 days, so a stream that is down loses nothing in that time. A paused stream holds nothing back. Deleting a user or a server deletes their access requests too, the audit log keeps who asked and who decided.

**Row-level security is a safety net, not a wall.** A request only sees the rows of its own workspace, and a connection with no workspace set sees nothing. The policy is the only workspace filter. Audit events are always written as `nokku_app` into their own workspace, `nokku_system` can't write them. This protects against application bugs, not against a compromised core, which holds the password of `nokku_system` too. Queries are parameterized through sqlc, which is the defense against injection.

**Licensing.** A self-hosted core runs without a key. License keys are Ed25519-signed and verified offline against a public key built into the binary. An expired key never stops the core. Licensed features turn off, except required single sign-on and the idle session timeout, which stay as set so a lapsed key opens nothing up. Data beyond the limits of a core without a key is kept for 30 more days. A core that holds a key sends it, and nothing else, to `license.nokku.sh` for the renewed one about once a day, and when an admin opens Billing, at most every 30 seconds per workspace. `NOKKU_LICENSE_OFFLINE=true` turns that off.

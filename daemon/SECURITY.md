# Security

This file has three parts. The first is for reporting a vulnerability. The second is for people who run `nokkud`. The third describes how its SSH server behaves, for anyone who has to assess it.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private reporting instead:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Tell us as much of this as you can:
   - The `nokkud` version and your platform or distribution
   - What the issue is and what an attacker gains
   - Steps to reproduce, or a minimal proof of concept
   - Logs that help, with secrets removed

Reports are handled confidentially. If you would like credit in the advisory or the changelog, say so.

What to expect:

- **Acknowledgement** within 48 hours
- **Triage** and a severity within 5 business days
- **A fix or clear guidance** within 30 days, depending on complexity and impact

### Supported versions

Only the latest release gets security fixes. Older releases are not patched, so upgrade to the newest release.

### In scope

- The `nokkud` binary: enrollment token handling, generating and renewing SSH host certificates, the SSH server's certificate authentication and session handling, and the authenticated outbound control stream to the core
- The local state it writes, all under `/var/lib/nokkud/`:
  - `config.json`, `cache.json` and `state.json`. The trusted CA keys are part of `cache.json`
  - `ssh_host_signer.json`, the host identity
  - The SSH host public key and host certificate
  - `recordings/`

### Out of scope

- The Nokku core and web app, which have their own [policy](../core/SECURITY.md)
- The SSH protocol itself, and vulnerabilities in OpenSSH or `sshd`
- Operating system and package manager issues
- The infrastructure that hosts the Nokku core

## Running nokkud securely

`nokkud` is a privileged daemon. It serves SSH on its own port, `:4022` by default, and keeps an authenticated outbound control stream to the core.

### The machine key

Every signing identity is ECDSA P-256. The daemon authenticates to the core with DPoP, and its session token is bound to that key.

- **With a TPM 2.0**, or a vTPM on AWS, GCP, Azure, Proxmox and others, the key is generated inside the TPM and never leaves it. It is derived deterministically, so it survives reboots without storing anything.
- **Restrict the TPM device to the daemon.** The TPM primary is created without an auth value or PCR policy, so any process that can open `/dev/tpmrm0` can use the identity.
- **Without a TPM**, the daemon uses a software key wrapped with a key derived from the machine fingerprint (`/etc/machine-id` and friends). That only stops someone from copying the state file to another machine. It is not encryption against anyone who can read the file, because the fingerprint is public. The key is only as strong as the file permissions.
- **Run with `--require-tpm` on servers that have a TPM.** The daemon then refuses to fall back to the software key.

### The connection to the core

The daemon talks to the core over TLS 1.3 and verifies its certificate. There is no switch to turn that off. A plain `http` API URL is refused unless it points at localhost, which is meant for development. The core's answers carry the CA the daemon trusts, so nobody may be able to change them in transit.

### Local state

Enrollment state and the cached access list live under `/var/lib/nokkud/`, protected by the daemon's privileges. Treat the directory as sensitive.

### Your own sshd

System `sshd` on port 22 is never touched. It is your way back in if Nokku misbehaves, and it is outside `nokkud`'s scope. Logins through it bypass Nokku's checks, audit and recording, so secure and monitor it by your own rules.

### Recordings on the server

- Recordings are written unredacted to `/var/lib/nokkud/recordings/` and uploaded to the core. The daemon does no redaction of its own.
- The core scrubs credential patterns after the upload completes. That is best effort. A failed scrub leaves the upload as it is and raises a `RecordingScrubFailed` audit event. It is not retried.
- Anyone with access to the recordings directory, or to the core's storage, can read what was on the terminal.

### Account limits

Sessions never go through PAM. A granted user runs with their own OS privileges and no session resource cap. Bound them with systemd slices or per-user limits if that matters for your threat model.

### Releases

- Releases are built with GoReleaser. Each one publishes `checksums.txt`, a cosign signature bundle for it (`checksums.txt.sigstore.json`) and a CycloneDX SBOM per binary.
- `install.sh` checks the SHA-256 of the tarball against the manifest. It verifies the manifest with cosign when cosign is available, and stops on a mismatch.
- You can check the manifest by hand with `cosign verify-blob`, against the bundle and the GitHub Actions OIDC issuer.
- The deb, rpm and apk packages come from the Cloudsmith repository. The package manager checks them against the repository key.

## How the SSH server behaves

### Who gets in

- **Certificates only.** No passwords, no keyboard-interactive, no PAM. A login needs a user certificate signed by the workspace CA, with a principal that the daemon's cache maps to the requested local user.
- **A certificate is for one server and its accounts.** The core signs a user certificate for one server, with one principal per account the user is granted there at that moment. The daemon compares principals as whole strings, so a certificate for another server or account opens nothing.
- **`/etc/nologin` is honored.** When the file exists, logins are refused for every user except root, like OpenSSH does. That lets you put a machine into maintenance.
- **An account expiry date is honored.** A user past the day set with `chage -E` is refused, as OpenSSH does through `pam_unix`. Root is not exempt.
- **Account lock is the OS's job.** Because sessions skip PAM, the daemon does not enforce `pam_limits`, `pam_access`, locked passwords or password expiry. The login shell from the password database is used as it is, so a `nologin` or `false` shell still ends the session.

### When the core is away, and when access is revoked

- **The offline window is bounded by the certificate lifetime.** When the core is unreachable, logins still work against the cached CA key and principal map. New access changes and certificate renewals need a reconnect.
- **A revoke that never reaches the daemon still stops new logins** once the user's last certificate expires, since the core signs no new one without the grant. A connection that is already open stays open until the daemon syncs again. A relayed one ends after 8 hours at most.
- **A daemon that syncs applies a revoke at once** and closes the connections that were open on it.
- **An approval can be taken back.** A daemon set back to pending drops its principals and its CA at the next sync. The core signs no certificates for its server until it is approved again.
- **A retired CA has a deadline.** After a CA rollover the core sends the previous key with a deadline, and the daemon trusts it until then, so certificates it signed keep working. An emergency rollover sends no previous key, which ends that trust at the next sync. That sync also closes the connections still open on a certificate of a CA it no longer trusts.
- **A sync never waits for the host certificate.** Principals and trusted CAs are applied as soon as they arrive. The host certificate is renewed apart from them, at half of its lifetime or when the CA changes. A signing failure cannot hold back a revoke.

### What a session may do

- **Sessions run as the target OS user.** The daemon has to run as root so it can drop privileges. It refuses to serve SSH unprivileged, so it never runs a session as the wrong user.
- **The client environment is an allowlist.** Sessions accept only locale and terminal variables from clients (`TERM`, `LANG`, `LC_*`, `TZ` and the like). They never accept variables that affect the shell or the loader (`PATH`, `LD_*`, `BASH_ENV`, `ENV`), or connection metadata (`SSH_*`). A certificate with a `force-command` critical option refuses all client-supplied environment. The command the client asked for is passed to the forced one as `SSH_ORIGINAL_COMMAND`, like sshd does, so restricted wrappers such as `git-shell` work.
- **Only modern algorithms are offered.** Key exchange, MACs and client key signatures are limited to the set OpenSSH ships by default. SHA-1 key exchange, `hmac-sha1-96`, `ssh-rsa` signatures and DSA keys are refused.
- **Remote forwards are loopback-only by default**, like OpenSSH's `GatewayPorts=no`. An authorized user cannot expose services on the server's external interfaces. Direct forwards (outbound `-L`) are written to the audit log with their destination.
- **Forwards are made by the daemon, as root.** It dials direct forwards and binds remote ones itself. Firewall rules that match on the user (nftables `meta skuid`, the iptables `owner` match) see the daemon and not the session's user.
- **Channels are capped per connection.** Sessions, port forwards and agent forwards count against one fixed cap for the life of each channel. The listener of a remote forward takes a slot as well, for as long as it is open. One authorized connection cannot exhaust the daemon's file descriptors or goroutines.
- **Relayed connections carry the user's address.** A connection through the core's relay is served in process, not over loopback. Audit events, `SSH_CLIENT` and `source-address` certificate options see the address the core reported for the user.
- **The daemon is not sandboxed.** Sessions are its children and would inherit any systemd, AppArmor or SELinux confinement, which would stop a root session from doing normal admin work. Like in OpenSSH, the user boundary isolates sessions. Every connection lives in the daemon process, so a restart or package upgrade ends live sessions.

### Audit and recording

- **Audit events go to the daemon's log.** Auth, session, command, subsystem, forward and remote forward events are written as `audit` lines with a `type`. Under systemd that is journald, under OpenRC it is `/var/log/nokkud.log`. Retention is the log's own.
- **Interactive sessions are recorded** as gzipped asciicast under `/var/lib/nokkud/recordings/`, tied to audit events by `session_id`. Input is recorded only while the PTY has echo enabled, so password prompts are left out.
- **A web terminal session is recorded under the core's session id.** The core puts it in the key id of the certificate it mints for the session, which the CA signs. Nothing a client sends can label a recording, so a direct login cannot claim another session's id.
- **Non-interactive `exec` sessions** are captured as `command` audit events (command line, user, exit code) and as recordings of their output. They have no echo signal, so only output is captured.
- **SFTP**, and so modern `scp`, is audited as a `subsystem` event. File contents are not recorded.
- **Recordings stream to the core live.** Any that the core did not fully receive (offline, upload error, crash) are uploaded again every few minutes. Once the core confirms a recording, the local file is deleted. The core then holds the only copy and its retention applies.
- **A recording that waits too long is dropped**, with a warning in the log: after 30 days, or oldest first once the waiting ones pass 1 GiB.
- **Recording fails open, except at the size cap.** A session that cannot be recorded (under 512 MiB free, a file error) still runs, so a full disk never locks admins out. Every gap raises a `recording_degraded` audit event with the reason. A recording that reaches the 50 MB cap ends its session with a notice, so flooding output cannot switch recording off.

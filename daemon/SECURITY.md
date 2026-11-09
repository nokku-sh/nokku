# Security of nokkud

`nokkud` is a privileged daemon. It serves SSH on its own port, `:4022` by default, and keeps an authenticated outbound connection to the core. This file is for people who run it and for anyone who has to assess it.

Found a vulnerability? Don't open a public issue. See [SECURITY.md](../SECURITY.md) for how to report it.

## In short

- **Keep `/var/lib/nokkud` to root.** It holds the server's identity in Nokku and its SSH host key.
- **Logins need a certificate.** No passwords, no plain keys, no PAM.
- **A revoke closes open sessions** as soon as the daemon syncs.
- **Your own `sshd` on port 22 is never touched.** It is your way back in, and outside Nokku's checks.
- **Recordings are not redacted.** Treat them like the server they come from.

## Scope

In scope:

- The `nokkud` binary: enrollment, SSH host certificates, the SSH server's certificate checks and session handling, and the connection to the core
- The local state it writes under `/var/lib/nokkud/`:
  - `daemon.json`, the enrollment and the synced access. The trusted CA keys are part of it
  - `state.json`, the daemon's signing identity toward the core, with a `.lock` file next to it
  - `ssh_host_ecdsa_key`, the SSH host key, with its public key and host certificate
  - `recordings/`

Out of scope:

- The core and web app, which have [their own file](../core/SECURITY.md)
- The SSH protocol itself, and vulnerabilities in OpenSSH or `sshd`
- Operating system and package manager issues
- The infrastructure that hosts the core

## Running nokkud securely

### The machine key

The daemon authenticates to the core with DPoP, so its session token is bound to an ECDSA P-256 key on the machine.

- **With a TPM 2.0**, or a vTPM on AWS, GCP, Azure, Proxmox and others, the key is made inside the TPM and never leaves it. The TPM's wrapped copy sits in `state.json`, readable by root only. It does not load on another machine.
- **Run with `--require-tpm`** on servers that have a TPM, so the daemon never falls back to a software key.
- **Without a TPM**, the key is a software key wrapped with a key derived from the machine's ID. That only stops a copy from working on another machine. The ID is no secret, so the key is only as strong as the file permissions.
- **The key has no auth value or PCR policy.** A process that can read the state files and open `/dev/tpmrm0` can use the identity. The TPM alone is not enough, so keep the folder to root.

### The SSH host key

- **It is a normal OpenSSH key file**, `ssh_host_ecdsa_key`, mode 0600, made at every enrollment. The daemon refuses a host key that others can read.
- **It is not in the TPM.** Every handshake signs with the host key before the client logs in, and a TPM signs far slower than the CPU. A flood of connections would queue up in front of real logins.
- **A copied host key works elsewhere.** Someone who copies `/var/lib/nokkud` to another machine can pose as this server until its host certificate expires. They need root on this server for that.

### Enrollment tokens

- **An enrollment token is a key to the servers it makes.** A server it enrolls gets the token's grants and tags, so whoever holds the token can add a machine that people with those grants log in to. Give it a use limit and an end date, and delete it once the rollout is done.
- **An ephemeral token can also take over names.** A new container of the same hostname replaces an offline one that the same token enrolled, so people who `ssh` by name reach the newcomer. That is what makes devboxes work across `docker rm -f`, and it means a leaked ephemeral token can claim the name of any of its servers while that one is offline. Keep these tokens in a secret store, never baked into an image.

### Everything else

- **The connection to the core** uses TLS 1.3 and always verifies the core's certificate. A plain `http` URL is refused unless it points at localhost, for development.
- **Your own `sshd`** is outside `nokkud`'s scope. Logins through it bypass Nokku's checks, audit and recording, so secure and monitor it by your own rules.
- **Recordings** wait in `/var/lib/nokkud/recordings/` until the core has them. Anyone who can read that folder can read what was on the terminal. On the core every recording is encrypted with a key of its own.
- **Account limits.** Sessions never go through PAM. A granted user runs with their own OS privileges and no resource cap. Bound them with systemd slices or per-user limits if that matters to you.
- **Upgrades.** Under systemd an upgrade goes live once the last session ends, an hour later at most. Under OpenRC it waits for a restart. Restart `nokkud` by hand when a fix can't wait.

### Releases

- Releases are built with GoReleaser. Each one publishes `checksums.txt`, a cosign signature bundle for it (`checksums.txt.sigstore.json`) and a CycloneDX SBOM per binary.
- `install.sh` checks the SHA-256 of the tarball against the checksums. It verifies them with cosign when cosign is available, and stops on a mismatch. You can check by hand with `cosign verify-blob`, against the bundle and the GitHub Actions OIDC issuer.
- The deb, rpm and apk packages come from the Cloudsmith repository. The package manager checks them against the repository key.

## How the SSH server behaves

### Who gets in

- **Certificates only.** No passwords, no keyboard-interactive, no PAM. A login needs a user certificate signed by the workspace CA's user key, with a principal the daemon's access list maps to the requested user. The CA's host key never signs a login.
- **A certificate is for one server and its accounts.** It names one principal per account the user was granted there, and the daemon compares them as whole strings. A certificate for another server or account opens nothing.
- **`/etc/nologin` is honored.** When the file exists, logins are refused for everyone but root, like OpenSSH does.
- **An account expiry date is honored.** A user past the day set with `chage -E` is refused, like OpenSSH does through `pam_unix`. Root is not exempt.
- **Account lock is the OS's job.** Because sessions skip PAM, the daemon does not enforce `pam_limits`, `pam_access`, locked passwords or password expiry. The login shell is used as it is, so a `nologin` or `false` shell still ends the session, and stops SFTP too. A port forward needs no shell, as in sshd.

### Revokes and outages

- **A daemon that syncs applies a revoke at once** and closes the connections that were open on it.
- **When the core is unreachable**, logins still work against the cached CA key and access list. An open session runs on until a sync that revokes it, or until it ends.
- **A revoke that never reaches the daemon** still stops new logins once the user's last certificate expires, since the core signs no new one without the grant. A relayed connection ends after 8 hours at most.
- **An approval can be taken back.** A daemon set back to pending drops its access list and its CA at the next sync. The core signs nothing for its server until it is approved again.
- **A rollover ends the old CA at the next sync.** From then on the daemon trusts only the new key, and closes the connections still open on a certificate of the old one.
- **A sync never waits for the host certificate.** The access list and CA keys apply as soon as they arrive. The host certificate is renewed apart from them, at half of its lifetime or when the CA's host key changes, so a signing failure can't hold back a revoke.

### What a session may do

- **Sessions run as the target OS user.** The daemon runs as root only so it can drop privileges, and refuses to serve SSH without root. A test running as root in a container checks that the shell, exec, file transfer, both kinds of port forward, the agent socket and signals all reach the OS as the user.
- **The client environment is an allowlist.** Only locale and terminal variables are accepted, like `TERM`, `LANG`, `LC_*` and `TZ`. Never `PATH`, `LD_*`, `BASH_ENV`, `ENV` or `SSH_*`.
- **Only modern algorithms are offered.** The modern set Go's SSH library supports. SHA-1 key exchange, `hmac-sha1-96`, `ssh-rsa` signatures and DSA keys are refused.
- **Remote forwards are loopback-only by default**, like OpenSSH's `GatewayPorts=no`. Direct forwards are written to the audit log with their destination.

<details>
<summary><b>Forced commands, forwards, signals and limits</b></summary>

- **A forced command**, which only a service account's certificate can carry, refuses all client-supplied environment. The command the client asked for is passed along as `SSH_ORIGINAL_COMMAND`, like sshd does, so wrappers such as `git-shell` work.
- **Forwards are opened as the session user.** A helper that runs as the user dials direct forwards and binds remote ones, then hands the socket to the daemon. Firewall rules that match on the user, like nftables `meta skuid` or the iptables `owner` match, see the session's user. Connections that arrive on a remote forward are accepted by the daemon, so those still count as root's.
- **Signals from the client are sent as the session user.** A process that became privileged, like a `sudo` the user started, can't be signaled this way. A forced command and SFTP take no signals from the client, like in sshd.
- **Channels are capped per connection.** Sessions, port forwards, agent forwards and remote forward listeners all count against one fixed cap, so one connection can't exhaust the daemon's file descriptors.
- **Relayed connections carry the user's address.** A connection through the relay is served in process, not over loopback. Audit events, `SSH_CLIENT` and a certificate's `source-address` see the address the core reported for the user.
- **The daemon is not sandboxed.** Sessions are its children and would inherit any systemd, AppArmor or SELinux confinement, which would stop a root session from doing normal admin work. Like in OpenSSH, the user boundary isolates sessions.

</details>

### Audit and recording

- **Audit events go to the daemon's log** as `audit` lines with a `type`: logins, sessions, commands, subsystems, forwards and idle timeouts. Under systemd that is journald, under OpenRC `/var/log/nokkud.log`.
- **Sessions with a terminal are recorded**, when recording is on for the daemon. Input is recorded only while the terminal echoes, so password prompts are left out.
- **Sessions without a terminal**, like `ssh host command`, are logged as `command` events, and their output is recorded.
- **SFTP**, and so modern `scp`, is logged as a `subsystem` event. File contents are not recorded.
- **Recording fails open.** A session that can't be recorded, like on a nearly full disk, still runs, so a full disk never locks admins out. Every gap raises a `recording_degraded` event.
- **A recording has a size cap.** At 50 MiB of compressed recording, a session with a terminal ends with a notice, so flooding output can't switch recording off. A session without a terminal is capped at 5 MiB and runs on, unrecorded past the cap, so `git clone` or `pg_dump` over ssh still finish.

<details>
<summary><b>How recordings reach the core</b></summary>

- **Files.** Recordings are gzipped asciicast. The recorder writes `recordings/<id>.part`, and only a recording that closed whole is synced and renamed to `<id>.cast.gz`. A direct session's recording shares its `session_id` with the audit events.
- **Web terminal sessions** are recorded under the core's session id, which the core puts in the key id of the certificate it signs for the session. Nothing a client sends can label a recording.
- **Upload while the session runs.** One upload per recording reads the file as it grows. After a break, like the core being offline, it starts again from the first byte until the core holds all of the file. Then the local file is deleted, and the core's retention applies.
- **A stop or a crash keeps what was recorded.** Stopping the daemon ends its sessions like a hangup and waits a few seconds for their uploads. What is left on disk goes to the core at the next start. A crash loses at most the last second of output.
- **Ephemeral hosts** normally remove themselves when they stop. With recordings still unsent, one stays enrolled and keeps them, until the core retires it. A container that loses its disk loses them, so keep `/var/lib/nokkud` on a volume if that matters.
- **Complete or not.** The last upload says how big the file is and, for a cut recording, why it stops early. A crash, a write error or the size cap leave a recording the console shows as incomplete, with the reason in the core's audit log.
- **Old leftovers are dropped** when the next recording starts, with a warning: after 30 days, or oldest first once the waiting ones pass 1 GiB.
- **The disk floor.** A session isn't recorded when less than 512 MiB is free. A disk that fills in the middle of a session stops the recording there, and the session runs on.
- **A capped command** closes its recording at the cap, so the console stops listing it as live, and the recording has no exit code. The exit code is on the `session_end` audit event.

</details>

### What sshd does that nokkud does not

`nokkud` is its own SSH server and never goes through PAM or the login machinery of the OS. Tools that rely on it see no session.

- **No login records.** `who`, `w`, `last` and `lastlog` don't show these sessions. The daemon's `audit` lines are the record of who logged in.
- **No loginuid.** `/proc/<pid>/loginuid` stays unset, so `auditd` rules can tie what a session does only to the daemon.
- **No logind session.** `loginctl` doesn't list it, there is no `XDG_RUNTIME_DIR`, and `systemctl --user` doesn't work in it.
- **No other PAM modules either**: no `pam_limits`, `pam_access`, `pam_env` or `pam_systemd`. The daemon checks `/etc/nologin` and the account expiry itself.

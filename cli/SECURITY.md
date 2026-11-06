# Security

This file has two parts. The first is for reporting a vulnerability. The second is for people who use `nk` and want to know how it protects them.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private reporting instead:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Tell us as much of this as you can:
   - The `nk` version and your platform or distribution
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

- The `nk` binary: the browser sign-in, service account tokens, requesting SSH certificates and the OpenSSH `ProxyCommand`
- The local state it writes under `~/.config/nk/`:
  - `config.json` and `cache.json`
  - `ssh-signer.json`, the SSH signing identity, and `signer.json`, the DPoP signing identity
  - `security-key` and `security-key.pub`, the handle of a security key from `nk login --security-key`
  - `agent.sock`, the local agent socket `ssh` uses for signing
  - `ssh_config`, `known_hosts` and `nokku.pub`
  - `certs/`, the SSH certificates the core signed

### Out of scope

- The Nokku core and web app, which have their own [policy](../core/SECURITY.md)
- The SSH protocol itself, and vulnerabilities in OpenSSH or `sshd`
- Operating system and package manager issues
- The infrastructure that hosts the Nokku core

## Using nk securely

`nk` runs on your workstation. It holds your sign-in tokens, manages your SSH key and asks the core for signed SSH certificates.

### How nk protects your key

- **With a TPM 2.0**, on Linux and Windows, your SSH private key is created inside the TPM and never leaves it. The TPM wraps it to itself, and `nk` keeps that blob as a TSS2 key file in `~/.config/nk`. Using the key takes the file and the TPM, so another user on the machine cannot use it even when they may use the TPM. `nk` uses a TPM automatically when it finds one.
- **Signing happens in a small background agent.** `nk` starts it on the first SSH connection and stops it after 30 idle minutes. `ssh` reads the key only through the agent socket, never directly.
- **Without a TPM**, `nk` falls back to a software ECDSA P-256 key, wrapped with a key derived from the machine fingerprint. The state file is useless on another machine, unless that machine's ID is copied along, as a full backup or a VM clone does. On the machine itself it is only as safe as its file permissions.
- **`--require-tpm` refuses software keys.** The SSH key may then be in the TPM or on a security key, the key `nk` signs in to Nokku with must be in the TPM. Use it where a TPM is expected.
- **On macOS** there is no TPM, so the key is the software key above. `--require-tpm` refuses it.
- **With `nk login --security-key`** the key lives on a FIDO2 security key. `ssh` talks to it directly, not through the agent, and the key signs only after a touch. The handle file `nk` keeps is useless without the key.

`nk doctor` shows which of these is in use.

### What a compromised machine can do

A sign-in registers your SSH public key with the core, and the core signs certificates for that key only. A new key needs a new sign-in. So malware that uses your session can't get a certificate for a key of its own and carry it off.

| Key                  | Malware takes your access off the machine | Malware uses ssh on the machine without you |
| -------------------- | ----------------------------------------- | ------------------------------------------- |
| Software key (macOS) | yes, it can copy the key file             | yes                                         |
| TPM                  | no                                        | yes, through the agent                      |
| Security key         | no                                        | no, every login needs a touch               |

None of these stops malware that rides along on a session you opened yourself.

### Your local state

- Everything under `~/.config/nk/` is a credential: the signer state, the SSH certificates and the sign-in tokens. Protect the directory.
- `nk logout` removes it and stops the agent.

### Service account tokens

- Sessions from `nk login` are bound to your machine key, and get certificates only for the SSH key they signed in with. A service account token is not bound, it is a plain bearer token. Treat it like a password.
- Pass it as `NK_TOKEN`. It is never accepted as a flag.
- Keep it out of source control, and use your CI system's secret store.

### TLS

TLS verification cannot be turned off. An `http://` API URL is refused, unless it points at this machine.

A core whose certificate comes from a private CA is trusted through that CA, and only for that core. Pass the CA with `--ca-file` or `NK_CA_FILE`. `nk` never fetches a CA from the server and never asks whether to trust one. A certificate from a CA it does not know fails with an error that names `--ca-file`.

The CA is stored in `~/.config/nk/config.json` and dropped when `--api` changes. Every request is verified the normal way, against the system roots plus that CA. `nk` installs it nowhere else, so the browser sign-in needs it in the browser or the system trust store.

### Releases

- Releases are built with GoReleaser. Each one publishes `checksums.txt`, a cosign signature bundle for it (`checksums.txt.sigstore.json`) and a CycloneDX SBOM per binary.
- `install.sh` checks the SHA-256 of the binary it downloads against the checksum manifest. It verifies the manifest with cosign when cosign is available, and stops on a mismatch.
- You can check the manifest by hand with `cosign verify-blob`, against the attached bundle and the GitHub Actions OIDC issuer.
- The deb, rpm and apk packages come from the Cloudsmith repository. The package manager checks them against the repository key.

## What to know about the design

**Offline.** When the core is unavailable, `nk` uses cached target data and a certificate you still hold. It cannot refresh access or get a new certificate until the core is back.

**Servers enforce access, not `nk`.** `nk` shows what you can reach, but the server decides. A revoke applies on the server, whatever the local cache says.

**One CA per workspace.** `nk` keeps the public keys of the workspace's CA with the access it caches, and checks every new certificate and every daemon's host certificate against them. A rollover reaches it at the next sync. `nk sync` reads the key from the core each time it runs and writes it to `/etc/ssh/nokku_ca.pub`. Its report to the core names that key, and the core refuses it if a rollover replaced the key in the meantime, so a server never counts as current while it holds an old key. A server set up that way trusts the old key until its next `nk sync`, so until then `nk` keeps the certificate it holds for that server while it is valid, and does not swap it for one the server would refuse.

**Limits are on the certificate.** A person's certificate carries the source list of the workspace's CA. A service account's carries its own forced command and source list, and nothing from the CA. A forced command also turns off port forwarding, agent forwarding and `~/.ssh/rc`. The server enforces both, not `nk`.

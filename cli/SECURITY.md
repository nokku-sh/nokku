# Security of nk

`nk` runs on your workstation. It holds your sign-in, manages your SSH key and asks the core for signed SSH certificates. This file says how it protects them.

Found a vulnerability? Don't open a public issue. See [SECURITY.md](../SECURITY.md) for how to report it.

## In short

- **Your SSH key stays on the machine.** In a TPM or on a security key it can't even be copied off.
- **Your sign-in gets certificates for its own key only.** Malware can't take your access to a key of its own.
- **Everything under `~/.config/nk/` is a credential.** Protect it. `nk logout` removes it, all but `signer.json`. That is the key the core knows this machine by, and it opens nothing without a sign-in. Delete the file to have the core forget this machine. Your next sign-in then counts as a new device.
- **A service account key is a password.** Keep it in a secret store and pass it only as `NK_TOKEN`.
- **The servers enforce access, not `nk`.**

## Scope

In scope:

- The `nk` binary: the browser sign-in, service account and CI sign-in, requesting SSH certificates and the OpenSSH `ProxyCommand`
- The local state it writes under `~/.config/nk/`:
  - `config.json` and `cache.json`
  - `ssh-signer.json`, the SSH signing identity, and `signer.json`, the DPoP signing identity, each with a `.lock` file next to it
  - `security-key` and `security-key.pub`, the handle of a security key from `nk login --security-key`
  - `agent.sock`, the local agent socket `ssh` uses for signing. On Windows it is a named pipe instead
  - `ssh_config`, `known_hosts` and `nokku.pub`
  - `certs/`, the SSH certificates the core signed

Out of scope:

- The core and web app, which have [their own file](../core/SECURITY.md)
- The SSH protocol itself, and vulnerabilities in OpenSSH or `sshd`
- Operating system and package manager issues
- The infrastructure that hosts the core

## Using nk securely

### How nk protects your key

- **With a TPM 2.0**, on Linux and Windows, your SSH private key is created inside the TPM and never leaves it. `nk` keeps the TPM's wrapped copy in its state file. Using the key takes the file and the TPM, so another user on the machine can't use it, even one who may use the TPM. `nk` uses a TPM automatically when it finds one.
- **Without a TPM**, `nk` uses a software ECDSA P-256 key, wrapped with a key derived from the machine's ID. The file is useless on another machine, unless that machine's ID is copied along, as a full backup or a VM clone does. On the machine itself it is only as safe as its file permissions. This is the case on a Mac.
- **With `nk login --security-key`** the key lives on a FIDO2 security key. `ssh` talks to it directly, and the key signs only after a touch. The handle file `nk` keeps is useless without the key.
- **Signing happens in a small background agent**, for the TPM and the software key. `nk` starts it on the first SSH connection and stops it after a while without use. `ssh` reads the key only through the agent socket.
- **`--require-tpm` refuses software keys.** The SSH key may then be in the TPM or on a security key, but the key `nk` signs in to Nokku with must be in the TPM. So it refuses to run on a Mac.

`nk doctor` shows which of these is in use.

### What a compromised machine can do

A person's sign-in registers their SSH public key with the core, and the core signs certificates for that key only. A new key needs a new sign-in. So malware that uses your session can't get a certificate for a key of its own and carry it off.

| Key                  | Malware takes your access off the machine | Malware uses ssh on the machine without you |
| -------------------- | ----------------------------------------- | ------------------------------------------- |
| Software key (macOS) | yes, it can copy the key file             | yes                                         |
| TPM                  | no                                        | yes, through the agent                      |
| Security key         | no                                        | no, every login needs a touch               |

None of these stops malware that rides along on a session you opened yourself.

The table holds until your next `nk login`. Malware that runs as you can replace `nk` or its files with ones that use a software key, then wait for you to sign in again. The core can't tell which kind of key it is asked to certify, so a sign-in on an infected machine hands over that sign-in. `--require-tpm` is kept until `nk logout`, but it lives in a file that malware can edit too. Treat an infected machine as lost: end its sessions from another device on **Profile, Security**, or have an admin deactivate your account, and set the machine up again before you sign in on it.

### Signing in

- **The browser hands its answer to `nk` on this machine.** `nk login` waits on `127.0.0.1`, and approving in the browser sends a one-time code there. The session needs that code and the device code `nk` holds. So a sign-in link someone sends you approves nothing for them: the answer lands on your machine, where their `nk` isn't.
- **A headless code is typed, never clicked.** With `--headless` the approval page refuses a code that came in a link and asks you to type it. Type only a code your own terminal shows.
- **Never copy the address the browser lands on after you approve.** It holds the one-time code. Nobody, IT included, needs it.

### Sessions and service account keys

- **A session from `nk login`** is bound to a machine key with DPoP, so a copied session token is useless elsewhere. A person's session gets certificates only for the SSH key it signed in with. It lasts 30 days, or one day where the workspace requires single sign-on, and no certificate outlives it.
- **It makes only the calls `nk` needs**: certificates, the list of what you reach, the relay, access requests and `nk sync`. It pins a new host key and deletes a target only for a server you added. The README says what everyone else does, for [a host key](./README.md#when-a-host-key-changes) and for [removing a server](./README.md#removing-a-server). Roles, grants, recordings and tokens are changed in the web app only, also by an owner.
- **A session from `nk login --ci`** is bound to the runner's key too, but like any service account it may get certificates for any key it sends.
- **A service account key** is not bound, it is a plain bearer token. Treat it like a password. Pass it as `NK_TOKEN`, it is never accepted as a flag. Keep it out of source control.

### TLS

TLS verification can't be turned off. An `http://` API URL is refused, unless it points at this machine.

A core whose certificate comes from a private CA is trusted through that CA, and only for that core. Pass it with `--ca-file` or `NK_CA_FILE`. `nk` never fetches a CA from the server and never asks whether to trust one. It keeps the CA in `config.json`, drops it when `--api` changes, and installs it nowhere else, so the browser sign-in needs it in the browser or the system trust store.

### Releases

- Releases are built with GoReleaser. Each one publishes `checksums.txt`, a cosign signature bundle for it (`checksums.txt.sigstore.json`) and a CycloneDX SBOM per binary.
- `install.sh` checks the SHA-256 of the binary it downloads against the checksums. It verifies them with cosign when cosign is available, and stops on a mismatch. You can check by hand with `cosign verify-blob`, against the bundle and the GitHub Actions OIDC issuer.
- The deb, rpm and apk packages come from the Cloudsmith repository. The package manager checks them against the repository key.

## What to know about the design

**Offline.** When the core is unavailable, `nk` uses cached access and the certificates you still hold. It can't refresh access or get a new certificate until the core is back.

**Servers enforce access, not `nk`.** `nk` shows what you can reach, but the server decides. A revoke applies on the server, whatever the local cache says.

**Limits are on the certificate.** A person's certificate carries the workspace's source list. A service account's carries its own forced command and source list. A forced command also turns off port forwarding, agent forwarding and `~/.ssh/rc`. The server enforces them, not `nk`.

**The CA.** `nk` keeps the public keys of the workspace's CA with the access it caches, and checks every new certificate and every daemon's host certificate against them. A rollover reaches it at the next sync.

<details>
<summary><b><code>nk sync</code> and a CA rollover</b></summary>

`nk sync` reads the CA key from the core each time it runs and writes it to `/etc/ssh/nokku_ca.pub`. Its report to the core names that key, and the core refuses the report if a rollover replaced the key in the meantime, so a server never counts as current while it holds an old key. Until its next `nk sync`, such a server trusts only the old key, so `nk` keeps the certificate it holds for that server while it is valid, and does not swap it for one the server would refuse.

</details>

<p align="center">
  <img src="../.github/nk.svg" height="80" alt="nk logo">
</p>

<p align="center">
  <a href="https://github.com/nokku-sh/nokku/releases"><img src="https://img.shields.io/github/v/tag/nokku-sh/nokku?label=Version" alt="Version"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue" alt="License"></a>
  <a href="https://github.com/nokku-sh/nokku/actions"><img src="https://img.shields.io/github/actions/workflow/status/nokku-sh/nokku/ci.yaml?label=Build" alt="Build"></a>
</p>

# nk

`nk` is the Nokku CLI for your own machine. It signs you in, keeps your short-lived SSH certificates fresh and sets up your SSH config.

There are no new SSH commands to learn. Once you are signed in, you connect with the plain `ssh` you already know.

`nk` is one of three parts. [`nokku`](../core) is the core that decides who may log in where. [`nokkud`](../daemon) is the daemon on your servers.

## Quick start

Install it:

```bash
curl -fsSL https://get.nokku.sh/nk | sh      # Linux and macOS
irm https://get.nokku.sh/nk.ps1 | iex        # Windows, in PowerShell
```

Sign in and connect:

```bash
nk login          # opens your browser, then syncs your SSH config
nk ls             # lists the servers you can reach
ssh user@target   # plain OpenSSH
```

On a self-hosted core, point `nk` at it once. It remembers the address:

```bash
nk --api https://nokku.example.com login
```

Run `nk doctor` when something does not work. It checks the connection to the core, your key and your SSH setup. `nk doctor --fix` repairs what it can.

## Install options

The installer picks the right way for your system:

- **Linux:** it adds the Cloudsmith repository and installs your distro's package (deb, rpm or apk).
- **macOS, other distros and machines without root:** it downloads the release binary from GitHub to `~/.local/bin`. Pass `--system` to use `/usr/local/bin`.
- **Windows:** it downloads the release binary from GitHub to `%LOCALAPPDATA%\Programs\nk` and adds that folder to your PATH. No admin rights needed.
- **A pinned version:** pass `--version <x.y.z>` or set `NK_VERSION=<x.y.z>`. On Windows only the variable works.

Every binary download is checked against the release checksums. When [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) is installed, the signature on the checksum file is verified too. Packages are verified by your package manager with the repository key.

Prefer to add the package repository yourself? The [package repository](https://broadcasts.cloudsmith.com/nokku/nk) has the apt, dnf and apk instructions.

## How access stays current

- Every `nk ls` refreshes what you can reach.
- An SSH connection refreshes it too, when the last sync is more than a minute old.
- A revoke applies at once, because the server enforces it.
- When the core is unreachable, `nk` fails fast and works from cached data and the certificates you still hold.
- Direct addresses and the Nokku relay are tried in parallel, so an unreachable private address never slows a connection down.

## Where your key lives

On Linux and Windows, `nk` keeps your SSH key in a TPM 2.0 when the machine has one. The key never leaves the chip. Without a TPM it falls back to a software key that only works on this machine. Pass `--require-tpm` to refuse that fallback.

`nk doctor` shows whether a TPM is in use.

> [!NOTE]
> On most Linux distributions `/dev/tpmrm0` belongs to `root:tss`, so a regular user cannot use the TPM by default. Run `sudo usermod -aG tss $USER` and log in again. A udev rule that grants your user access works too.

The details are in [SECURITY.md](./SECURITY.md#how-nk-protects-your-key).

## CI and headless machines

Use a service account key where no browser is around:

```bash
export NK_TOKEN=nk_sa_<SECRET>
nk login
ssh user@target
```

The key has to start with `nk_sa_`. `nk` refuses any other token.

## Servers without the daemon

`nk sync` sets up a server you manage yourself, without installing `nokkud`:

```bash
nk sync 10.0.0.5            # or root@10.0.0.5, or an alias from ~/.ssh/config
nk sync web --dry-run       # show what would change on a known target
```

What it does:

- It connects as root with your own `ssh`, so your keys and SSH config apply and a password is asked at most once.
- It writes the Nokku CA, an sshd drop-in and one principals file per account.
- It checks the result with `sshd -t` and rolls every file back if sshd rejects it.
- Nokku only hears about the sync once the server is written.

Run it again whenever access changes.

A new server can start with access in place, so nobody has to open the web app after the first sync:

```bash
nk sync 10.0.0.5 --grant root=me --grant deploy=team:ops,alice@example.com --tag prod
```

- A `--grant` is `account=subject,subject`. A subject is `me`, an email, `team:<name>` or `sa:<name>`. An id works in place of an email or a name.
- The account has to exist on the server. If it does not, the sync stops and writes nothing.
- Grants and tags are set once, with the new target. On a server Nokku already knows, both are ignored with a warning, so the web app stays the place to change access.

Every user pins the host key that the last sync saw. When it changed, the sync stops and writes nothing. If you reinstalled the server, run it again with `--accept-host-key` to pin the new one.

For scripts, `--json` prints one object with the target, the files written and the stale principals files removed. Progress goes to stderr. With `--dry-run` it is the same object and nothing is written. A dry run of a new server cannot know its principals yet, so their files are empty and `grants` lists the subjects per account as you typed them.

`nk rm` undoes it:

```bash
nk rm web        # or the address, like nk sync
```

It removes the drop-in, the CA and the principals files over the same root `ssh`, reloads sshd, and only then deletes the target in Nokku. If sshd rejects its config without the drop-in, everything is put back and the target stays. Pass `--keep-host` when the server is already gone.

## Commands

| Command                      | Purpose                                                                                       |
| ---------------------------- | --------------------------------------------------------------------------------------------- |
| `nk login` (alias `refresh`) | Sign in and sync local state                                                                  |
| `nk ls` / `nk list`          | List the servers you can reach                                                                |
| `nk doctor`                  | Check the core, the TPM and your local SSH setup                                              |
| `nk sync <host>`             | Add a server without the daemon, or refresh one you added                                     |
| `nk rm <host>`               | Clean up a server you added with `nk sync` and delete its target                              |
| `nk logout`                  | Sign out, stop the agent and remove local credentials and state. Asks about a CA it installed |

### Command flags

| Command     | Flags                                                                                      |
| ----------- | ------------------------------------------------------------------------------------------ |
| `nk ls`     | `--json` for machine-readable output                                                       |
| `nk doctor` | `--fix` to repair permissions and regenerate files, `--json` for output                    |
| `nk sync`   | `--name`, `--ca`, `--grant`, `--tag`, `--port`, `--dry-run`, `--accept-host-key`, `--json` |
| `nk rm`     | `--port`, `--keep-host` to leave the server untouched                                      |

## Configuration

| Flag            | Environment         | Purpose                                                                                                                    |
| --------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `--api`         | `NK_API_URL`        | Address of the core                                                                                                        |
|                 | `NK_TOKEN`          | Service account key (`nk_sa_...`) for CI. Environment only, never a flag                                                   |
| `--ttl`         | `NK_TTL`            | Requested SSH certificate lifetime                                                                                         |
| `--require-tpm` | `NK_REQUIRE_TPM`    | Require a TPM 2.0 or the Secure Enclave, refuse the software key fallback                                                  |
|                 | `NK_SECURE_ENCLAVE` | Set to `1` on macOS to keep new keys in the Secure Enclave. Experimental                                                   |
| `--pin`         | `NK_API_PIN`        | Fingerprint of the core's private CA, `sha256:...`. The web app shows it under **Profile, Security**. Without it `nk` asks |
| `--ca-file`     | `NK_CA_FILE`        | PEM file with the core's private CA, instead of a pin                                                                      |
| `--debug`       | `NK_DEBUG`          | Debug logging                                                                                                              |

`--api` is remembered after the first use. Switching to another core drops the old session. The other flags apply to one run only.

Local state lives under `~/.config/nk/` on every OS.

## Uninstall

```bash
nk logout                  # removes credentials and config
rm -f ~/.local/bin/nk      # or /usr/local/bin/nk after a --system install
rm -rf ~/.config/nk
```

If you installed a package, remove the package instead of the binary. On Windows, delete `%LOCALAPPDATA%\Programs\nk` and `%USERPROFILE%\.config\nk`.

## More

- [Documentation](https://nokku.sh/docs)
- [SECURITY.md](./SECURITY.md), for how `nk` protects your key and for reporting a vulnerability
- [CONTRIBUTING.md](../CONTRIBUTING.md), for building from source

## Hosting

<img alt="Static Badge" src="https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith&style=flat-square&link=https%3A%2F%2Fcloudsmith.com"></img>

Package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com).

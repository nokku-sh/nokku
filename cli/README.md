<p align="center">
  <img src="../.github/nk.svg" height="80" alt="nk logo">
</p>

<p align="center">
  <a href="https://github.com/nokku-sh/nokku/releases"><img src="https://img.shields.io/github/v/tag/nokku-sh/nokku?label=Version" alt="Version"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue" alt="License"></a>
  <a href="https://github.com/nokku-sh/nokku/actions"><img src="https://img.shields.io/github/actions/workflow/status/nokku-sh/nokku/ci.yaml?label=Build" alt="Build"></a>
</p>

# nk

`nk` is the Nokku CLI for your own machine. It signs you in and keeps your SSH certificates fresh, so you connect with the plain `ssh` you already know.

`nk` is one of three parts. [`nokku`](../core) is the core that decides who may log in where. [`nokkud`](../daemon) is the daemon on your servers.

## Quick start

```bash
curl -fsSL https://get.nokku.sh/nk | sh      # Linux and macOS
irm https://get.nokku.sh/nk.ps1 | iex        # Windows, in PowerShell

nk login          # opens your browser, then sets up your SSH config
nk ls             # lists the servers you can reach
ssh user@target   # plain OpenSSH
```

On a self-hosted core, point `nk` at it once with `nk --api https://nokku.example.com login`. It remembers the address.

Something not working? Run `nk doctor`. It checks the core, your key and your SSH setup, and `nk doctor --fix` repairs what it can.

## What it does

- Signs you in through your browser, the way you sign in to the web app. On a machine without one, `nk login --headless` gives you a code to type on another device.
- Gets a short-lived certificate per server right before `ssh` needs it, and renews it on its own.
- Writes an SSH config for your servers and adds one `Include` line to your `~/.ssh/config`. Your own settings stay untouched.
- Connects directly when it can, and through the Nokku relay when it can't.
- Sets up servers without the daemon, with [`nk sync`](#servers-without-the-daemon).

## Commands

| Command                      | Purpose                                                                       |
| ---------------------------- | ----------------------------------------------------------------------------- |
| `nk login` (alias `refresh`) | Sign in and sync local state                                                  |
| `nk ls` / `nk list`          | List the servers you can reach, and until when for access that ends           |
| `nk request <host> <user>`   | Ask an admin for an account on a server for a while, then wait for the answer |
| `nk doctor`                  | Check the core, the TPM and your local SSH setup                              |
| `nk sync <host>`             | Add a server without the daemon, or refresh one you added                     |
| `nk rm <host>`               | Clean up a server you added with `nk sync` and delete its target              |
| `nk logout`                  | Sign out, stop the agent and remove local credentials and state               |

<details>
<summary><b>Flags per command</b></summary>

| Command      | Flags                                                                                                                                                                                                                                                              |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `nk login`   | `--ci <service account>` to sign in a CI job with its platform's token, `--security-key` to keep the key on a FIDO2 security key, kept for later runs, `--security-key=false` to go back to the key on this machine, `--headless` to type a code on another device |
| `nk ls`      | `--json` for machine-readable output, with the `host` ssh knows each server by                                                                                                                                                                                     |
| `nk doctor`  | `--fix` to repair permissions and regenerate files, `--json` for output                                                                                                                                                                                            |
| `nk sync`    | `--name`, `--grant`, `--tag`, `--port`, `--dry-run`, `--accept-host-key`, `--json`                                                                                                                                                                                 |
| `nk request` | `--reason` (required), `--for` from `15m` to `168h`, default `1h`, `--no-wait` to return at once                                                                                                                                                                   |
| `nk rm`      | `--port`, `--keep-host` to leave the server untouched, `--accept-host-key`                                                                                                                                                                                         |

</details>

## Where your key lives

- **In a TPM 2.0**, on Linux and Windows when the machine has one. The key never leaves the chip.
- **As a software key** tied to this machine, without a TPM. This is the default on a Mac.
- **On a FIDO2 security key**, like a YubiKey, on any machine. Sign in with `nk login --security-key`, and every login needs a touch.

Your sign-in only ever gets certificates for that one key. `nk doctor` shows which one is in use. `nk login --security-key` moves the key to a security key and `nk login --security-key=false` moves it back. Both sign this machine in again. A software key moves to the TPM only with `nk logout` and a new sign-in.

> [!NOTE]
> On most Linux distributions a regular user can't use the TPM by default. Run `sudo usermod -aG tss $USER` and log in again, before your first `nk login`. A machine that already signed in with a software key keeps it until you sign out and in again.

<details>
<summary><b>Security keys in detail</b></summary>

`nk` runs `ssh-keygen` once and you touch the key. From then on `ssh` talks to the key itself. Malware on your machine can't copy the key or use it behind your back.

- Each machine makes its own key on the same security key. Nothing is stored on the security key, so it never runs out of room. The file `nk` keeps is useless without the key.
- `ssh` and `ssh-keygen` must support security keys. Most Linux distributions and Windows do. Apple's built-in `ssh` does not, install OpenSSH from Homebrew and put it first in `PATH`. IDEs often run `/usr/bin/ssh`, point them at the Homebrew one.
- A server set up with `nk sync` needs OpenSSH 8.2 or newer to take a security key. RHEL 8 and older releases ship less.
- A lost security key: `nk login --security-key=false` goes back to the key on this machine. For a new one, run `nk logout`, then `nk login --security-key`.

</details>

<details>
<summary><b><code>--require-tpm</code></b></summary>

`--require-tpm` refuses software keys. The SSH key may then be in a TPM or on a security key, but the key `nk` signs in to Nokku with needs a TPM. So on a Mac it refuses to run, also with a security key.

</details>

[SECURITY.md](./SECURITY.md#how-nk-protects-your-key) has what each option protects against.

## CI and headless machines

On a server you `ssh` into, there is no browser to open. `nk login --headless` prints a link and a code. Open the link on any device where you are signed in to Nokku and type the code there. `nk` picks this by itself over plain `ssh`, when no display is set.

A CI job needs no stored secret. GitHub Actions, GitLab and others give every job a signed token, and `nk login --ci` trades it for a short session of a service account. First add a rule under **CI jobs** on the service account in the web app. The rule says which jobs may sign in.

On GitHub Actions, the job needs `id-token: write`. Naming one permission turns the others off, so keep `contents: read` for `actions/checkout`:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    permissions:
      contents: read
      id-token: write
    env:
      NK_API_URL: https://nokku.example.com
    steps:
      - run: curl -fsSL https://get.nokku.sh/nk | sh
      - run: nk login --ci deploy
      - run: ssh deploy@web-1 ./release.sh
```

<details>
<summary><b>GitLab and other platforms</b></summary>

On GitLab, ask for the token with `id_tokens`. Its `aud` is the address of the core, exactly as in `NK_API_URL`:

```yaml
deploy:
  environment: production
  variables:
    NK_API_URL: https://nokku.example.com
  id_tokens:
    NK_ID_TOKEN:
      aud: https://nokku.example.com
  script:
    - curl -fsSL https://get.nokku.sh/nk | sh
    - nk login --ci deploy
    - ssh deploy@web-1 ./release.sh
```

Any other platform with signed tokens works the same way: put the job's token in `NK_ID_TOKEN`, with the address of the core as its audience.

</details>

<details>
<summary><b>How the CI session behaves</b></summary>

- The session lasts an hour at most and never past the job's token. It is bound to a key `nk` holds on the runner, so a session token in a log is worth nothing alone.
- A job token works once, so a retry needs a new one. On GitHub Actions `nk login --ci` fetches a new token each time, so a long job can run it again. On GitLab the token is fixed for the job and is refused once it is about an hour old, so sign in early in the job.
- When the session ends, `nk` fails and says to run `nk login --ci` again. It never waits on a browser.
- A forced command and a source list set on the service account go on its certificates. A forced command also turns off port and agent forwarding.

</details>

For Ansible and scripts that run somewhere without a signed token, use a service account key. CI should not hold one.

```bash
export NK_TOKEN=nk_sa_<SECRET>
nk login
ssh user@target
```

`nk` only takes a key that starts with `nk_sa_`. A key ends within a year at most, so it needs rolling over.

## Servers without the daemon

`nk sync` sets up a server you manage yourself, with plain `sshd` and nothing installed:

```bash
nk sync 10.0.0.5            # or root@10.0.0.5, or an alias from ~/.ssh/config
nk sync web --dry-run       # show what would change on a known target
nk rm web                   # undo it and delete the target
```

- It connects as root with your own `ssh`, so your keys and SSH config apply. On Linux and macOS a password is asked at most once.
- It writes the workspace's CA key to `/etc/ssh/nokku_ca.pub`, and an sshd drop-in, `/etc/ssh/sshd_config.d/60-nokku.conf`, with one fixed rule: let in a certificate Nokku signed for this server and the account asked for.
- It checks the result with `sshd -t` and rolls every file back if sshd rejects it, or if the run breaks off halfway.

**Access changes need no new sync.** A new grant works at once. A revoke stops new logins within an hour, because certificates for these servers last an hour at most. An open session stays until it ends, and these servers have no recording and no relay. **After a CA rollover, run `nk sync` again** on each of them right away.

**Keys in home directories outlive a revoke.** The server's `sshd` still reads `~/.ssh/authorized_keys`, so someone granted an account can add a key there and keep access after a revoke. `nk sync` warns while it does. It logs in with your own root key, so move keys to a root-owned file instead of turning them off. [The daemon's SECURITY.md](../daemon/SECURITY.md#your-own-sshd) shows how.

A new server can start with access in place:

```bash
nk sync 10.0.0.5 --grant root=me --grant deploy=team:ops,alice@example.com --tag prod
```

- A `--grant` is `account=subject,subject`. A subject is `me`, an email, `team:<name>` or `sa:<name>`. An id works in place of an email or a name.
- The account has to be a login account on the server, root or a regular user with a shell. If it is not, the sync stops and writes nothing.
- You get `root` on a new server, unless a `--grant` already names you. You have root there already, this only lets you in through Nokku too. A service account gets only the grants it asks for.
- Grants and tags are set once, with the new target. On a server Nokku already knows they are ignored with a warning, so the web app stays the place to change access.

<details>
<summary><b>Host keys, scripts and <code>nk rm</code></b></summary>

- **Finding a server.** `nk sync` and `nk rm` take its name, the name `nk ls` shows, or its address. Pass `--port` when several servers share one address.
- **The first sync** trusts the server the way your own `ssh` does. When `ssh` asks about the host key, answer as you would for any server. Without a terminal, as in CI, connect once with `ssh root@host` first.
- **Later syncs** pin the host key the first one saw, and `ssh` accepts no other. A server that shows another key is refused before you are asked for a password, and nothing is written. If you reinstalled the server, run it again with `--accept-host-key`. That drops the pin and your own `ssh` checks the host, as on the first sync, so a key it remembers from before shows its usual warning until you remove it with `ssh-keygen -R`.
- **Your ssh config applies, but not its forwards.** The root `ssh` runs without an agent, X11 or port forwarding, whatever `ForwardAgent` or `LocalForward` your config sets.
- **Order.** Nokku only hears about the sync once the server is written. A new target is created first, so if the write fails it is removed again.
- **For scripts**, `--json` prints one object with the target and the files `nk sync` manages. Progress goes to stderr. With `--dry-run` it is the same object and nothing is written. A dry run of a new server has no target id yet, so the drop-in shows `<target-id>` in its place and `grants` lists the subjects per account as you typed them, with your default `root` as `me`.
- **`nk rm`** checks the pinned host key first, then removes the drop-in and the CA over the same root `ssh`, reloads sshd, and only then deletes the target in Nokku. If sshd rejects its config without the drop-in, everything is put back and the target stays. Pass `--keep-host` when the server is already gone.

</details>

## Reference

### Install options

The installer picks the right way for your system:

- **Linux:** it adds the Cloudsmith repository and installs your distro's package (deb, rpm or apk).
- **macOS, other distros and machines without root:** it downloads the release binary from GitHub to `~/.local/bin`. Pass `--system` to use `/usr/local/bin`.
- **Windows:** it downloads the release binary from GitHub to `%LOCALAPPDATA%\Programs\nk` and adds that folder to your PATH. No admin rights needed.
- **A pinned version:** pass `--version <x.y.z>` or set `NK_VERSION=<x.y.z>`. On Windows only the variable works.

Every binary download is checked against the release checksums, and against the cosign signature when [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) is installed. Packages are verified by your package manager. To add the package repository yourself, see the [package repository](https://broadcasts.cloudsmith.com/nokku/nk).

### Configuration

| Flag            | Environment      | Purpose                                                                                                   |
| --------------- | ---------------- | --------------------------------------------------------------------------------------------------------- |
| `--api`         | `NK_API_URL`     | Address of the core                                                                                       |
|                 | `NK_TOKEN`       | Service account key (`nk_sa_...`) for scripts. Environment only, never a flag                             |
|                 | `NK_ID_TOKEN`    | The job's signed token for `nk login --ci`, anywhere but GitHub Actions                                   |
| `--ttl`         | `NK_TTL`         | Requested SSH certificate lifetime, kept for later connections. `0` goes back to the CA default           |
| `--require-tpm` | `NK_REQUIRE_TPM` | Refuse software keys. The SSH key may be in a TPM 2.0 or on a security key, the sign-in key needs the TPM |
| `--ca-file`     | `NK_CA_FILE`     | PEM file with the core's private CA, kept for later runs                                                  |
| `--debug`       | `NK_DEBUG`       | Debug logging                                                                                             |

`--api`, `--ttl` and `--ca-file` are remembered after the first use. Switching to another core drops the old session and its CA. `--require-tpm` is remembered until `nk logout`, also when you switch cores. `--debug` applies to one run only.

Local state lives under `~/.config/nk/` on every OS. On Windows the agent listens on a named pipe instead of a socket in that folder.

<details>
<summary><b>How access stays current</b></summary>

- Every `nk ls` refreshes what you can reach. An SSH connection refreshes it too, when the last sync is a little old.
- A revoke applies at once on servers with the daemon, because the server enforces it. On a server set up with `nk sync` it lands within an hour.
- When the core is unreachable, `nk` fails fast and works from cached data and the certificates you still hold.
- Direct addresses are tried in parallel, and the Nokku relay joins a moment later, so an unreachable private address barely slows a connection down.
- When there is another way in, a private address must show the server's own host key first. Another machine at that address on your network, like a NAS at home, is skipped.

</details>

### Uninstall

```bash
nk logout                  # removes credentials and config
rm -f ~/.local/bin/nk      # or /usr/local/bin/nk after a --system install
rm -rf ~/.config/nk
```

If you installed a package, remove the package instead of the binary. On Windows, delete `%LOCALAPPDATA%\Programs\nk` and `%USERPROFILE%\.config\nk`.

## More

- [Documentation](https://nokku.sh/docs)
- [SECURITY.md](./SECURITY.md), for how `nk` protects your key
- [CONTRIBUTING.md](../CONTRIBUTING.md), for building from source

## Hosting

<img alt="Static Badge" src="https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith&style=flat-square&link=https%3A%2F%2Fcloudsmith.com"></img>

Package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com).

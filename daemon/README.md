<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="../.github/nokkud_dark.svg">
    <source media="(prefers-color-scheme: dark)" srcset="../.github/nokkud_light.svg">
    <img src="../.github/nokkud_light.svg" width="80" alt="nokkud">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/nokku-sh/nokku/releases"><img src="https://img.shields.io/github/v/tag/nokku-sh/nokku?label=Version" alt="Version"></a>
  <a href="https://github.com/nokku-sh/nokku/actions"><img src="https://img.shields.io/github/actions/workflow/status/nokku-sh/nokku/ci.yaml?branch=main&label=Build" alt="Build"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue" alt="License"></a>
</p>

# nokkud

`nokkud` is the Nokku daemon for your servers. It runs its own small SSH server on port 4022, next to your normal `sshd`, and lets in whoever Nokku says may log in.

`nokkud` is one of three parts. [`nokku`](../core) is the core that decides who may log in where. [`nk`](../cli) is the CLI on your own machine.

## Quick start

Create an enrollment token in the Nokku web app, on the **Servers** page. Then on the server:

```bash
curl -fsSL https://get.nokku.sh/nokkud | sudo sh    # installs the package and the service
sudo nokkud enroll                                  # paste the token, it is not shown
sudo systemctl restart nokkud
```

On a self-hosted core, enroll with `sudo nokkud --api https://nokku.example.com enroll`. The web app shows these commands with your address filled in.

The server shows up in the web app. Unless the token approves it automatically, someone approves it there before it serves logins.

## What it does

- Checks Nokku certificates and keeps the list of who may log in up to date. A revoke closes open sessions as soon as the daemon syncs.
- Serves every SSH connection itself. There is no proxy in the path.
- Keeps working when the core is down, from the last synced access list.
- Records sessions, when recording is on, and sends the recordings to the core.
- Never touches your `sshd`. It stays on port 22 as your way back in.

## Network

Sessions reach the server in one of two ways, and `nk` tries both at once:

- **Directly on port 4022.** The fastest path. Open it for the networks your users connect from, and in your cloud provider's firewall:

  ```bash
  sudo ufw allow nokkud                                # Debian, Ubuntu
  sudo firewall-cmd --permanent --add-service=nokkud   # Fedora, RHEL
  sudo firewall-cmd --reload
  ```

- **Through the relay.** The daemon keeps an outbound connection to the core, and sessions can travel over it. Nothing has to be opened, and the session stays encrypted end to end.

## Enrollment

- **Unattended installs:** set `NOKKUD_ENROLL_TOKEN` instead of answering the prompt. The token is never taken from the command line, where any local user could read it.
- **The service enrolls itself** on start when `NOKKUD_ENROLL_TOKEN` is set and nothing is enrolled yet. Once enrolled, the variable is ignored.
- **A token can carry grants and tags.** Every server it enrolls starts with them. They are copied once, so later changes in the web app stay.
- **Enrolling again** is safe. With a token from another workspace it moves the server there and drops everything the old one trusted.
- **A private CA.** If the core's certificate comes from one, point `NOKKUD_CA_FILE` at it for the enroll. `nokkud` keeps it.

## Container

The image at `ghcr.io/nokku-sh/nokkud` is for devboxes, CI runners and sandboxes, anything you want to SSH into without opening a port. It enrolls itself on start and is reached through the relay:

```bash
docker run -d --hostname alice -e NOKKUD_ENROLL_TOKEN=... ghcr.io/nokku-sh/nokkud
ssh dev@alice
```

- **Accounts.** Besides root, the image ships one login account, `dev`. Build on it with `FROM ghcr.io/nokku-sh/nokkud` to add your tools and users. The container has to run as root, which is the default.
- **Ephemeral tokens** are made for this. A container enrolled with one is approved right away, deletes itself when it stops, and is removed by the core once it has been offline for a while. A new container of the same name and token takes over from one that went offline. In the first two minutes after the core starts it gets a generated name instead, while the others are still reconnecting.
- **Names.** A hostname a person chose becomes the server's name in Nokku. A random Docker hostname gets a generated name, so pass `--hostname`.
- **A persistent devbox** mounts `/var/lib/nokkud` and keeps its hostname fixed. Without a TPM the identity is bound to the machine, so a volume moved to another host fails to start.

## Reference

### Configuration

| Flag            | Environment          | Purpose                                       |
| --------------- | -------------------- | --------------------------------------------- |
| `--api`         | `NOKKUD_API_URL`     | Address of the core, `https` unless localhost |
| `--ca-file`     | `NOKKUD_CA_FILE`     | PEM file with the core's private CA           |
| `--ssh-addr`    | `NOKKUD_SSH_ADDR`    | Where the SSH server listens. Default `:4022` |
| `--require-tpm` | `NOKKUD_REQUIRE_TPM` | Require a TPM 2.0 and refuse the software key |
| `--debug`       | `NOKKUD_DEBUG`       | Debug logging                                 |

Session rules like recording and port forwarding are set per daemon in the web app. A new daemon starts with the workspace defaults, a later change of the defaults leaves enrolled daemons alone. The idle timeout is the exception, it is one setting for every daemon.

When recording is on, every session with a terminal starts with `nokkud: this session is recorded`, and the web terminal shows a REC badge. Sessions without a terminal, like scp, rsync and git, get no line, since text in their stream would break them.

### Files

Everything `nokkud` owns lives under `/var/lib/nokkud/`:

- `daemon.json` holds the enrollment and the synced access. A host that still has the older `config.json` and `cache.json` is not enrolled anymore, so enroll it again.
- `state.json` is the daemon's identity toward the core. With a TPM, its key never leaves the chip.
- `ssh_host_ecdsa_key` is the SSH host key, a normal OpenSSH key file readable by root only. Every enrollment makes a new one, and the core signs a host certificate for it.
- `recordings/` holds recordings that are not uploaded yet.

### Operations

```bash
sudo systemctl status nokkud
sudo journalctl -u nokkud -f
```

<details>
<summary><b>Outages, rollovers, restarts and upgrades</b></summary>

- **The core is unreachable.** Logins keep working from the last synced access list. Access changes and certificate renewals resume once the daemon reconnects.
- **A CA rollover** reaches a daemon at its next sync. There is nothing to do on the server.
- **A restart** ends the sessions that are open on the daemon, like a hangup. Their recordings still go to the core, the ones it could not send in time at the next start.
- **A package upgrade under systemd** waits for those sessions. The daemon keeps serving and restarts on the new binary once the last connection ends, so an upgrade can run in a session of its own. After an hour it restarts anyway. For a security fix that can't wait, run `sudo systemctl restart nokkud`.
- **Under OpenRC** an upgrade does not restart the daemon. Run `sudo rc-service nokkud restart`.

</details>

### Install options

The installer adds the Cloudsmith repository and installs your distro's package (deb, rpm or apk). Other distros and pinned versions get the release tarball from GitHub. Pin a version with `--version <x.y.z>` or `NOKKUD_VERSION=<x.y.z>`. To add the repository yourself, see the [package repository](https://broadcasts.cloudsmith.com/nokku/nokkud).

<details>
<summary><b>Manual install from the tarball</b></summary>

Download the tarball for your architecture from [Releases](https://github.com/nokku-sh/nokku/releases), then run the bundled installer:

```bash
tar -xzf nokkud_linux_amd64.tar.gz
sudo ./install.sh
```

Prefer to place things yourself? Copy [packaging/systemd/nokkud.service](packaging/systemd/nokkud.service) to `/etc/systemd/system/nokkud.service`, then register and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nokkud
```

On OpenRC or another init system, use [packaging/openrc/nokkud.openrc](packaging/openrc/nokkud.openrc) as a starting point.

</details>

### Uninstall

Reset the daemon first. This removes the server from Nokku and deletes all local state:

```bash
sudo nokkud reset
```

Then remove the package (`apt remove nokkud`, `dnf remove nokkud` or `apk del nokkud`).

<details>
<summary><b>After a manual install</b></summary>

Stop the service and remove what the installer put down:

```bash
sudo systemctl disable --now nokkud
sudo rm -rf /usr/bin/nokkud /usr/share/nokkud /usr/lib/systemd/system/nokkud.service \
  /etc/init.d/nokkud /etc/ufw/applications.d/nokkud /usr/lib/firewalld/services/nokkud.xml
```

</details>

## More

- [Documentation](https://nokku.sh/docs), with the guide for [adding a server](https://nokku.sh/docs/guides/add-server-daemon)
- [SECURITY.md](./SECURITY.md), for how the daemon protects its key and how its SSH server behaves
- [CONTRIBUTING.md](../CONTRIBUTING.md), for building from source

## Hosting

<img alt="Static Badge" src="https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith&style=flat-square&link=https%3A%2F%2Fcloudsmith.com"></img>

Package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com).

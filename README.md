<p align="center">
    <picture>
        <source media="(prefers-color-scheme: light)" srcset="./.github/nokku_dark.svg">
        <source media="(prefers-color-scheme: dark)" srcset="./.github/nokku_light.svg">
        <img src="./.github/nokku_light.svg" width="80" alt="Nokku logo">
    </picture>
</p>

<p align="center">
  <a href="https://github.com/nokku-sh/nokku/actions"><img src="https://img.shields.io/github/actions/workflow/status/nokku-sh/nokku/ci.yaml?branch=main&label=Build" alt="Build"></a>
  <a href="https://nokku.sh/docs"><img src="https://img.shields.io/badge/Docs-nokku.sh-blue" alt="Docs"></a>
  <a href="./LICENSE.md"><img src="https://img.shields.io/badge/License-FCL--1.0%20%2F%20Apache--2.0-blue" alt="License"></a>
</p>

# Nokku

**SSH access without SSH keys to hand out, rotate or forget about.**

Nokku gives people short-lived SSH certificates instead of long-lived keys. You decide who may log in to which server as which account. Nokku signs a certificate for exactly that, and it expires by itself.

```bash
nk login           # opens your browser, good for 30 days
ssh deploy@web-1   # the ssh you already know
```

That is the whole workflow. No new SSH client and no `authorized_keys` to clean up when someone leaves, once your `sshd` [stops reading them from home directories](./daemon/SECURITY.md#your-own-sshd).

## Three parts

Each one has its own README. Pick where you want to start.

| Part                            | What it is                                                                        | Start here                               |
| ------------------------------- | --------------------------------------------------------------------------------- | ---------------------------------------- |
| **[Core](./core)** `nokku`      | Users, access, one CA per workspace, SSO and the web app. One binary, PostgreSQL. | [Run it with Docker](./core#quick-start) |
| **[Daemon](./daemon)** `nokkud` | Runs on a server next to your `sshd` and keeps its access in sync                 | [Add a server](./daemon#quick-start)     |
| **[CLI](./cli)** `nk`           | Signs you in on your machine, then plain `ssh` works                              | [Sign in and connect](./cli#quick-start) |

Don't want a daemon on a server? [`nk sync`](./cli#servers-without-the-daemon) sets up its plain `sshd` instead, with no recording and no relay.

Use the hosted service, or run the core yourself for free. The guides are at [nokku.sh/docs](https://nokku.sh/docs).

## What you get

- **Plain OpenSSH.** `ssh`, `scp`, `rsync` and your editor's remote mode work as before.
- **No passwords anywhere.** People sign in with a passkey or your identity provider.
- **Access you can read.** This person or team, on this server, as this account.
- **Revokes that land.** At once on daemon servers, open sessions included. Within the hour on `nk sync` servers.
- **Access that runs out.** Grant a server for a while, or let people ask and an admin approve.
- **Keys that stay in hardware.** In a TPM or on a FIDO2 security key where there is one.
- **No bastion in the path.** Every server serves its own SSH. When the core is down, a certificate you hold still logs in, on a daemon server for up to a week.
- **No open ports needed.** Servers behind NAT are reached through an end-to-end encrypted relay.
- **Recorded sessions and an audit log.** Recordings are encrypted, the log streams to your SIEM.
- **A terminal in the browser**, for the day you only have a tablet.
- **Made for machines too.** CI jobs sign in with their platform's own token, and containers enroll themselves.

## Development

Everything is one Go module. A change to the API and the code that uses it is one commit.

```bash
task gen     # regenerate code after a change in proto/ or the SQL queries
task lint    # tidy, vet, test and lint everything
task test    # unit tests
task --list  # the rest, tasks of one part are prefixed (core:dev, cli:build)
```

Next to the three parts, [`proto`](./proto) is the API schema they all speak, `gen` is the Go code generated from it, and [`internal`](./internal) holds what `nk`, `nokkud` and the core share. [CONTRIBUTING.md](./CONTRIBUTING.md) has the setup.

## License

The core in `core/` is under the Fair Core License. The CLI, the daemon, the API schema and the shared packages are under Apache-2.0. [LICENSE.md](./LICENSE.md) has the list.

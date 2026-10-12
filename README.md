<p align="center">
    <picture>
        <source media="(prefers-color-scheme: light)" srcset="./.github/nokku_dark.svg">
        <source media="(prefers-color-scheme: dark)" srcset="./.github/nokku_light.svg">
        <img src="./.github/nokku_light.svg" width="80">
    </picture>
</p>

# Nokku

Nokku gives people short-lived SSH certificates instead of long-lived keys. You decide who may log in to which server as which account, and Nokku signs a certificate for exactly that.

It has three parts. Each has its own README with setup and usage.

| Part       | Folder               | What it does                                           |
| ---------- | -------------------- | ------------------------------------------------------ |
| **Core**   | [`core`](./core)     | Users, access, certificate authorities, SSO, audit log |
| **Daemon** | [`nokkud`](./nokkud) | Runs on a server and keeps its SSH access in sync      |
| **CLI**    | [`nk`](./nk)         | Signs you in on your machine, then plain `ssh` works   |

The guides are at [nokku.sh/docs](https://nokku.sh/docs).

## What else is in here

| Folder                   | What it is                                                          |
| ------------------------ | ------------------------------------------------------------------- |
| [`proto`](./proto)       | The API schema all three parts speak                                |
| `gen`                    | Go code generated from `proto`, never edited by hand                |
| [`internal`](./internal) | Go packages `nk` and `nokkud` share: DPoP, machine keys, CA pinning |

## Development

Everything is one Go module. A change to the API and the code that uses it is one commit.

```bash
task gen     # regenerate code after a change in proto/ or the SQL queries
task lint    # tidy, vet, test and lint everything
task test    # unit tests
task --list  # the rest, tasks of one part are prefixed (core:dev, nk:build)
```

[CONTRIBUTING.md](./CONTRIBUTING.md) has the setup.

## License

The core in `core/` is under the Fair Core License. The CLI, the daemon, the API schema and the shared packages are under Apache-2.0. [LICENSE.md](./LICENSE.md) has the list.

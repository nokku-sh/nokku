# Backlog

Work queue for the whole Nokku ecosystem (nokku, nokkud, nk, mon, protos,
docs). Paths start with the repo name. Agents work Ready items and add what
they find. Needs decision is for Roxas: features, contracts, and anything
with a product trade-off. The `unattended-pass` skill defines how to work
this file.

## Ready

- [ ] `nokku/internal/api` Unexport the package internals. Only `api.New` is
      used outside, but services, constructors, interceptors, and `Err*`
      vars are exported. Use `gopls rename`, change nothing else. RPC
      methods stay exported, connect needs them.
      Done when: nothing but `New` and the RPC methods is exported, lint and
      tests pass. (2026-09-30)
- [ ] `nokku/internal/daemon` Unexport what only the package uses, starting
      with `Pool.Shutdown` and `Pool.Done`.
      Done when: the exported surface is what `api` and `config` call.
      (2026-09-30)
- [ ] `nokku/internal/db` Cut the tx closure boilerplate. About 47 handlers
      declare an outer var, assign it inside `WithWorkspace`, and check the
      error. A generic method returning `(T, error)` would make each a single
      call. Try it on one file first and keep it only if it reads better.
      Done when: the pattern is gone or the item is skipped with the reason.
      (2026-09-30)
- [ ] `nokku/internal/api` Characterization tests for the riskiest untested
      handlers: `DaemonService.CreateSession`, `DaemonService.EnrollDaemon`,
      `TargetService.SyncTargetUsers`. They protect later refactors.
      Done when: each has a DB-backed test covering its success path and its
      main denial. (2026-09-30)
- [ ] `nokkud/main.go` The root command description says nokkud "replaces
      the host sshd". It runs beside it on :4022 and never touches port 22.
      Done when: the help text matches. (2026-09-30)
- [ ] `mon` Add CONTRIBUTING.md and SECURITY.md to match the other repos.
      Done when: both exist and fit mon's scope (a library, no binaries).
      (from ROADMAP)

## Needs decision

- [ ] `nokku/internal/daemon` Multi-instance support. The pool keeps control
      streams, relays, and web sessions in memory, so relays fail across
      replicas. Planned as its own pass. (2026-09-30)
- [ ] `nokku/charts` The chart ships an HPA up to 5 replicas, which breaks
      relays today. Remove it, or keep it for after the multi-instance pass.
      (2026-09-30)
- [ ] `nokku/README.md` Says Redis makes multiple instances safe. Not true
      while the daemon pool is in memory. Also decide whether Redis stays if
      nokku stays single-instance. (2026-09-30)
- [ ] `protos` No LICENSE file. Pick one to match its consumers (Apache 2.0
      like nk, nokkud, mon?). (2026-09-30)
- [ ] `nokku/docs` Replace PRODUCT.md with a single agent-facing doc that is
      kept current. The public docs site covers the product. (2026-09-30)
- [ ] `nk` Feature: `nk target delete` or unmanage. Remove the drop-in, CA
      file, and principals dir over ssh, then delete the backend target.
      (from ROADMAP)
- [ ] `nk` Feature: structured `--json` output for `nk sync` and a
      changed-files summary. (from ROADMAP)
- [ ] `docs` Refresh the website. Replace the `placeholder/` legal pages and
      empty sections, and add user TTL guidance for manual-heavy workspaces.
      (from ROADMAP)

## Done

- [x] `protos` Proto lock-step. Solved by publishing the generated code as
      one Go module, CI checks `gen/` is current. (2026-09-30)
- [x] Local `go.work` for cross-repo work, documented in the protos README.
      (2026-09-30)
- [x] `nokku/internal/iam` Dangling ADR reference, already gone from the
      code. (2026-09-30)
- [x] Earlier ROADMAP items: mon CI, mon lint prefix fix, state/io dedup,
      dpopclient dedup, web/ui README, nokkud enroll prompt, manual sync
      staleness signal.

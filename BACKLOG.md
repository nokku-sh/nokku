# Backlog

Work queue for the whole Nokku ecosystem (nokku, nokkud, nk, mon, protos,
docs). Paths start with the repo name. Agents work Ready items and add what
they find. Needs decision is for Roxas: features, contracts, and anything
with a product trade-off. The `unattended-pass` skill defines how to work
this file.

## Ready

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

- [ ] `nokku/internal/iam` Unexport the 46 identifiers only iam uses. One
      mechanical commit, list from the exports tool.
      Done when: the tool reports no `internal` entries for iam. (2026-09-30)
- [ ] `nokku` Unexport what the exports tool lists as `internal` in the
      remaining packages (entitlement, util, email, billing, crypto, audit,
      and smaller ones). Leave `api.Server` and daemon's `Enrolled`, `Relay`,
      `Synced`, they are returned by exported functions.
      Done when: only those deliberate entries remain. (2026-09-30)
- [ ] `nokkud` Unexport the 18 identifiers the exports tool lists (recording
      8, sshd 4, audit 4, hostcerts 1, sysutil 1). (2026-09-30)
- [ ] `nk` Unexport the 21 identifiers the exports tool lists (doctor 7,
      manual 6, ssh 3, state 3, ui 2). (2026-09-30)
- [ ] `nokku` Dead code: `crypto.HashedToken.Verify` and
      `sshclient.Terminal.Done` are only called from tests. Delete them and
      the tests that only cover them.
      Done when: the exports tool shows no `tests-only` entry for either.
      (2026-09-30)

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

- [ ] `nokku` Feature: change the account email. Today the profile says it
      can't be changed. Spec from Roxas: the change is confirmed through a
      verification email to both the old and the new address, using the
      `verification` template. Needs a proto field or RPC, a pending-email
      column, and a token flow. (2026-09-30)

## Done

- [x] `nokku/internal/api` Resend verification sent the welcome email
      again. Welcome now goes out once at signup, resends use the
      `verification` template. No test yet, api handlers have no DB test
      harness (see the characterization tests item). (2026-09-30)
- [~] `nokku/internal/db` Cut the tx closure boilerplate. Skipped: tried a
      generic `InWorkspace[T]` on target.go. Only 22 blocks have the simple
      shape (the rest carry logic), each shrinks by one line, and it needs a
      helper per scope. Net about zero lines, two more db entry points, and
      the type moves into long closure signatures. Not worth it.
      (loop/2026-09-30)
- [x] `nokku/internal/daemon` Unexport what only the package uses. Result:
      12 identifiers unexported, the `Conn.Cancel` wrapper removed, -4
      lines. Kept exported: what `api` and `config` call, connect handler
      methods, and types returned to `api`. (loop/2026-09-30)
- [x] `nokku/internal/api` Unexport the package internals. Result: 72
      identifiers unexported, only `Server` and `New` remain. Case-only diff,
      0 lines net. (loop/2026-09-30)
- [x] `protos` Proto lock-step. Solved by publishing the generated code as
      one Go module, CI checks `gen/` is current. (2026-09-30)
- [x] Local `go.work` for cross-repo work, documented in the protos README.
      (2026-09-30)
- [x] `nokku/internal/iam` Dangling ADR reference, already gone from the
      code. (2026-09-30)
- [x] Earlier ROADMAP items: mon CI, mon lint prefix fix, state/io dedup,
      dpopclient dedup, web/ui README, nokkud enroll prompt, manual sync
      staleness signal.

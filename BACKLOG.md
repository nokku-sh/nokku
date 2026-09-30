# Backlog

Work queue for the whole Nokku ecosystem (nokku, nokkud, nk, mon, protos,
docs). Paths start with the repo name. Agents work Ready items and add what
they find. Needs decision is for Roxas: features, contracts, and anything
with a product trade-off. The `unattended-pass` skill defines how to work
this file.

## Ready


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

- [ ] `nokku/internal/db` Parallel test packages race on
      `ALTER ROLE nokku_app` ("tuple concurrently updated", SQLSTATE XX000).
      The `nokku_schema` advisory lock is per database, each test package has
      its own database, and the role is cluster-wide. Seen 2 of 4 full runs
      while api built a config per test, 0 of 4 right after api started
      building it once. Options, all touch production startup: retry the ALTER
      on that error, try an app login first and skip the ALTER when it
      works, or take the lock in the `postgres` maintenance database. Or
      accept the low rate. The comment now states the limit. (2026-10-01)

## Done

- [x] `nokku` Dead code `crypto.HashedToken.Verify` and
      `sshclient.Terminal.Done`. Result: both deleted with the Verify-only
      tests, the Terminal teardown tests now wait on Stdout closing like the
      pool does. -72 lines. (loop/2026-10-01)
- [x] `nk` Unexport package internals. Result: 8 identifiers, case-only
      diff, 0 lines net. Kept: doctor's `Report`, `Check`, `Status` and its
      consts (returned by `Run`, exported fields), `manual.Result` and
      `File`, `ssh.RelayDialer`, and the state types (exported and embedded
      fields). 25a9a10 on loop/2026-10-01.
- [x] `nokkud` Unexport package internals. Result: 13 identifiers,
      case-only diff, 0 lines net. Kept: `audit.EventDegraded` (its enum is
      used outside), `hostcerts.SignFunc`, `recording.Uploader`,
      `sshd.Policy`, `sshd.RecordingSink` (exported signatures and fields).
      8068959 on loop/2026-10-01.
- [x] `nokku` Unexport the remaining package internals. Result: 47
      identifiers across actor, audit, billing, cache, config, crypto, kms,
      email, entitlement, ssh, storage, util. Case-only diff, 0 lines net.
      Kept: types returned by or passed to exported functions, exported
      field types, the `Feature*` consts (enum used outside), the email
      template data group (`newLoginTemplateData` would read as a
      constructor). `billing.Stripe` and `cache.Redis` clash with their
      imported package names. (loop/2026-10-01)
- [x] `nokku/internal/iam` Unexport what only iam uses. Result: 25
      identifiers unexported, case-only diff, 0 lines net. Kept exported:
      types of exported fields other packages use (`DPoPVerifier`,
      `DeviceFlow`, `SCIMFlow`, `PasswordManager`, `OAuth2Provider`, `Sink`,
      `Action` and its consts so the enum stays whole). `linker.Resolve`
      clashes with `linker.resolve`. (loop/2026-10-01)
- [x] `mon` CONTRIBUTING.md and SECURITY.md. Result: both added, scoped to
      a library (consumers, tags, salts, per-package scope). ed31e99 on
      loop/2026-10-01.
- [x] `nokkud/main.go` Root help said nokkud replaces the host sshd.
      Result: now says it runs beside it on :4022. aa43d70 on loop/2026-10-01.
- [x] `nokku/internal/api` `CreateSession` success path. Result: a fake
      daemon on the real Connect and DaemonRelay streams bridges to
      `sshtest`, the test sees the session env and OS user reach sshd. The
      api harness is now built once per package on TLS with HTTP/2, and
      `sshtest.NewServerFor` takes real principals. Net +152 lines.
      (loop/2026-10-01)
- [x] `nokku/internal/api` `CreateSession` characterization test, first
      part. Result: covers the daemon, CA, and target lookups, the offline
      daemon (Unavailable), and a service account (PermissionDenied). +52
      lines. Success path split into Ready. (loop/2026-10-01)
- [x] `nokku/internal/api` `EnrollDaemon` characterization test. Result:
      covers enrollment through a real enroll token and DPoP proof, same-key
      re-enroll, used-up and bad tokens. +90 lines. (loop/2026-10-01)
- [x] `nokku/internal/api` Characterization tests, first part. Result:
      DB-backed api harness (`main_test.go`, real config and interceptors
      over httptest) and a `SyncTargetUsers` test for success, no-delete, and
      viewer denial. +223 lines. Split the other two handlers into Ready.
      (loop/2026-10-01)
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

# Improvement roadmap

Seeded backlog, roughly in priority order. One line each. Agents pick work
here and move it to Done.

## Todo

1. **Proto lock-step check.** CI job in each app repo running `task gen` then
   `git diff --exit-code internal/gen`, or switch `buf.gen.yaml` input to
   `git_repo` once the protos repo is pushed.
2. **`go.work` at the projects root** for local dev. Not committed, the repos
   stay standalone.
3. **Refresh the `../docs` website.** Replace `placeholder/` legal pages and
   empty sections. Owner-confirmed pending work.
4. **`nk target delete` or unmanage.** Remove drop-in, CA file, principals
   dir over ssh, then delete the backend target. Deferred: this round chose
   gap-closers only.
5. **`mon` CONTRIBUTING.md and SECURITY.md** to match the other repos.
6. **Dangling ADR reference.** `nokku/internal/iam/service.go` cites
   `docs/adr/0001-merge-auth-back-into-nokku.md` which does not exist. Delete
   the reference or write the ADR.
7. **Structured `--json` output for `nk sync`** and a changed-files summary.
8. **User TTL guidance for manual-heavy workspaces** in the public docs.

## Done

- mon CI (`mon/.github/workflows/test.yaml`).
- mon lint fix (golangci local-prefixes pointed at nokkud).
- state/io.go dedup into `mon/fsutil` (`LoadJSON`, `SaveJSON`).
- client/dpop.go dedup into `mon/dpopclient` (`NewProofer`).
- web/ui README was a SvelteKit placeholder, now real.
- nokkud `--enroll` flag with no-echo prompt.
- Staleness signal: `metadata.last_manual_sync` from `SyncTargetUsers`,
  shown in the UI target modal and `nk ls`.

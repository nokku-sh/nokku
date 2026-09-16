# Nokku web UI

The control plane UI for Nokku. SvelteKit 5 with shadcn-svelte components and Tailwind CSS 4. The production build is embedded into the Go binary by `../web/embed.go`, so the backend serves it with no separate deployment.

## Commands

```bash
pnpm install        # first time only
pnpm dev            # dev server
pnpm build          # production build
pnpm check          # type checking
pnpm fmt            # format with oxfmt
pnpm lint           # oxlint
```

The dev server needs a backend. Run `task backend` from the repo root and point the proxy at it.

## Generated code

`src/lib/gen` holds the generated API client for the Nokku protos. Never edit it by hand. Regenerate with `task gen` from the repo root, which runs buf against `../protos`.

See the repo root `AGENTS.md` for project conventions.

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

`src/lib/gen` holds the generated API client for the Nokku protos. Never edit it by hand. Regenerate with `task gen` from the repo root, which runs buf against the protos version `go.mod` pins.

## UI conventions

The look is terminal-native: compliance paper in light mode, a console at night in dark mode, signal teal throughout. It matches the docs site at nokku.sh.

### Where things live

- `src/routes/layout.css` holds every token. Colors, radius, the `text-2xs` size, the `spec-label` utility, the blink animation and the console palette (`--terminal`, `--ansi-0..15`) that xterm and asciinema both read. No raw palette classes, no hex in components.
- `lib/components/ui` is shadcn-svelte plus a few registry extras. Our own variants live in place: `Badge` has `success`, `warning`, `info` and `muted`, and `Empty.Command` renders a `$ prompt` hint.
- `lib/components/layout` is the app shell: sidebar, header, footer, command palette, `PageHeader` and `routes.ts`, the single source for titles, icons, roles and `g` shortcuts.
- `lib/components/blocks` holds generic compositions used in more than one place: `FormModal`, `ConfirmDialog`, `AuthCard`, `StatTile`, `StatusDot`, `SecretReveal`, `FilterPill`, `CopyText`, `SaveStatus` and friends.
- Feature folders (`access`, `audit`, `sheets`, `modals`, `tables`, `dashboard`) hold domain pieces. A component with one user stays next to its route.

### Status colors

`lib/tone.ts` defines one `Tone` (`success`, `warning`, `info`, `destructive`, `muted`) and maps status words to it with `statusTone()`. Tone names match Badge variants, so `<Badge variant={tone}>` works. Use `StatusDot` for live state and `toneText`, `toneSoft` or `toneBg` when a class is needed.

### Which block for what

- A page starts with `PageHeader`. The app shell wraps it in the page container, the header takes its icon from `routes.ts`.
- Lists use `DataTable` with `TableToolbar`. Filters are URL params, empty states set a `command` hint when a CLI way exists.
- Editing an existing entity opens its sheet (`EntitySheet`). Creating one opens a `FormModal`. A secret shown once goes through `SecretReveal`.
- Destructive actions call `confirm()`. Bulk actions pass `confirm` on the `BulkAction` instead. Type-to-confirm is for deletes that are hard to undo, and asks for the name (the email for members).
- Loading is `Skeleton` or `Spinner`, never a spinning icon. Settings autosave with `SaveStatus`, forms that talk to an outside system keep a Save button.

### Copy

Sentence case everywhere. No trailing period on page descriptions. Use the domain verb when there is one (Invite, Enroll, Sign, Add target), otherwise Create. Machine values like IDs, hostnames, principals and fingerprints are set in mono.

See the repo root `AGENTS.md` for project conventions.

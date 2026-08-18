# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-08-18

### Features

- db: Add recordings table and queries
- crypto: Add x25519 key parsing and fingerprinting
- storage: Add streaming writes and prefix deletes
- billing: Enforce recording storage quotas
- api: Add recording upload and playback service
- ui: Add recordings list, player, and key settings
- workspaces: Store settings as jsonb and add daemon default config
- db: Add kagi auth schema and queries
- auth: Add kagi-backed auth service
- api: Migrate auth flows to kagi
- web: Migrate frontend auth to kagi flows

### Bug Fixes

- db: Default workspace settings to empty jsonb object
- ui: Pass github as provider to oauth login links
- ui: Treat any whoami failure as expired session

### Refactoring

- crypto: Drop argon2 hashing and token prefixes
- auth: Delete legacy authn service and helpers
- config: Wire kagi auth into app config
- audit: Track new auth http routes
- seed: Align seed with kagi auth
- auth: Export username derivation helper
- cache: Adopt kagi cache package and drop internal cache
- auth: Rename authn_kagi files to authn
- auth: Expose facade API on auth service

### Documentation

- auth: Add ADR for kagi auth refactor

### Miscellaneous

- ui: Bump svelte and protobuf dependencies
- proto: Regenerate clients from local protos
- go: Enable gofumpt and race-enabled tests

## [0.1.0] - 2026-08-14

### Features

- geo: Replace embedded GeoIP with iplocate API service
- audit: Track actor email and audit auth events
- config: Trust client ip headers only from configured proxies
- billing: Migrate billing from Polar to Stripe
- license: Add offline-verifiable instance licenses
- billing: Redesign license cards
- billing: Use customer email and single flex price for checkout
- storage: Support explicit mode and cdn redirects
- domain: Verify workspace domain via doh with fallback
- cache: Add redis backend with env-based selection
- db: Grant target access through team membership
- ui: Show via-team access and optimistic toggles
- rbac: Add built-in roles with role-based rls
- service-accounts: Assign and filter by role
- roles: Add list roles rpc to util service
- ui: Role pickers and cells backed by server roles
- authn: Authenticate devices with signed key challenges
- config: Allow extra websocket origins
- ui: Gate sso and plan display on billing capabilities
- db: Make pool max and min connections configurable
- audit: Audit oauth and saml login endpoints
- audit: Reject exports exceeding max rows
- api: Scope requests to workspace via interceptor
- audit: Resolve workspace from request context
- ui: Inject workspace_id via transport interceptor
- ui: Add success color token
- daemon: Support updating config and status
- daemon: Add session recording toggle
- deploy: Add production compose stack with caddy
- otel: Enable otelslog bridge
- auth: Rotate refresh tokens with device reuse detection
- geo: Serve lookups from a cached local ip2location database
- db: Enforce tenant isolation and move authz to go
- sso: Split oauth and oidc flows and tag identity protocols
- db: Adopt tern versioned migrations
- api: Reject inactive users on token auth
- email: Add changelog and product update templates
- daemon: Version workspace state to trigger daemon re-sync

### Bug Fixes

- api: Wrap principal errors with connect codes
- entitlement: Fail closed on unknown license status
- daemon: Harden pool concurrency on reconnect
- api: Broadcast workspace events synchronously
- api: Bound audit and terminal request contexts
- api: Handle stale cli login waiter non-blockingly
- api: Fail closed on otel exporter failure
- api: Validate oidc config and passkey response
- cache: Copy bytes to prevent buffer aliasing
- crypto: Copy secret to avoid key aliasing
- db: Seed only after migrations have run
- db: Drop alias prefix in domain verification update
- doh_test: Remove unused parameter r
- pagination: Offset handling
- sso: Improve domain collapsible layout
- daemon: Clean stale sessions on daemon re-register
- api: Propagate list workspaces errors
- ui: Stop copy button click propagation
- ci: Use tag job bump output in release trigger
- daemon: Resolve session request race and event map leak
- db: Serialize auto-migrate with advisory lock
- geo: Unpack zip-wrapped database downloads
- api: Require request or context id for cert and daemon ops
- api: Remove debug printf from oidc login
- ui: Use dedicated page param types in useInfiniteQuery
- ui: Handle expired sessions and stale workspaces

### Security

- auth: Harden auth errors and wire audit identity
- billing: Cap webhook request body size
- kms: Redact kms uri from logs and errors

### Refactoring

- audit: Consolidate retention constants and cleanup
- license: Replace manager with static key validation
- web: Adapt billing page to new license and portal apis
- comments: Trim redundant doc comments
- seed: Extract seeding into standalone binary
- email: Drop testing bypass from sender
- deadcode: Remove unused helper functions
- license: Extract env license construction
- license: Return zero-value key instead of nil
- storage: Parse config via env.ParseAs
- legal: Link to external legal docs
- auth: Use shared layout section and drop legal footers
- api: Map database errors to connect errors
- otel: Drop otelslog bridge on sdk upgrade
- license: Switch to standard library slog
- ui: Move status column to front of activity log
- api: Return DBError on database query failures
- billing: Clean up checkout and plan name handling
- email: Make app url private
- count: Merge counts with list queries
- db: Replace bulk principal membership queries with single ops
- workspaces: Default new members to viewer
- ui: Remove ssh details card from target modal
- billing: Merge license and entitlement into billing service
- api: Improve rpc and http request logging
- avatar: Drop storage existence check before redirect
- email: Log template instead of cooldown cache key
- api: Drop manual audit workspace assignment
- ui: Polish modal and table cell styling
- api: Simplify certificate CA resolution
- compose: Move dev services to compose.test.yml
- kms: Drop gcp-kms support
- authn: Rename challenge daemon id to identity id
- db: Drop permission column from roles table
- db: Add ErrNoActor sentinel for missing actor
- audit: Fold schema into base migration
- user: Reorder oauth identity proto fields

### Testing

- email: Remove outdated password assertion from template test
- util: Add helper unit tests
- crypto: Add hasher, token and secretbox tests
- db: Add safe conversion tests
- license: Add key verification tests
- pki: Split cert signing tests into sign_test.go
- ssh: Split cert signing tests into sign_test.go
- api: Add ratelimit route tests
- audit: Add event conversion tests
- authn: Add token and bearer extraction tests
- daemon: Add replay sanitize tests
- geo: Add ip lookup tests
- storage: Add object store tests
- api: Cover request workspace promotion
- db: Cover tern migrator edge cases

### Documentation

- readme: Drop license key worker paragraph
- contributing: Add contribution guide
- security: Add security policy
- billing: Document plan and licensing changes
- readme: Overhaul project overview and architecture docs
- Add and prune code comments
- comments: Normalize comment punctuation and phrasing

### Styling

- format: Normalize import groupings across packages
- format: Apply golines line wrapping and cleanup comments

### Miscellaneous

- gen: Regenerate protobuf stubs
- workflow: Add permissions and full git history to test pipeline
- docs: Remove OpenAPI generation and spec
- Adjust tasks
- log: Standardize log messages and keys
- license: Update default signing public key
- build: Remove installer deploy task
- proto: Regenerate protobuf bindings
- proto: Regenerate protobuf bindings
- db: Tidy tables schema comments
- proto: Regenerate protobuf bindings
- authn: Warn when session seed is unset
- api: Remove stale doc comment
- db: Enable automigrate by default
- go: Apply gofmt formatting
- buf: Regenerate protobufs
- buf: Regenerate protobufs
- buf: Regenerate protobufs
- misc: Remove stale comment from kms package
- api: Format error imports
- release: Split version bumping from release workflow
- authn: Reformat code and add challenge cache todo
- Regen protobufs
- proto: Regen protobufs
- Enable goroutineleakprofile experiment
- taskfile: Wrap migrate dump command lines
- ui: Update footer company name



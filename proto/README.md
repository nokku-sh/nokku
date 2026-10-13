# proto

The Nokku API schema. The core, `nokkud` and `nk` compile against the Go
code generated from it. The web UI client is generated from the same files,
so nothing drifts.

- `nokku/v1/` holds the `.proto` files. Proto package `nokku.v1`.
- `../gen/` is the generated Go and connect code.
- `../core/web/src/lib/gen` is the TypeScript client of the web UI.

Never edit the generated files by hand.

## Access rules

Every RPC declares who may call it with `option (access)`, see
`nokku/v1/access.proto`. An RPC without it is denied by the server.

## Changing the schema

From the repo root:

```bash
task gen    # regenerates both
task lint   # includes buf format and buf lint
```

Commit the proto change together with what `task gen` rewrote and the code
that uses it. CI fails when `gen/` is stale.

## License

Apache License 2.0

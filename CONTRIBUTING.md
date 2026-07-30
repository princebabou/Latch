# Contributing to Latch

Thank you for helping improve Latch. Security-boundary changes receive a
higher review bar than ordinary application code.

## Development

Requirements: Go 1.24 or newer.

```sh
go test ./...
go vet ./...
go build ./cmd/latch
```

On systems with `make`, `make verify` runs the complete local gate.

Keep changes deterministic and fail closed. A parser must never execute,
interpolate, resolve, or connect to the input it analyzes. New enforcement
behavior should include positive, negative, and malformed-input tests.

## Pull requests

Explain the security invariant being added or preserved. Call out any change
to decision precedence, identity binding, policy matching, approval scope,
budget accounting, protocol forwarding, state persistence, or audit
redaction. Include tests for concurrency and crash behavior when state is
involved.

Use synthetic secrets and endpoints in tests and examples. Never commit
credentials or production data.

## Vulnerabilities

Do not use a public issue for a suspected vulnerability. Follow
[SECURITY.md](SECURITY.md).

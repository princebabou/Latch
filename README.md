# Latch

> A security firewall for AI agent actions.

Latch is an open-source security enforcement layer for AI agents. It receives a normalized tool action before execution, evaluates readable YAML policy and deterministic risk signals, then returns an explainable `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL` verdict.

It is deliberately a control plane, not a prompt-injection scanner. The intended boundary is between an agent and the real tools, files, shells, APIs, databases, and MCP servers it can reach.

## What this milestone delivers

- Protocol-neutral `Action` and `Assessment` models
- YAML policy engine with tool, operation, path, command, URL, hostname, HTTP method, database operation, and argument matching
- Deny-overrides policy evaluation with safe risk escalation
- Deterministic signals for credentials, secrets, destructive shell commands, privilege escalation, database operations, and outbound data risk
- Human approval prompt with a narrowly scoped persistent “always allow this exact action” option
- Redacted JSONL audit trail with file permissions restricted to the current user
- `latch check`, `latch run`, `latch policies`, and `latch logs` commands

The CLI never executes the action it evaluates. That makes it safe to use for policy development and integration testing.

## Quick start

Requirements: Go 1.24+

```powershell
go run ./cmd/latch check --tool filesystem.read --arg path=./README.md
go run ./cmd/latch check --tool filesystem.read --arg path=~/.ssh/id_rsa
go run ./cmd/latch check --tool shell.exec --arg "command=npm test" --interactive
go run ./cmd/latch run --input examples/actions.jsonl
```

Build a standalone binary:

```powershell
go build -o bin/latch.exe ./cmd/latch
```

`latch check` exits `0` only for an allowed action and exits `3` for a blocked or pending-approval action, which makes it friendly to CI and wrappers.

## How a decision is made

```text
Agent tool call
      │
      ▼
Request normalizer ──► Generic Action
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
        YAML policy     Risk detectors     Approval cache
             └────────────────┼────────────────┘
                              ▼
                    Explainable verdict
               ALLOW / BLOCK / REQUIRE_APPROVAL
                              │
                              ▼
                      Redacted JSONL audit
```

Explicit `BLOCK` rules always win. An explicit `ALLOW` is a deliberate exception. `REQUIRE_APPROVAL` is a minimum control: it cannot downgrade a critically risky request such as recursive deletion into an approval prompt.

## Policy

Start with [configs/latch.example.yaml](configs/latch.example.yaml). It blocks private keys, `.env` files, and `/etc/shadow`; requires approval for shell use; and requires approval for production writes.

```yaml
rules:
  - id: production-delete
    description: Production deletion is prohibited.
    match:
      tool: database.query
      database_operation: DELETE
      arguments:
        environment: production
    action: block
```

Validate and inspect policies:

```powershell
go run ./cmd/latch policies validate
go run ./cmd/latch policies list
```

## Risk signals

Risk is deterministic and capped at 100. Signals are included in terminal output and audit events, so every escalation has a concrete reason. Current detectors include:

- SSH and cloud credential paths, private keys, environment files, browser cookies, password stores, shell history, Git credentials, and `/etc/shadow`
- recursive or direct deletion, privilege escalation, unsafe permissions, remote-script pipes, Docker pruning, Kubernetes deletion, and database dumps
- destructive or unbounded database queries and queries referencing sensitive columns
- outbound requests and secrets embedded in URLs

The detector package isolates lexical command inspection from the policy engine so it can later gain shell parsers, DLP scanning, or model-assisted analysis without changing the enforcement contract.

## Audit and approval

Every CLI evaluation writes a redacted JSONL event to `.latch/audit.jsonl` by default. Secret-bearing keys and inline bearer/token values are redacted before serialization. Inspect recent events with:

```powershell
go run ./cmd/latch logs --tail 20
```

For an approval-required action, pass `--interactive`. “Always allow” stores only a SHA-256 fingerprint of the exact normalized action in `.latch/approvals.json`; it does not create a wildcard or tool-wide bypass. A policy block is never overridden by an approval cache entry.

## Design boundary and next step

This milestone implements the enforcement kernel and local CLI first. It intentionally stops before forwarding any tool call. An MCP proxy adapter can now normalize `tools/call` requests into `models.Action`, call `enforce.Evaluate`, consult the approval gate, and only then forward allowed calls. That keeps MCP transport concerns separate from the security decision path.

Run the suite with:

```powershell
go test ./...
```

# Latch

> A security firewall for AI agent actions.

Latch is an open-source security enforcement layer for AI agents. It receives a normalized tool action before execution, evaluates readable YAML policy and deterministic risk signals, then returns an explainable `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL` verdict.

It is deliberately a control plane, not a prompt-injection scanner. The intended boundary is between an agent and the real tools, files, shells, APIs, databases, and MCP servers it can reach.

## What this milestone delivers

- Protocol-neutral `Action` and `Assessment` models
- YAML policy engine with tool, operation, path, command, URL, hostname, HTTP method, database operation, and argument matching
- Deny-overrides policy evaluation with safe risk escalation
- Structured, deterministic shell, HTTP, and SQL analysis for destructive behavior, credential movement, privilege escalation, and outbound data risk
- Operator-bound agent identities with aliases and policy-defined capability ceilings
- Durable per-agent rolling action budgets that stop cumulative and runaway behavior
- Time-bound, identity-attributed approval grants scoped to one exact normalized action and one policy version
- Redacted JSONL audit trail with file permissions restricted to the current user
- A versioned, fail-closed `latch.security/v1` Enforcement API for every SDK and adapter
- Official fail-closed Go, Python, and TypeScript SDKs with guarded execution helpers
- Bidirectional MCP stdio and Streamable HTTP proxies that enforce every `tools/call` before forwarding
- A generic HTTP/API reverse gateway with semantic body inspection, separated credentials, and allow-only forwarding
- OpenAI-compatible Responses API and Chat Completions function adapters for Go, Python, and TypeScript
- Native LangChain middleware and whole-batch protected LangGraph ToolNodes for Python and TypeScript
- Fail-closed local process executors for Go, Python, and TypeScript with argv-first APIs, replay protection, executable fingerprinting, and bounded execution
- One-command policy scaffolding, deployment diagnostics, and native MCP configuration generation
- Static cross-platform releases, Linux packages, a non-root multi-architecture container, SBOMs, checksums, and build attestations
- `latch init`, `latch doctor`, `latch integrations`, `latch check`, `latch proxy`, `latch proxy-http`, `latch proxy-api`, `latch run`, `latch policies`, `latch identities`, `latch budgets`, `latch approvals`, and `latch logs` commands
- `latch serve` for the stable HTTP decision contract, health checks, replay protection, and operator-bound identity

The `check` and `run` commands never execute evaluated actions. Every proxy permits only actions that pass Latch enforcement.

## Quick start

Install a release with a checksum-verifying installer, or build with Go 1.24+:

```sh
curl -fsSL https://raw.githubusercontent.com/princebabou/Latch/main/scripts/install.sh | sh
go install github.com/princebabou/Latch/cmd/latch@latest
```

```powershell
irm https://raw.githubusercontent.com/princebabou/Latch/main/scripts/install.ps1 | iex
```

Set up a protected MCP server in three commands:

```sh
latch init --profile balanced --agent desktop-agent
latch doctor --config latch.yaml --agent desktop-agent -- my-mcp-server
latch integrations mcp --client vscode --name protected-server \
  --config latch.yaml --agent desktop-agent -- my-mcp-server
```

The integration generator also supports `claude`, `cursor`, and a reusable
`generic` launch object. It emits absolute executable and policy paths so GUI
launchers do not depend on their working directory.

Try the policy evaluator:

```sh
latch check --tool filesystem.read --arg path=./README.md
latch check --tool filesystem.read --arg path=~/.ssh/id_rsa
latch check --tool shell.exec --arg "command=npm test" \
  --interactive --approver local:alice --approval-ttl 30m
latch run --input examples/actions.jsonl
```

Start the stable Enforcement API used by integrations:

```sh
export LATCH_API_TOKEN="$(openssl rand -hex 32)"
latch serve --config latch.yaml --agent desktop-agent
```

Submit one intended action to `POST /v1/decisions` using the versioned
`latch.security/v1` contract. A valid verdict always returns HTTP `200`; callers
must execute only an explicit `ALLOW` and fail closed on every error. See the
[Enforcement API guide](docs/enforcement-api.md) and canonical
[OpenAPI contract](api/openapi.yaml).

Use the official [Go, Python, or TypeScript SDK](docs/sdks.md) to integrate the
same contract in a few lines. Their guarded helpers invoke a tool only after a
valid, request-correlated `ALLOW`.

See [integration recipes](docs/integrations.md) and the
[deployment guide](docs/deployment.md) for client destinations, CI gates,
containers, packages, provenance verification, and service hardening.

`latch check` exits `0` only for an allowed action and exits `3` for a blocked or pending-approval action, which makes it friendly to CI and wrappers.

## MCP stdio proxy

Place Latch where your MCP client would normally launch a server:

```powershell
latch proxy --config C:\absolute\path\latch.yaml --agent claude-desktop -- C:\absolute\path\my-mcp-server.exe --server-option
```

The arguments after `--` are the real server command. Latch owns that child process, forwards the complete MCP session in both directions, and inspects `tools/call` requests before they reach it. Initialization, notifications, tool discovery, server-to-client requests, responses, and other MCP methods pass through transparently.

`--agent` is an operator-controlled trust binding because it is supplied in the MCP launcher configuration, outside the MCP protocol stream. Names reported by `initialize.clientInfo` or request `_meta` are retained for diagnostics but are always treated as self-asserted and unverified.

Example MCP client configuration:

```json
{
  "mcpServers": {
    "protected-server": {
      "command": "C:\\absolute\\path\\latch.exe",
      "args": [
        "proxy",
        "--config", "C:\\absolute\\path\\latch.yaml",
        "--agent", "desktop-agent",
        "--",
        "C:\\absolute\\path\\my-mcp-server.exe"
      ]
    }
  }
}
```

The proxy follows MCP stdio framing: UTF-8 JSON-RPC objects, one message per line, with protocol data exclusively on `stdout` and diagnostics on `stderr`. Invalid client calls receive standard JSON-RPC errors. Blocked and approval-required actions receive MCP tool results with `isError: true`; they are never sent upstream. Invalid upstream protocol output, oversized messages, approval-store failures, and audit failures fail closed.

The default message limit is 4 MiB and can be changed with `--max-message-bytes`. Use `--cwd` when the child server needs a specific working directory. The proxy currently targets the stable MCP `2025-11-25` stdio contract while remaining transparent to protocol methods it does not inspect.

## MCP Streamable HTTP proxy

Place Latch in front of an existing remote or local Streamable HTTP server:

```sh
export LATCH_MCP_TOKEN="$(openssl rand -hex 32)"
export LATCH_MCP_UPSTREAM_TOKEN="upstream-service-token"

latch proxy-http \
  --config latch.yaml \
  --agent desktop-agent \
  --upstream https://tools.example/mcp
```

Clients connect to `http://127.0.0.1:7071/mcp`. Generate a native, secret-safe
configuration instead of hand-writing it:

```sh
latch integrations mcp-http --client vscode --name protected-tools \
  --url http://127.0.0.1:7071/mcp --output .vscode/mcp.json
```

The proxy preserves MCP `POST`, `GET`, and `DELETE`, JSON responses, SSE
streams, protocol-version headers, resumability headers, and upstream session
IDs. It rejects disallowed origins, redirects, ambiguous duplicate-key JSON,
oversized messages, invalid sessions, and unavailable audit or policy state.
The client-facing bearer token is never forwarded upstream; configure upstream
credentials separately with `LATCH_MCP_UPSTREAM_TOKEN`.

See the [Streamable HTTP adapter guide](docs/mcp-streamable-http.md) for TLS,
authentication, client setup, Docker networking, and operational limits.

## Generic HTTP/API gateway

Protect an existing HTTP API without modifying it:

```sh
export LATCH_HTTP_TOKEN="$(openssl rand -hex 32)"
export SERVICE_AUTHORIZATION="Bearer upstream-service-token"

latch proxy-api --config latch.yaml --agent api-agent \
  --upstream https://api.example/v1 \
  --upstream-header-env Authorization=SERVICE_AUTHORIZATION
```

Point the calling tool's base URL at `http://127.0.0.1:7072` and add the
`X-Latch-Token` header. Latch evaluates the exact method, destination, headers,
query, and semantically inspected body as `http.request`. Gateway and upstream
credentials remain separate; agent-supplied credentials are stripped unless
the operator explicitly enables their risk-visible forwarding.

Only `ALLOW` reaches the fixed upstream. Blocks, pending approvals, exhausted
budgets, ambiguous JSON, opaque bodies, redirects, and unavailable audit or
durable state fail closed. See the [HTTP/API gateway guide](docs/http-api-gateway.md)
for client configuration, policy examples, status codes, and hardening.

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

Latch uses deny-overrides semantics. A broad allow rule cannot silently weaken a stronger control.

| Precedence | Control | Result |
|---:|---|---|
| 1 | Matching `BLOCK` policy | Always blocked |
| 2 | Unverified, unknown, mismatched, or under-capable identity | Always blocked |
| 3 | Built-in hard-deny signal or score at the block threshold | Blocked unless a valid break-glass override exists |
| 4 | Exhausted cumulative action budget | Always blocked |
| 5 | Matching `REQUIRE_APPROVAL` policy | Approval required, even when an allow also matches |
| 6 | Valid `unsafe_override` allow | Allows the specifically matched protected action |
| 7 | Ordinary matching `ALLOW` policy | Allows only non-protected actions |
| 8 | Risk approval threshold | Approval required |
| 9 | No stronger control | Allowed |

Every assessment records `decision_source`, `hard_deny`, `unsafe_override`, identity verification, canonical agent ID, matched capabilities, and matching budget state, making the exact enforcement path visible in JSON output and audit logs.

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

### Trusted agent identities and capabilities

For a production launcher, enable verified identities and give each agent an explicit maximum capability set. Start with [configs/latch.identity.example.yaml](configs/latch.identity.example.yaml):

```yaml
identity:
  require_verified: true
  enforce_capabilities: true
  agents:
    - id: desktop-agent
      aliases: ["Claude Desktop"]
      capabilities:
        - id: workspace-read
          description: Read files in the checked-out workspace.
          match:
            tool: filesystem.read
            action: read
            path: "./**"
        - id: project-tests
          description: Run the project's test command.
          match:
            tool: shell.exec
            command: "npm test"
```

Capabilities use the same typed matcher as policy rules and form a ceiling, not an allow rule. The action must first fit at least one capability and then still pass every block, approval, and risk control. A policy `ALLOW`, a cached approval, or a break-glass rule cannot grant an agent a capability it does not have.

Capability enforcement requires `require_verified: true`; Latch rejects insecure configurations that try to assign capabilities to spoofable identities. IDs and aliases are case-insensitive, globally unique, and canonicalized before approvals and audit records are created.

Bind the trusted identity at the operator-controlled entry point:

```powershell
latch proxy --config configs/latch.identity.example.yaml --agent desktop-agent -- my-mcp-server
latch check --config configs/latch.identity.example.yaml --agent desktop-agent --tool filesystem.read --arg path=./README.md
latch run --config configs/latch.identity.example.yaml --agent desktop-agent --input examples/actions.jsonl
latch identities list --config configs/latch.identity.example.yaml
```

Without `--agent`, identities inside batch input and MCP protocol metadata remain unverified. `require_verified: true` therefore fails those calls closed. For local stdio, the launcher process is the trust boundary; cryptographically authenticated identities for remote transports are intentionally a separate deployment concern.

### Cumulative action budgets

Single-call controls are not enough for an autonomous agent: a runaway loop or slow data sweep can distribute risk across many individually acceptable calls. Budgets place a durable rolling-window ceiling on matching actions for each verified, canonical agent identity:

```yaml
budgets:
  store_path: .latch/budgets.json
  lock_timeout: 2s
  rules:
    - id: workspace-read-burst
      description: Bound cumulative workspace reads by this agent.
      match:
        tool: filesystem.read
        action: read
        path: "./**"
      max_actions: 100
      window: 5m

    - id: project-test-burst
      description: Prevent runaway test command loops.
      match:
        tool: shell.exec
        command: "npm test"
      max_actions: 5
      window: 10m
```

Every allowed MCP call atomically reserves one unit from every matching budget immediately before audit and forwarding. If any matching budget is exhausted, none are changed and the call is blocked with `decision_source: budget_exhausted`. The last available unit is valid; the following call is denied until the oldest reservation expires.

Budget state is scoped to the complete security policy digest, agent ID, rule ID, and rolling expiry window. It is protected by an operating-system lock and crash-safe atomic replacement, so concurrent Latch proxy processes cannot oversubscribe a limit. Corrupt, oversized, inaccessible, or lock-contended state fails closed with `budget_store_failure`.

Budgets require `identity.require_verified: true`; otherwise an agent could evade them by changing its claimed name. They are security ceilings: cached approvals, ordinary allows, and unsafe overrides cannot bypass exhaustion. Policy changes create a new counter scope, while obsolete entries expire naturally.

Inspect live state without consuming capacity:

```powershell
latch budgets status --config configs/latch.identity.example.yaml --agent desktop-agent
latch budgets status --config configs/latch.identity.example.yaml --agent desktop-agent --json
```

`latch check` and `latch run` are evaluators, so they report current matching budget state but do not reserve capacity. Only an action that is about to be forwarded by a proxy consumes it. Because reservation precedes required audit and forwarding, a later fail-closed audit or upstream transport failure may still consume that attempt.

### Break-glass overrides

Unsafe overrides are disabled by default. Enabling one requires both a policy-wide opt-in and a specific allow rule:

```yaml
enforcement:
  approval_threshold: 40
  block_threshold: 90
  allow_unsafe_overrides: true

rules:
  - id: break-glass-scratch-cleanup
    description: Permit cleanup of this disposable scratch directory during recovery.
    unsafe_override: true
    match:
      tool: shell.exec
      command: "rm -rf ./scratch"
    action: allow
```

Latch rejects unsafe-override rules that are globally disabled, omit a description, use an action other than `ALLOW`, or match only a broad tool/action category. They must constrain a path, command, URL, hostname, database operation, HTTP method, or argument. A matching `BLOCK` or `REQUIRE_APPROVAL` policy still takes precedence over the override.

## Risk signals

Risk is deterministic and capped at 100. Signals are included in terminal output and audit events, so every escalation has a concrete reason.

Latch analyzes tool inputs by structure:

- Shell analysis separates executable commands from quoted data and comments. It understands command sequences, pipelines, wrappers such as `sudo`, command substitutions, literal `sh -c`/PowerShell/CMD payloads, structured argv arrays, download-then-execute chains, encoded execution, exact deletion flags, permission changes, container and cluster deletion, and database export tools. Structured `curl`, `wget`, and PowerShell web requests are also passed through HTTP data-flow analysis.
- HTTP analysis parses URLs, decoded query keys, user information, methods, headers, JSON/form payloads, and TLS options. It distinguishes loopback, private, public, numeric-IP, link-local, and cloud metadata destinations, then detects credential forwarding, sensitive payload exfiltration, cleartext secrets, disabled certificate verification, and destructive methods.
- SQL analysis tokenizes executable syntax separately from strings and comments. It understands multiple statements, CTEs, nested data-modifying statements, MySQL executable comments, scoped versus unscoped mutations, wildcard result bounds, privilege changes, server-side command execution, filesystem access, and sensitive identifiers. Policy `database_operation` matching uses the same parser.
- Filesystem analysis detects SSH and cloud credentials, private keys, environment files, browser stores, shell histories, Git credentials, sensitive system paths, and `/etc/shadow`.

Malformed syntax, unsupported type shapes, or excessive parser nesting produces an explicit ambiguity signal and fails closed. The parsers never execute, interpolate, resolve DNS, or connect to a database. They implement a conservative security grammar across common POSIX shell, PowerShell/CMD, PostgreSQL, MySQL, SQLite, and SQL Server forms; an explicit resource-specific break-glass rule remains available for intentionally unsupported dialect syntax.

Credential material, parser ambiguity, recursive deletion, remote or encoded script execution, database dumps, destructive or unscoped database mutations, database command/filesystem access, cloud metadata access, credential or sensitive-data exfiltration, and insecure secret transport are hard-deny classes. Ordinary allow rules cannot bypass them. Actions that reach the configured block threshold through multiple other signals receive the same protection.

## Audit and approval

Every CLI evaluation writes a redacted JSONL event to `.latch/audit.jsonl` by default. Secret-bearing keys and inline bearer/token values are redacted before serialization. Inspect recent events with:

```powershell
go run ./cmd/latch logs --tail 20
```

For an approval-required action, pass `--interactive` to `latch check`. The prompt can allow the current attempt, deny it, or issue a time-bound grant for the exact normalized action. Every durable grant records a random ID, approver identity, safe action metadata, issue time, expiry, and the policy digest under which it was approved. It never creates a wildcard or tool-wide bypass.

Approval behavior is configured independently from enforcement rules:

```yaml
approvals:
  store_path: .latch/approvals.json
  default_ttl: 15m
  max_ttl: 24h
  lock_timeout: 2s
```

The store is updated under a crash-safe operating-system lock using atomic file replacement. An expired or revoked grant is rejected, as is a grant created under a different policy version, rule set, enforcement threshold, or approval TTL policy. Legacy unbounded approval entries are retained for visibility but never trusted.

MCP stdin and stdout are protocol channels, so the proxy never displays an interactive prompt on them. Pre-approve an exact action using the same config and agent identity:

```powershell
latch check --config latch.yaml --agent desktop-agent --tool shell.exec --arg "command=npm test" --interactive --approver local:alice --approval-ttl 30m
```

The next identical call through `latch proxy` will use that approval until it expires or is revoked. The agent identity, tool name, operation, resource, arguments, and effective policy must all match.

Inspect and manage the lifecycle explicitly:

```powershell
latch approvals list
latch approvals list --json
latch approvals revoke --id <grant-id> --approver local:alice --reason "task complete"
latch approvals prune
```

`revoke` preserves who revoked the grant, when, and why. `prune` is an explicit maintenance command that removes inactive history. Policy blocks and hard-deny risk signals are never overridden by an approval grant, and approval-store errors fail closed.

## Deployment and portability

Operational paths in YAML resolve relative to the policy file, so client
working directories cannot scatter or silently reset security state.
Deployments can override them with `LATCH_AUDIT_PATH`,
`LATCH_APPROVAL_STORE`, and `LATCH_BUDGET_STORE`; `LATCH_CONFIG` and
`LATCH_AGENT` provide launcher-friendly defaults.

`latch version --json` exposes embedded source and platform metadata.
Official releases target Linux, macOS, and Windows on AMD64 and ARM64, include
Linux packages and archive SBOMs, and publish a non-root multi-architecture
container at `ghcr.io/princebabou/latch`.

### GitHub Actions policy gate

Place the packaged action immediately before the real side effect:

```yaml
- uses: princebabou/Latch@v0.2.0
  id: latch
  with:
    config: latch.yaml
    agent: github-actions
    tool: deployment.apply
    operation: write
    resource: production
    arguments: '{"environment":"production"}'

- if: steps.latch.outputs.allowed == 'true'
  run: ./scripts/deploy.sh production
```

The action installs an exact checksummed release on Linux, macOS, or Windows,
then produces a native annotation, job summary, stable decision output, and
machine-readable reasons. It exits successfully only for `ALLOW`; blocks,
unresolved approvals, reporting failures, audit failures, and unavailable state
all stop the job. Pin the action to a full commit SHA in high-assurance
workflows. See [CI/CD and GitHub Actions](docs/ci-cd-github-actions.md) for the
reusable workflow and complete hardening contract.

## Current boundary

Latch now secures MCP stdio, MCP Streamable HTTP, generic HTTP APIs, and
OpenAI-compatible Responses API and Chat Completions function calls, alongside
native LangChain middleware, protected LangGraph ToolNodes, fail-closed local
process execution, a native CI adapter, packaged GitHub Action, reusable policy
workflow, the stable Enforcement API, and official Go, Python, and TypeScript
SDKs. The conformance suite remains the next v0.2 milestone, followed by the policy playground,
observability, and reference deployments.

Run the suite with:

```sh
go test ./...
go vet ./...
```

`make verify` is the equivalent shortcut where Make is available.

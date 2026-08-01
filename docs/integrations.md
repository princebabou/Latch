# Integrating Latch

Latch has four stable integration surfaces:

1. `latch proxy` is a transparent security boundary for local MCP stdio
   servers.
2. `latch proxy-http` protects MCP Streamable HTTP servers while preserving
   JSON, SSE, and session behavior.
3. The versioned Enforcement API and official SDKs embed Latch into existing
   Go, Python, and TypeScript tool runners.
4. `latch check` is a protocol-neutral policy gate for scripts, CI jobs,
   orchestrators, and tool wrappers.

## Three-command MCP setup

Create a production-oriented policy, verify it, and generate a native client
configuration:

```sh
latch init --profile balanced --agent desktop-agent
latch doctor --config latch.yaml --agent desktop-agent -- my-mcp-server
latch integrations mcp --client vscode --name protected-server \
  --config latch.yaml --agent desktop-agent -- my-mcp-server
```

Use `--client claude`, `--client cursor`, or `--client vscode` to emit the
client's native JSON shape. `--client generic` emits only the reusable launch
object. The generated executable, policy, working directory, and path-like
server command are absolute so GUI clients do not depend on an unpredictable
working directory.

Write the generated JSON directly to a new file:

```sh
latch integrations mcp --client cursor --name protected-server \
  --config latch.yaml --agent desktop-agent \
  --output .cursor/mcp.json -- my-mcp-server
```

Existing client configuration is never silently merged or replaced. Copy the
generated server entry into an existing file, or pass `--force` only when the
destination should be replaced.

Common destinations:

| Client | Generated root | Typical project/user destination |
|---|---|---|
| Claude Desktop | `mcpServers` | Claude Desktop configuration |
| Cursor | `mcpServers` | `.cursor/mcp.json` |
| Visual Studio Code | `servers` | `.vscode/mcp.json` |
| Generic | launch object | Your launcher's server entry |

Run `latch doctor` again after moving the policy or server. It checks the
policy, trusted identity, capability and budget readiness, state locations,
working directory, and server executable without starting the server.

## Streamable HTTP setup

Start an authenticated local boundary in front of an existing MCP endpoint:

```sh
export LATCH_MCP_TOKEN="$(openssl rand -hex 32)"
export LATCH_MCP_UPSTREAM_TOKEN="upstream-service-token"

latch proxy-http --config latch.yaml --agent desktop-agent \
  --upstream https://tools.example/mcp
```

Generate client-native configuration:

```sh
latch integrations mcp-http --client vscode --name protected-tools \
  --url http://127.0.0.1:7071/mcp --output .vscode/mcp.json

latch integrations mcp-http --client cursor --name protected-tools \
  --url http://127.0.0.1:7071/mcp --output .cursor/mcp.json
```

The VS Code generator uses a password input and never writes the token. Claude
Code and generic output reference `${LATCH_MCP_TOKEN}`. Cursor output uses its
`${env:LATCH_MCP_TOKEN}` form; keep the generated entry in user configuration
if the installed Cursor version does not interpolate remote header variables.
Use `--no-auth` only for an authless loopback proxy without a trusted `--agent`
binding.

The client-facing and upstream bearer tokens are separate trust boundaries.
When `LATCH_MCP_TOKEN` is enabled, the incoming `Authorization` header is
consumed by Latch and is not sent upstream. Set
`LATCH_MCP_UPSTREAM_TOKEN` when the real server also requires a bearer token.

See [MCP Streamable HTTP](mcp-streamable-http.md) for the complete transport and
deployment contract.

## Trust binding

The `--agent` value belongs in operator-controlled launcher configuration.
Latch treats an identity sent inside the MCP protocol as unverified. When
`identity.require_verified` is enabled, omitting the launcher binding fails
closed.

Use a separate canonical agent ID for each independently administered
launcher. Aliases are useful when an operator-facing product name differs
from the policy ID:

```yaml
identity:
  require_verified: true
  agents:
    - id: finance-desktop
      aliases: ["Finance Claude"]
```

## Environment forwarding

Repeat `--env NAME=value` while generating an MCP configuration to add values
to the launcher entry:

```sh
latch integrations mcp --client vscode --name protected \
  --agent desktop-agent --env SERVICE_MODE=read-only -- my-mcp-server
```

The child MCP server inherits the Latch process environment. Avoid placing
long-lived secrets directly in committed client JSON; use the client's secret
input mechanism, an operating-system credential store, or a short-lived
launcher environment.

## CI and ordinary tool wrappers

`latch check` evaluates one normalized action and exits `0` only for
`ALLOW`. It exits `3` for `BLOCK` and unresolved `REQUIRE_APPROVAL`, making it
usable as a gate before an existing command:

```sh
latch check \
  --config latch.yaml \
  --agent deployment-bot \
  --tool deployment.apply \
  --action write \
  --arg environment=production

# Run the real deployment only if the preceding command succeeds.
./existing-deploy-tool
```

The command after `latch check` remains under the wrapper's control. Latch
does not execute it. This separation makes the policy decision reusable from
shell scripts, CI systems, job schedulers, and custom orchestrators without
giving the evaluator ambient execution authority.

For bulk evaluation, send normalized JSON actions through `latch run
--input actions.jsonl`. It remains an evaluator and does not consume runtime
budgets. Only an allowed call immediately about to cross `latch proxy`
reserves budget capacity.

## Working-directory portability

Approval, budget, and audit paths in YAML resolve relative to the policy file,
not the launching application's current directory. Operational environment
overrides are also available:

| Variable | Purpose |
|---|---|
| `LATCH_CONFIG` | Default policy path |
| `LATCH_AGENT` | Default trusted launcher identity |
| `LATCH_MCP_LISTEN` | Streamable HTTP proxy listen address |
| `LATCH_MCP_TOKEN` | Client-facing Streamable HTTP bearer token |
| `LATCH_MCP_UPSTREAM_TOKEN` | Separate upstream MCP bearer token |
| `LATCH_AUDIT_PATH` | Audit JSONL location |
| `LATCH_APPROVAL_STORE` | Durable approval store |
| `LATCH_BUDGET_STORE` | Durable budget store |
| `LATCH_AUDIT_TERMINAL` | `true` or `false` terminal audit output |

Use absolute paths for environment overrides in services and containers.
Without `LATCH_CONFIG`, Latch first looks for `latch.yaml` in the current
directory, then for the platform system package configuration (for example
`/etc/latch/latch.yaml`), and finally reports the local `latch.yaml` path in
any load error.

# MCP Streamable HTTP adapter

`latch proxy-http` is a reverse security boundary for MCP Streamable HTTP. It
evaluates every `tools/call` immediately before forwarding it and preserves the
rest of the MCP session, including JSON responses, Server-Sent Events (SSE),
notifications, server-to-client requests, protocol negotiation, resumption,
and session termination.

The adapter targets the stable MCP `2025-11-25` transport. It accepts the
standard single-object JSON-RPC POST format and supports `GET` and `DELETE` on
the same endpoint. Draft protocol behavior is not silently advertised as
stable.

## Start the proxy

Create separate client-facing and upstream credentials:

```sh
export LATCH_MCP_TOKEN="$(openssl rand -hex 32)"
export LATCH_MCP_UPSTREAM_TOKEN="token-issued-by-the-upstream-server"
```

Start Latch on the loopback interface:

```sh
latch proxy-http \
  --config latch.yaml \
  --listen 127.0.0.1:7071 \
  --agent desktop-agent \
  --upstream https://tools.example/mcp
```

The client endpoint is `http://127.0.0.1:7071/mcp` by default. Change it with
`--path` and the listening socket with `--listen`.

## Generate a client configuration

```sh
latch integrations mcp-http --client vscode --name protected-tools \
  --url http://127.0.0.1:7071/mcp --output .vscode/mcp.json
```

Supported targets are `vscode`, `cursor`, `claude-code`, and `generic`.

- VS Code output uses a password input, so the token is collected and stored
  by the client rather than written to the JSON file.
- Claude Code and generic output reference the `LATCH_MCP_TOKEN` environment
  variable.
- Cursor output uses its environment-variable header form. Store a literal
  token only in user-level configuration if a specific Cursor build cannot
  interpolate remote headers; never commit it.
- `--no-auth` emits no authorization header. Use it only with an authless
  loopback proxy and no trusted agent binding.

Claude and Claude Desktop remote connectors are configured through Settings >
Connectors rather than `claude_desktop_config.json`. Internet-facing connector
deployments normally need an OAuth-aware gateway; Latch's current adapter
provides static bearer authentication and does not claim to be an OAuth
authorization server.

## Security contract

| Control | Behavior |
|---|---|
| Tool enforcement | Only an explicit Latch `ALLOW` reaches the upstream server. |
| Identity | `--agent` is operator-bound and verified; MCP client metadata is self-asserted and unverified. |
| Authentication | `LATCH_MCP_TOKEN` authenticates clients using constant-time comparison. |
| Credential separation | The Latch token is stripped; `LATCH_MCP_UPSTREAM_TOKEN` is added independently. |
| Browser origins | Every supplied `Origin` must exactly match a repeated `--allow-origin`; otherwise HTTP 403 is returned. |
| JSON ambiguity | Duplicate object keys, batches, invalid UTF-8, trailing values, and malformed calls are rejected. |
| Request limits | Bodies are bounded to 4 MiB by default and may be set from 1 KiB through 16 MiB. |
| Redirects | Upstream redirects are forbidden and fail closed. |
| Sessions | Visible-ASCII session IDs are bounded, retained with an LRU-style capacity limit, expired, and removed on successful DELETE or upstream 404. |
| Streaming | JSON and SSE response bodies stream without buffering the full upstream result. |
| Enforcement state | Approval, budget, and required audit failures return a local MCP error result and never reach upstream. |

The adapter also removes client-supplied forwarding headers and HTTP
hop-by-hop headers. Query parameters are rejected so credentials and routing
state cannot be smuggled outside the single MCP endpoint contract.

## Network safety

Loopback is the safe default. A non-loopback listener requires:

1. a trusted `--agent`;
2. a bearer token from `--token-env` (default `LATCH_MCP_TOKEN`); and
3. either `--tls-cert` plus `--tls-key`, or `--behind-tls-proxy`.

Cleartext upstream HTTP is accepted automatically only for loopback targets.
For a deliberate private-network hop, pass `--allow-http-upstream`; this flag
does not make the network encrypted or trusted.

The default session capacity is 10,000 with a 24-hour inactivity lifetime.
Tune these with `--max-sessions` and `--session-ttl`. The session cache stores
only identity context, never bearer tokens or tool arguments.

## Failure behavior

Invalid requests receive a JSON-RPC error with the appropriate HTTP failure
status. `BLOCK` and `REQUIRE_APPROVAL` receive an HTTP 200 MCP tool result with
`isError: true` and `io.latch/security` decision metadata. The action is not
sent upstream.

An upstream outage, redirect, or invalid session response returns HTTP 502.
As with stdio, budget capacity is reserved immediately before an allowed call
crosses the boundary. A later upstream transport failure may therefore consume
that attempt; this prevents retry races from exceeding a configured budget.

## Important flags

| Flag | Default | Purpose |
|---|---:|---|
| `--upstream` | required | Real MCP Streamable HTTP endpoint. |
| `--listen` | `127.0.0.1:7071` | Listener socket. |
| `--path` | `/mcp` | Exact public endpoint path. |
| `--agent` | `LATCH_AGENT` | Operator-bound identity. |
| `--token-env` | `LATCH_MCP_TOKEN` | Client bearer-token environment variable. |
| `--upstream-token-env` | `LATCH_MCP_UPSTREAM_TOKEN` | Upstream bearer-token environment variable. |
| `--allow-origin` | none | Exact browser origin; repeatable. |
| `--max-message-bytes` | `4194304` | Maximum JSON-RPC POST body. |
| `--max-sessions` | `10000` | Session identity cache capacity. |
| `--session-ttl` | `24h` | Inactive session identity lifetime. |
| `--allow-http-upstream` | false | Explicitly permit non-loopback cleartext upstream HTTP. |

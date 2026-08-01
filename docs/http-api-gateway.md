# Generic HTTP/API gateway

`latch proxy-api` is a drop-in reverse security gateway for agents and tools
that already speak HTTP. Point the tool's API base URL at Latch; Latch turns
each request into the canonical `http.request` action, evaluates it, and sends
it to one operator-fixed upstream only after an explicit `ALLOW`.

## Start the gateway

```sh
export LATCH_HTTP_TOKEN="$(openssl rand -hex 32)"
export SERVICE_AUTHORIZATION="Bearer upstream-service-token"

latch proxy-api \
  --config latch.yaml \
  --agent api-agent \
  --upstream https://api.example/v1 \
  --upstream-header-env Authorization=SERVICE_AUTHORIZATION
```

The default listener is `http://127.0.0.1:7072`. A client request to
`/customers/42?view=summary` is evaluated and, if allowed, forwarded to
`https://api.example/v1/customers/42?view=summary`:

```sh
curl http://127.0.0.1:7072/customers/42?view=summary \
  -H "X-Latch-Token: $LATCH_HTTP_TOKEN"
```

Generate a reusable, secret-safe connection object for an existing tool:

```sh
latch integrations http --url http://127.0.0.1:7072
```

```json
{
  "base_url": "http://127.0.0.1:7072",
  "headers": {
    "X-Latch-Token": "${LATCH_HTTP_TOKEN}"
  }
}
```

The placeholder names an environment variable; the generator never reads or
writes its secret value.

## Credential boundaries

Gateway and upstream credentials are deliberately separate:

- `LATCH_HTTP_TOKEN` authenticates the client to Latch. It is read from the
  environment named by `--token-env`, carried in `X-Latch-Token` by default,
  compared in constant time, and never forwarded.
- `LATCH_HTTP_UPSTREAM_TOKEN` is an optional upstream bearer token. Latch adds
  it only after an action is allowed.
- `--upstream-header-env Header=ENV_VAR` adds any other operator-controlled
  upstream credential or tenant header after the decision. Repeat the option
  for multiple headers. An explicitly configured but empty environment
  variable stops startup.
- Agent-supplied authorization, cookies, API keys, and auth tokens are stripped
  by default. `--forward-sensitive-headers` preserves them only when dynamic
  credentials are unavoidable; Latch then includes their redacted header names
  in risk analysis, where external credential movement is a hard deny unless a
  tightly scoped unsafe override permits it.

Operator-controlled upstream credential values never enter the normalized
action, denial response, or audit event.

## What is evaluated

Every request is normalized with:

- tool: `http.request`
- operation: `network`
- exact method and fixed-upstream destination URL
- agent-controlled header names and bounded non-secret values
- parsed JSON, form, or UTF-8 text content when the body is at most 256 KiB
- content type, byte count, and SHA-256 digest for opaque bodies
- trusted agent identity from `--agent`

Secret-looking query values are replaced before policy evaluation and audit,
while their field names remain visible to the risk detector. The original
query is used only for the allowed upstream request.

Binary, unknown-media-type, or larger bodies are marked
`body_inspected: false`. That adds the `uninspected-http-body` risk signal; the
balanced defaults therefore require approval instead of silently treating an
opaque upload as safe. The forwarding ceiling defaults to 4 MiB and can be
changed with `--max-body-bytes` between 1 KiB and 16 MiB.

Compressed request bodies are rejected because content inspection must happen
on the same semantic bytes the upstream parses. JSON bodies reject duplicate
keys at every depth. Invalid form encoding, malformed media types, path dot
segments, encoded path separators, NULs, oversized paths or queries, and
`CONNECT`/`TRACE` are also blocked before evaluation.

## Policy example

The adapter uses existing URL, hostname, HTTP method, and argument matching:

```yaml
rules:
  - id: block-customer-deletion
    description: Agents may never delete customer records
    priority: 100
    match:
      tool: [http.request]
      hostname: [api.example]
      http_method: [DELETE]
      url: ["https://api.example/v1/customers/**"]
    action: BLOCK

  - id: approve-customer-updates
    description: Customer mutations need operator review
    priority: 80
    match:
      tool: [http.request]
      hostname: [api.example]
      http_method: [POST, PUT, PATCH]
      url: ["https://api.example/v1/customers/**"]
    action: REQUIRE_APPROVAL
```

Policy, protected risk signals, verified identity, approvals, budgets, and
required audit logging have the same precedence as every other Latch adapter.
An audit, approval-store, or budget-store failure never reaches the upstream.

## Client-visible outcomes

Only `ALLOW` forwards. Successful upstream responses preserve their status,
end-to-end headers, and streamed body, with `X-Latch-Decision: ALLOW` added.
Latch owns browser CORS headers when an exact `--allow-origin` is configured.

Local denials use `application/vnd.latch.proxy.v1+json`:

| HTTP status | Meaning |
|---|---|
| `401` | Missing or invalid gateway token |
| `403` | Policy or protected-risk block |
| `428` | Exact action requires approval |
| `429` | Cumulative action budget exhausted |
| `503` | Audit or durable enforcement state unavailable |

Malformed or unsafe inputs use the appropriate `4xx`; upstream connection
failures and forbidden redirects use `502`. Latch never follows upstream
redirects, retries a request, or falls back to direct access.

## Deployment controls

Non-loopback listeners require a token, trusted `--agent`, and either
`--tls-cert`/`--tls-key` or `--behind-tls-proxy`. Cleartext non-loopback
upstreams are rejected unless the operator explicitly supplies
`--allow-http-upstream`. Browser origins are denied unless repeated exact
`--allow-origin` values permit them; wildcard origins are not supported.

Keep the real upstream address and credentials out of agent configuration.
Network policy should also prevent the agent from bypassing the gateway and
reaching the upstream directly.

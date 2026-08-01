# Stable Enforcement API v1

The Latch Enforcement API is the shared pre-execution contract for SDKs and
adapters. A caller submits one intended action immediately before execution and
receives one explicit `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL` verdict.

The contract version is `latch.security/v1`. Its canonical OpenAPI description
is [`api/openapi.yaml`](../api/openapi.yaml).

## Start the local service

```sh
export LATCH_API_TOKEN="$(openssl rand -hex 32)"
latch serve --config latch.yaml --agent desktop-agent
```

The safe default listens on `127.0.0.1:7070`. The token must contain at least
32 bytes, is read from the environment, and is never placed on the command line. A trusted `--agent` binding
is rejected unless authentication is active. For unverified local development,
omit both `--agent` and the token:

```sh
latch serve --config latch.yaml
```

Non-loopback listeners are rejected unless an agent binding, bearer token, and
TLS are configured. `--behind-tls-proxy` is available when a trusted local
reverse proxy terminates TLS.

## Request a decision

```sh
curl --fail-with-body http://127.0.0.1:7070/v1/decisions \
  -H 'Content-Type: application/vnd.latch.decision.v1+json' \
  -H "Authorization: Bearer $LATCH_API_TOKEN" \
  --data '{
    "api_version": "latch.security/v1",
    "request_id": "req_019fb8f80a8f7c2d",
    "action": {
      "tool": "filesystem.read",
      "arguments": {"path": "./README.md"}
    }
  }'
```

A valid enforcement decision always returns HTTP `200`. HTTP success does not
mean permission: the caller must execute only when `decision` is exactly
`ALLOW`. Any timeout, connection error, invalid response, unsupported API
version, `BLOCK`, or `REQUIRE_APPROVAL` must stop execution.

```json
{
  "api_version": "latch.security/v1",
  "request_id": "req_019fb8f80a8f7c2d",
  "decision": "ALLOW",
  "risk": {"score": 0, "level": "LOW"},
  "identity": {
    "verified": true,
    "source": "api_server_config",
    "canonical_agent_id": "desktop-agent"
  },
  "policy": {
    "decision_source": "default_allow",
    "hard_deny": false
  }
}
```

## Security semantics

- `request_id` is an idempotency key. Reuse is rejected with `409` so an old
  `ALLOW` cannot be replayed through the API process.
- Request bodies cannot mark an identity verified. Only an operator-controlled
  server binding can establish trusted identity in v1.
- Unknown JSON fields, oversized bodies, unsupported media types, and malformed
  requests are rejected before evaluation.
- Browser origins are denied unless explicitly listed with `--allow-origin`.
- Bearer credentials are read from an environment variable and are never
  returned, logged, or accepted in a URL.
- An allowed decision reserves matching cumulative budget capacity before it is
  returned.
- Approval, budget, and audit failures produce a `BLOCK` with
  `fail_closed: true`.
- Every valid decision is written to the configured redacted audit trail.

`GET /healthz` and `GET /readyz` provide process and readiness probes. They do
not evaluate actions and do not require bearer authentication.

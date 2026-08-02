# Interactive policy playground

The Latch Policy Lab is a local, execution-free interface for answering three
questions before a policy reaches an agent:

- What will Latch decide for this exact action?
- Which rule, identity control, or deterministic risk signal caused it?
- Did my policy edit strengthen, weaken, or preserve the boundary?

## Start the lab

```sh
latch playground --config latch.yaml --open
```

Latch loads the policy as an immutable comparison baseline, starts a loopback
web interface at `http://127.0.0.1:7073`, and optionally opens it in the default
browser. Use another local port when needed:

```sh
latch playground --config ./policies/agent.yaml \
  --agent desktop-agent \
  --listen 127.0.0.1:8087 \
  --open
```

If the default `latch.yaml` does not exist, the lab opens with an in-memory
balanced starter policy. An explicitly supplied missing `--config` is an error,
so a typo cannot silently select the starter.

## Evaluation workflow

1. Select an attack-lab preset or paste the complete intended action as JSON.
2. Set the operator-established agent identity and whether the transport has
   verified it.
3. Edit the loaded YAML policy in memory.
4. Select **Evaluate action** or press `Ctrl+Enter` / `Cmd+Enter`.
5. Inspect the final decision, source, identity result, normalized action,
   matching rules, deterministic risk signals, and reasons.
6. Review the baseline comparison. A prominent warning appears when an edit
   changes `BLOCK` to `REQUIRE_APPROVAL` or `ALLOW`, or changes
   `REQUIRE_APPROVAL` to `ALLOW`.

The built-in presets cover workspace reads, production writes, private-key
access, credential exfiltration, and shell execution. They are examples, not a
separate mock decision system: every evaluation uses Latch's normalizer, strict
policy parser, identity authorization, policy precedence, and deterministic
risk engine.

## Simulation contract

The lab deliberately has less authority than an enforcement adapter:

- It binds only to loopback addresses. Wildcard and LAN bindings are rejected.
- The browser session uses a random same-origin token, strict host checks,
  request-size limits, a restrictive Content Security Policy, and no CORS.
- JSON with duplicate keys, trailing values, or unknown contract fields is
  rejected.
- YAML with duplicate keys, unknown policy fields, multiple documents, or an
  invalid Latch policy is rejected.
- No tool, command, child process, upstream HTTP service, or MCP server is ever
  invoked.
- Policy edits stay in browser memory. The policy file, approval store, budget
  store, and audit log are never changed.
- Durable approval grants and current budget usage are intentionally excluded.
  Approval rules therefore remain `REQUIRE_APPROVAL`, and budgets are shown as
  configured policy rather than live consumption.

This makes the lab safe for policy design, explanation, review, and regression
experiments. It is not an execution gateway and never returns authority to run
a side effect.

## When to use live evaluation

Use the Policy Lab to reason about policy semantics. Use `latch check --json`
to inspect a real local evaluator with configured operational state, and use a
first-class Latch adapter immediately before the real side effect for
enforcement.

Do not paste production secrets into example actions. Data remains local, but
the lab does not need real credentials to detect secret-bearing fields or
demonstrate exfiltration controls.

## Local API contract

The UI uses the versioned `latch.playground/v1` simulation contract:

- `GET /api/bootstrap` returns the loaded baseline, initial identity, request
  limit, and short-lived browser-session token.
- `POST /api/evaluate` accepts edited policy YAML, optional baseline policy,
  one stable API action, and explicit identity verification state.
- Successful responses include the normalized action, full assessment,
  matching-rule trace, policy digest and counts, and a decision delta.

This contract belongs to the local Policy Lab. External tool integrations
should continue to use the stable `latch.security/v1` Enforcement API.

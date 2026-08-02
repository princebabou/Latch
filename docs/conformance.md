# Conformance and security testing

Latch ships a versioned, machine-readable security corpus and an offline
runner. It exists to make adapter security measurable: integrations must prove
that they execute only an explicit `ALLOW` and fail closed when policy,
protocol, audit, replay, or availability guarantees are not satisfied.

## Run the suite

```sh
latch conformance
```

The command starts no external server, opens no external connection, and never
executes a tool. Each case uses isolated temporary state and an in-memory fake
upstream. A successful built-in run reports 41 of 41 checks:

```text
LATCH CONFORMANCE latch.conformance/v1 (suite 1.0.0)

PASS  decision-core            7/7 decision checks
PASS  enforcement-api          7/7 decision checks
PASS  mcp-stdio                7/7 decision checks
PASS  mcp-streamable-http      7/7 decision checks
PASS  generic-http-api         7/7 decision checks
PASS  enforcement-api-wire     6/6 wire checks

Result: 41/41 passed
```

Use JSON in automation:

```sh
latch conformance --json
```

The command exits `0` only when every requirement passes, `1` on any failed
requirement, and `64` for invalid command use. `--timeout` bounds the complete
run and is capped at five minutes.

## Versioned contract

The canonical corpus is
[`internal/conformance/testdata/v1/manifest.json`](../internal/conformance/testdata/v1/manifest.json).
Inspect the exact embedded manifest in any distributed Latch binary:

```sh
latch conformance --manifest
```

Its schema identifier is `latch.conformance/v1`. Case IDs are stable and
unique, so CI systems can compare reports without parsing human text. Breaking
requirement changes require a new schema version; compatible cases can extend
the existing suite version.

## Security profiles

| Profile | Required behavior | Certified boundaries |
|---|---|---|
| Decision | Baseline allow, explicit block, unresolved approval, block-wins conflict resolution, hard-deny bypass resistance, approval expiry, and required-audit fail-closed behavior | Decision core, Enforcement API, MCP stdio, MCP Streamable HTTP, generic HTTP/API gateway |
| Wire | Malformed JSON, nested duplicate keys, unknown fields, trailing values, replayed request IDs, and oversized bodies are rejected before execution | Enforcement API |
| Client | Only a correlated, version-compatible `ALLOW` executes; block, approval, unknown verdicts, version/ID mismatches, malformed or oversized responses, redirects, and outages do not execute | Go, Python, and TypeScript SDKs |

The SDK tests load the same manifest rather than maintaining independent test
lists. Adapter-specific suites additionally test batch atomicity, tool-call
replays, executable fingerprint changes, session behavior, credential
stripping, and provider-native reporting where those concepts apply.

## What certification means

Certification demonstrates behavior at Latch's enforcement boundary. It does
not claim that an untrusted caller cannot bypass a deployment where the real
tool remains directly reachable. Operators must place Latch on the only path to
the side effect, keep identity and upstream credentials outside agent control,
and treat transport or audit failure as denial.

The runner deliberately avoids live network services and arbitrary tool
execution. Environment-specific TLS, authentication, process sandboxing, and
network isolation remain deployment tests.

## Adding an adapter

An adapter is ready to claim conformance only when it:

1. Maps the complete intended action into the stable Enforcement API model.
2. Runs the applicable manifest profile without changing expected outcomes.
3. Proves that its side-effect callback or upstream forward count stays zero
   for every non-allow and error case.
4. Adds boundary-specific replay, mutation, and partial-batch tests.
5. Runs its certification in required CI and publishes a machine-readable
   failure report.

Do not translate `REQUIRE_APPROVAL` into success, reuse an old `ALLOW`, retry a
side effect after an ambiguous failure, or add a fail-open mode. Those behaviors
are incompatible with Latch conformance.

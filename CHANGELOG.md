# Changelog

All notable changes to Latch are documented here. This project follows
[Semantic Versioning](https://semver.org). Dates are in UTC.

## v0.2.0 — 2026-08-17

The first release of the versioned `latch.security/v1` enforcement contract and
the integrations built on it. Latch moves from a single CLI evaluator to a
protocol-neutral control plane with official SDKs, transport gateways,
framework adapters, and a certified security corpus.

### Added

- **Stable Enforcement API (`latch.security/v1`).** A versioned, fail-closed
  `POST /v1/decisions` contract with replay protection, operator-bound
  identity, and health checks. A valid verdict always returns HTTP `200`;
  callers execute only an explicit `ALLOW`.
- **Official SDKs.** Fail-closed Go, Python, and TypeScript clients with
  guarded execution helpers that invoke a tool only after a valid,
  request-correlated `ALLOW`.
- **Anthropic Messages API adapter.** Guards Claude `tool_use` blocks in all
  three SDKs: whole-message authorization, replay defense on `tool_use` IDs,
  and provider-native `tool_result` output.
- **OpenAI-compatible tool adapters.** Responses API and Chat Completions
  function-call guards with whole-batch authorization and replay defense.
- **LangChain and LangGraph adapters.** Native middleware and whole-batch
  protected ToolNodes for Python and TypeScript.
- **Protected local process execution.** Argv-first executors with executable
  fingerprinting, replay protection, and bounded execution.
- **Transport gateways.** Bidirectional MCP stdio and Streamable HTTP proxies,
  and a generic HTTP/API reverse gateway with semantic body inspection and
  separated credentials.
- **Remote approval flow.** Pending `REQUIRE_APPROVAL` responses carry an
  approval challenge with the exact action fingerprint. An optional webhook
  posts a redacted alert (Slack or generic), and `GET`/`POST /v1/approvals`
  issues and lists grants behind a dedicated approver token that must differ
  from the decision bearer token, so an agent cannot approve its own actions.
- **PowerShell-aware risk analysis.** A PowerShell grammar pass runs alongside
  the POSIX analyzer, adding deterministic signals for download-to-execution
  cradles, encoded commands, execution-policy bypass, hidden-window execution,
  endpoint-protection tampering (hard-deny), and autorun/scheduled-task
  persistence.
- **CI/CD gate.** A native GitHub Action, job-summary reporting, typed outputs,
  and a reusable policy-gate workflow.
- **Cross-adapter conformance suite.** `latch conformance` certifies decision,
  wire, and fail-closed client behavior against a versioned security corpus.
- **Interactive Policy Lab.** A loopback-only workbench that evaluates editable
  YAML and action JSON through the real engine, explains each result, and
  detects policy weakening without touching operational state.
- **Developer portal.** Product site, documentation, and a decision playground.

### Changed

- Deterministic risk `deny-overrides` precedence now documents an explicit,
  loudly-labeled `unsafe_override` break-glass path.
- The README milestone summary reflects the shipped v0.2 surface; observability
  and reference deployments remain the next milestones.

### Security

- Every proxy, gateway, adapter, and SDK fails closed: malformed or oversized
  protocol messages, ambiguous parses, approval-store or budget contention, and
  audit-write failures deny protected actions rather than allowing them.
- Approval notifications never follow redirects, require HTTPS for
  non-loopback hosts, and never change a verdict on delivery failure.

## v0.1.1

Security and supply-chain hardening.

## v0.1.0

Initial Latch security enforcement layer.

export type DocSection = {
  id: string;
  title: string;
  paragraphs?: string[];
  bullets?: string[];
  code?: string;
  language?: string;
  note?: string;
};

export type DocPage = {
  slug: string;
  group: string;
  title: string;
  summary: string;
  readingTime: string;
  sections: DocSection[];
};

export const docs: DocPage[] = [
  {
    slug: "quickstart",
    group: "Start",
    title: "Quickstart",
    summary:
      "Install Latch, create a production-oriented policy, validate it, and protect an MCP server.",
    readingTime: "6 min",
    sections: [
      {
        id: "install",
        title: "Install Latch",
        paragraphs: [
          "Official releases include static binaries for Linux, macOS, and Windows on AMD64 and ARM64, Linux packages, checksums, SBOMs, and attestations.",
        ],
        code: `# Linux or macOS
curl -fsSL https://raw.githubusercontent.com/princebabou/Latch/main/scripts/install.sh | sh

# Windows PowerShell
irm https://raw.githubusercontent.com/princebabou/Latch/main/scripts/install.ps1 | iex

# Or install from source with Go 1.24+
go install github.com/princebabou/Latch/cmd/latch@latest`,
      },
      {
        id: "create-policy",
        title: "Create a policy",
        paragraphs: [
          "The balanced profile creates a verified launcher identity, a durable runaway-action budget, private-key and environment-file blocks, and human approval gates for shell and production writes.",
        ],
        code: `latch init --profile balanced --agent desktop-agent

# Other starting points
latch init --profile strict --agent desktop-agent
latch init --profile developer --agent desktop-agent`,
        note: "Latch will not silently replace an existing policy. Pass --force only when replacement is intentional.",
      },
      {
        id: "doctor",
        title: "Validate the boundary",
        paragraphs: [
          "Run diagnostics before wiring the launcher. Doctor checks policy validity, trusted identity, capability and budget readiness, state locations, the working directory, and the server executable without starting it.",
        ],
        code: `latch doctor \\
  --config latch.yaml \\
  --agent desktop-agent \\
  -- my-mcp-server`,
      },
      {
        id: "integrate",
        title: "Generate native MCP configuration",
        paragraphs: [
          "Generate a complete launcher entry for Claude Desktop, Cursor, Visual Studio Code, or a reusable generic object. Latch emits absolute paths so GUI launchers do not depend on their working directory.",
        ],
        code: `latch integrations mcp \\
  --client vscode \\
  --name protected-server \\
  --config latch.yaml \\
  --agent desktop-agent \\
  --output .vscode/mcp.json \\
  -- my-mcp-server`,
      },
      {
        id: "test",
        title: "Test the policy",
        paragraphs: [
          "The check command evaluates but never executes an action. It exits 0 only for ALLOW and 3 for BLOCK or unresolved REQUIRE_APPROVAL.",
        ],
        code: `latch check --tool filesystem.read --arg path=./README.md
latch check --tool filesystem.read --arg path=~/.ssh/id_rsa
latch check --tool shell.exec --arg "command=npm test" --interactive`,
      },
    ],
  },
  {
    slug: "concepts",
    group: "Understand",
    title: "Core concepts",
    summary:
      "Understand the action boundary, deterministic decision contract, and deny-overrides precedence model.",
    readingTime: "8 min",
    sections: [
      {
        id: "boundary",
        title: "The enforcement boundary",
        paragraphs: [
          "Latch is a control plane, not a prompt-injection scanner. It belongs between an agent and the real tools, files, shells, APIs, databases, and MCP servers the agent can reach.",
          "A transport adapter normalizes the requested tool call into a protocol-neutral Action. Policy, deterministic risk analysis, trusted identity, capability ceilings, budgets, and approvals then produce an Assessment before execution.",
        ],
      },
      {
        id: "decisions",
        title: "Three decisions",
        bullets: [
          "ALLOW — the action passed every stronger control and may be forwarded.",
          "BLOCK — the action must not execute. A policy, identity failure, budget, hard-deny signal, or risk threshold can block it.",
          "REQUIRE_APPROVAL — the exact normalized action needs a valid human grant before forwarding.",
        ],
      },
      {
        id: "precedence",
        title: "Deny-overrides precedence",
        paragraphs: [
          "A broad allow can never silently weaken a stronger control. Latch evaluates controls in a fixed order.",
        ],
        bullets: [
          "Matching BLOCK policy",
          "Unverified, unknown, mismatched, or under-capable identity",
          "Built-in hard-deny signal or block-threshold risk",
          "Exhausted cumulative action budget",
          "Matching REQUIRE_APPROVAL policy",
          "Explicit resource-scoped unsafe override, when globally enabled",
          "Ordinary matching ALLOW policy",
          "Risk approval threshold",
          "No stronger control: allow",
        ],
      },
      {
        id: "explanation",
        title: "Every verdict carries evidence",
        paragraphs: [
          "Assessments record the decision source, hard-deny status, unsafe override status, identity verification, canonical agent ID, matched capabilities, matching budget state, risk score, signals, policies, and reasons.",
        ],
        code: `latch check \\
  --tool http.request \\
  --arg url=https://api.example.com/data \\
  --arg method=GET \\
  --json`,
      },
    ],
  },
  {
    slug: "policies",
    group: "Configure",
    title: "Policies",
    summary:
      "Write readable YAML controls for tools, operations, paths, commands, URLs, HTTP, SQL, and arguments.",
    readingTime: "12 min",
    sections: [
      {
        id: "shape",
        title: "Policy shape",
        paragraphs: [
          "A policy defines enforcement thresholds, identities, budgets, approval storage, audit behavior, and ordered rules. Rules match typed action fields and return allow, block, or require_approval.",
        ],
        code: `version: 1

enforcement:
  approval_threshold: 40
  block_threshold: 90
  allow_unsafe_overrides: false

rules:
  - id: production-delete
    description: Production deletion is prohibited.
    match:
      tool: database.query
      database_operation: DELETE
      arguments:
        environment: production
    action: block`,
        language: "yaml",
      },
      {
        id: "matchers",
        title: "Typed matchers",
        bullets: [
          "tool and normalized action/operation",
          "filesystem path and resource",
          "shell command",
          "URL, hostname, and HTTP method",
          "database operation",
          "structured action arguments",
        ],
        note: "Matchers are case-aware where security semantics require it and reuse the same structured parsers used by risk analysis.",
      },
      {
        id: "approval-rule",
        title: "Require a human decision",
        code: `- id: shell-needs-approval
  description: Shell execution requires a human decision.
  match:
    tool: shell.exec
  action: require_approval

- id: production-write-needs-approval
  description: Production writes require explicit approval.
  match:
    action: write
    arguments:
      environment: production
  action: require_approval`,
        language: "yaml",
      },
      {
        id: "unsafe-overrides",
        title: "Break-glass overrides",
        paragraphs: [
          "Unsafe overrides are disabled by default. Enabling one requires a policy-wide opt-in and a narrowly constrained allow rule with a description.",
          "A matching BLOCK or REQUIRE_APPROVAL rule still takes precedence. Identity capability ceilings and exhausted budgets are never bypassed.",
        ],
        code: `enforcement:
  allow_unsafe_overrides: true

rules:
  - id: break-glass-scratch-cleanup
    description: Permit cleanup of this disposable recovery directory.
    unsafe_override: true
    match:
      tool: shell.exec
      command: "rm -rf ./scratch"
    action: allow`,
        language: "yaml",
      },
      {
        id: "validate",
        title: "Validate and inspect",
        code: `latch policies validate --config latch.yaml
latch policies list --config latch.yaml`,
      },
    ],
  },
  {
    slug: "mcp",
    group: "Integrate",
    title: "MCP stdio gateway",
    summary:
      "Place a transparent, fail-closed security boundary in front of local MCP servers.",
    readingTime: "10 min",
    sections: [
      {
        id: "proxy",
        title: "Wrap the server process",
        paragraphs: [
          "Place Latch where the MCP client would normally launch the server. Latch owns the child process, forwards the full session in both directions, and evaluates tools/call requests before they reach it.",
        ],
        code: `latch proxy \\
  --config /absolute/path/latch.yaml \\
  --agent desktop-agent \\
  -- /absolute/path/my-mcp-server --server-option`,
      },
      {
        id: "transparent",
        title: "What passes through",
        paragraphs: [
          "Initialization, notifications, tool discovery, server-to-client requests, responses, and protocol methods Latch does not inspect pass through transparently.",
          "Blocked and approval-required calls receive MCP tool results with isError: true and are never sent upstream.",
        ],
      },
      {
        id: "identity",
        title: "Bind identity outside the protocol",
        paragraphs: [
          "The --agent value lives in operator-controlled launcher configuration. Client names reported inside MCP metadata are retained for diagnostics but treated as self-asserted and unverified.",
        ],
        note: "For local stdio, the launcher process is the trust boundary. Do not treat an MCP payload field as cryptographic remote identity.",
      },
      {
        id: "framing",
        title: "Transport guarantees",
        bullets: [
          "UTF-8 JSON-RPC, one message per line",
          "Protocol data exclusively on stdout; diagnostics on stderr",
          "4 MiB default message limit, configurable with --max-message-bytes",
          "Invalid client calls receive standard JSON-RPC errors",
          "Malformed or oversized upstream output fails closed",
        ],
      },
      {
        id: "clients",
        title: "Generate client configuration",
        code: `latch integrations mcp --client claude  --name protected --agent desktop-agent -- my-mcp-server
latch integrations mcp --client cursor  --name protected --agent desktop-agent -- my-mcp-server
latch integrations mcp --client vscode  --name protected --agent desktop-agent -- my-mcp-server
latch integrations mcp --client generic --name protected --agent desktop-agent -- my-mcp-server`,
      },
    ],
  },
  {
    slug: "mcp-http",
    group: "Integrate",
    title: "MCP Streamable HTTP gateway",
    summary:
      "Protect remote MCP JSON and SSE sessions through an authenticated, fail-closed boundary.",
    readingTime: "8 min",
    sections: [
      {
        id: "start",
        title: "Start the boundary",
        paragraphs: [
          "Clients connect to Latch while the real MCP endpoint and its credentials remain operator-controlled.",
        ],
        code: `export LATCH_MCP_TOKEN="$(openssl rand -hex 32)"
export LATCH_MCP_UPSTREAM_TOKEN="upstream-service-token"

latch proxy-http \\
  --config latch.yaml \\
  --agent remote-agent \\
  --upstream https://tools.example/mcp`,
      },
      {
        id: "clients",
        title: "Generate client configuration",
        code: `latch integrations mcp-http \\
  --client vscode \\
  --name protected-tools \\
  --url http://127.0.0.1:7071/mcp`,
      },
      {
        id: "guarantees",
        title: "Transport guarantees",
        bullets: [
          "Shared tools/call enforcement with the stdio adapter",
          "POST, GET, DELETE, JSON, SSE, and session preservation",
          "Separate client-facing and upstream bearer credentials",
          "Exact origin allowlists and strict session validation",
          "Duplicate-key JSON, redirects, oversized input, and state failures fail closed",
        ],
      },
    ],
  },
  {
    slug: "http-api",
    group: "Integrate",
    title: "Generic HTTP/API gateway",
    summary:
      "Point an existing HTTP tool at an allow-only reverse gateway without changing the upstream service.",
    readingTime: "10 min",
    sections: [
      {
        id: "start",
        title: "Protect a fixed API",
        paragraphs: [
          "Latch evaluates the method, fixed-upstream URL, agent-controlled headers, query, and semantic body before forwarding. Only an explicit ALLOW crosses the boundary.",
        ],
        code: `export LATCH_HTTP_TOKEN="$(openssl rand -hex 32)"
export SERVICE_AUTHORIZATION="Bearer upstream-service-token"

latch proxy-api \\
  --config latch.yaml \\
  --agent api-agent \\
  --upstream https://api.example/v1 \\
  --upstream-header-env Authorization=SERVICE_AUTHORIZATION`,
      },
      {
        id: "connect",
        title: "Connect an existing tool",
        code: `latch integrations http --url http://127.0.0.1:7072

curl http://127.0.0.1:7072/customers/42 \\
  -H "X-Latch-Token: $LATCH_HTTP_TOKEN"`,
      },
      {
        id: "credentials",
        title: "Separate credentials by authority",
        bullets: [
          "X-Latch-Token authenticates the caller and is never forwarded.",
          "Operator upstream credentials are injected only after ALLOW and never enter action or audit data.",
          "Agent authorization, cookies, and API keys are stripped by default.",
          "Dynamic credential forwarding is explicit and remains visible to protected risk analysis.",
        ],
      },
      {
        id: "inspection",
        title: "Semantic and fail-closed inspection",
        bullets: [
          "JSON rejects duplicate keys at every depth.",
          "JSON, forms, and UTF-8 text are parsed up to 256 KiB.",
          "Opaque or larger bodies receive an uninspected-body risk signal and require scrutiny.",
          "Compressed bodies, unsafe paths, CONNECT, TRACE, and upstream redirects are rejected.",
          "Audit, approval, budget, and upstream failures never fall back to direct access.",
        ],
      },
    ],
  },
  {
    slug: "identities-budgets",
    group: "Configure",
    title: "Identities & budgets",
    summary:
      "Bind operator-controlled identities, cap capabilities, and stop cumulative or runaway behavior.",
    readingTime: "10 min",
    sections: [
      {
        id: "identities",
        title: "Verified launcher identities",
        paragraphs: [
          "Register a canonical ID for each independently administered launcher. Aliases are case-insensitive operator-facing names; the canonical ID is used in approvals, budgets, and audit records.",
        ],
        code: `identity:
  require_verified: true
  enforce_capabilities: true
  agents:
    - id: desktop-agent
      aliases: ["Claude Desktop"]
      capabilities:
        - id: workspace-read
          description: Read files inside the workspace.
          match:
            tool: filesystem.read
            action: read
            path: "./**"`,
        language: "yaml",
      },
      {
        id: "capabilities",
        title: "Capabilities are ceilings",
        paragraphs: [
          "A capability does not allow an action. The action must fit at least one capability and then still pass every block, approval, budget, and risk control.",
          "Capability enforcement requires verified identities; Latch rejects configurations that assign security authority to spoofable names.",
        ],
      },
      {
        id: "budgets",
        title: "Durable rolling budgets",
        paragraphs: [
          "Budgets stop autonomous loops and slow cumulative abuse that distributes risk across many individually acceptable calls.",
        ],
        code: `budgets:
  store_path: .latch/budgets.json
  lock_timeout: 2s
  rules:
    - id: workspace-read-burst
      match:
        tool: filesystem.read
        action: read
        path: "./**"
      max_actions: 100
      window: 5m`,
        language: "yaml",
      },
      {
        id: "atomicity",
        title: "Fail-closed accounting",
        bullets: [
          "Every allowed proxied call reserves capacity immediately before forwarding.",
          "All matching budgets are evaluated atomically.",
          "The last available unit is valid; the next call is denied until expiry.",
          "Corrupt, oversized, inaccessible, or lock-contended state fails closed.",
          "Policy changes create a new counter scope.",
        ],
      },
      {
        id: "inspect",
        title: "Inspect current capacity",
        code: `latch identities list --config latch.yaml
latch budgets status --config latch.yaml --agent desktop-agent
latch budgets status --config latch.yaml --agent desktop-agent --json`,
      },
    ],
  },
  {
    slug: "approvals-audit",
    group: "Operate",
    title: "Approvals & audit",
    summary:
      "Issue exact, expiring grants and retain a redacted record of every enforcement outcome.",
    readingTime: "9 min",
    sections: [
      {
        id: "approvals",
        title: "Exact-action grants",
        paragraphs: [
          "A durable approval is scoped to one exact normalized action, one canonical agent identity, and one policy digest. It never creates a wildcard or tool-wide bypass.",
        ],
        code: `latch check \\
  --config latch.yaml \\
  --agent desktop-agent \\
  --tool shell.exec \\
  --arg "command=npm test" \\
  --interactive \\
  --approver local:alice \\
  --approval-ttl 30m`,
      },
      {
        id: "lifecycle",
        title: "Manage the lifecycle",
        code: `latch approvals list
latch approvals list --json
latch approvals revoke \\
  --id <grant-id> \\
  --approver local:alice \\
  --reason "task complete"
latch approvals prune`,
        note: "A policy change, action mismatch, identity mismatch, expiry, or revocation invalidates the grant. Blocks and hard-deny signals are never overridden.",
      },
      {
        id: "audit",
        title: "Redacted JSONL audit",
        paragraphs: [
          "Every CLI evaluation and proxied tool decision writes an event to .latch/audit.jsonl by default. Secret-bearing keys and inline bearer or token values are redacted before serialization.",
        ],
        code: `latch logs --config latch.yaml --tail 20`,
      },
      {
        id: "storage",
        title: "Durable local state",
        bullets: [
          "Approval and budget stores use operating-system locks.",
          "Updates use crash-safe atomic replacement.",
          "State paths resolve relative to the policy file.",
          "Audit, approval, and budget failures deny protected actions.",
        ],
      },
    ],
  },
  {
    slug: "deployment",
    group: "Operate",
    title: "Deployment",
    summary:
      "Ship static binaries, native packages, or a hardened multi-architecture container with verifiable provenance.",
    readingTime: "11 min",
    sections: [
      {
        id: "artifacts",
        title: "Choose an artifact",
        bullets: [
          "Static archives for Linux, macOS, and Windows on AMD64 and ARM64",
          "Debian, RPM, and APK packages",
          "Multi-architecture non-root OCI image",
          "Go source installation",
        ],
      },
      {
        id: "verify",
        title: "Verify provenance",
        paragraphs: [
          "Installers verify downloaded archives against the release checksum list. Release archives include Syft SBOMs and GitHub artifact attestations.",
        ],
        code: `sha256sum --check checksums.txt

gh attestation verify latch_0.1.1_linux_amd64.tar.gz \\
  --repo princebabou/Latch`,
      },
      {
        id: "container",
        title: "Run the container",
        code: `docker run --rm \\
  -v latch-state:/var/lib/latch \\
  -v "$PWD/latch.yaml:/etc/latch/latch.yaml:ro" \\
  ghcr.io/princebabou/latch:0.1.1 \\
  doctor --agent desktop-agent`,
        note: "An MCP stdio proxy must spawn the real server in the same container. An unrelated network sidecar cannot intercept another container’s stdin/stdout.",
      },
      {
        id: "hardening",
        title: "Production hardening",
        bullets: [
          "Mount policy files read-only and state directories read/write.",
          "Run as a dedicated non-root identity.",
          "Keep the executable, policy, launcher config, identity binding, and approval store in one integrity boundary.",
          "Persist approval and budget state across restarts.",
          "Reserve stdout for MCP protocol data and forward stderr to operator logs.",
          "Run latch doctor during deployment validation.",
        ],
      },
      {
        id: "environment",
        title: "Operational environment",
        code: `LATCH_CONFIG=/etc/latch/latch.yaml
LATCH_AGENT=desktop-agent
LATCH_AUDIT_PATH=/var/lib/latch/audit.jsonl
LATCH_APPROVAL_STORE=/var/lib/latch/approvals.json
LATCH_BUDGET_STORE=/var/lib/latch/budgets.json
LATCH_AUDIT_TERMINAL=true`,
      },
    ],
  },
  {
    slug: "cli-reference",
    group: "Reference",
    title: "CLI reference",
    summary:
      "A practical map of Latch’s evaluator, proxy, policy, identity, budget, approval, diagnostic, and integration commands.",
    readingTime: "7 min",
    sections: [
      {
        id: "commands",
        title: "Commands",
        code: `latch init [--profile balanced|strict|developer]
latch doctor [--config policy.yaml] [--agent <trusted-id>] [-- server]
latch integrations mcp --client <claude|cursor|vscode|generic> -- server
latch integrations mcp-http --client <claude-code|cursor|vscode|generic>
latch integrations http [--url http://127.0.0.1:7072]
latch check --tool <name> [--arg key=value] [options]
latch proxy [options] -- <mcp-server-command> [args...]
latch proxy-http --upstream <https://server/mcp> [options]
latch proxy-api --upstream <https://api.example> [options]
latch serve [--listen 127.0.0.1:7070] [options]
latch run --input <actions.jsonl> [--config policy.yaml]
latch policies list|validate [--config policy.yaml]
latch identities list [--config policy.yaml] [--json]
latch budgets status --agent <trusted-id> [--json]
latch approvals list|revoke|prune [options]
latch logs [--config policy.yaml] [--tail 20]
latch version [--json]`,
      },
      {
        id: "check",
        title: "check",
        paragraphs: [
          "Evaluate one normalized action without executing it. Repeat --arg key=value for tool arguments. Use --json for machine-readable Action and Assessment output, or --interactive to resolve an approval-required decision locally.",
        ],
        code: `latch check \\
  --config latch.yaml \\
  --agent desktop-agent \\
  --tool deployment.apply \\
  --action write \\
  --arg environment=production \\
  --json`,
      },
      {
        id: "proxy",
        title: "proxy",
        paragraphs: [
          "Launch and supervise an MCP stdio server. Options include --config, --agent, --cwd, and --max-message-bytes. Arguments after -- belong to the real server.",
        ],
      },
      {
        id: "exit-codes",
        title: "Exit behavior",
        bullets: [
          "0 — success or ALLOW",
          "1 — operational or configuration failure",
          "3 — BLOCK or unresolved REQUIRE_APPROVAL",
          "64 — invalid command usage",
          "130 — interrupted proxy",
        ],
      },
    ],
  },
  {
    slug: "security-model",
    group: "Reference",
    title: "Security model",
    summary:
      "What Latch guarantees today, how it fails, and where the current trust boundary ends.",
    readingTime: "12 min",
    sections: [
      {
        id: "guarantees",
        title: "Enforcement guarantees",
        bullets: [
          "Matching block rules override approvals and allows.",
          "Hard-deny risk classes resist ordinary policy allows.",
          "Verified capability ceilings cannot be expanded by policy or approval.",
          "Exhausted budgets cannot be bypassed by approvals or unsafe overrides.",
          "Approvals bind to the exact action, identity, expiry, and policy digest.",
          "Parser ambiguity and critical state failures fail closed.",
        ],
      },
      {
        id: "structured-analysis",
        title: "Structured risk analysis",
        paragraphs: [
          "Latch separates executable syntax from quoted data and comments across common POSIX shell, PowerShell/CMD, PostgreSQL, MySQL, SQLite, and SQL Server forms.",
          "It parses HTTP destinations, decoded keys, headers, payloads, TLS settings, and network classes. Filesystem analysis recognizes common credential and sensitive-system paths.",
        ],
        note: "The parsers never execute, interpolate, resolve DNS, or connect to a database.",
      },
      {
        id: "failure",
        title: "Fail-closed conditions",
        bullets: [
          "Malformed, unsupported, or excessively nested syntax",
          "Invalid or oversized MCP and HTTP messages",
          "Invalid upstream protocol output",
          "Forbidden upstream redirects or unavailable upstream services",
          "Approval-store read or write failure",
          "Budget corruption, contention, or inaccessible state",
          "Required audit write failure",
        ],
      },
      {
        id: "current-boundary",
        title: "Current boundary",
        paragraphs: [
          "The current release secures MCP stdio, MCP Streamable HTTP, and generic HTTP APIs, with operator-bound identities, capability ceilings, cumulative budgets, exact local approvals, and structured shell, HTTP, SQL, and filesystem inspection.",
          "OpenAI-compatible tool calling, LangChain/LangGraph, shell execution, CI/CD, cryptographic remote-agent identity, and centrally authenticated remote approvers remain follow-up priorities.",
        ],
      },
      {
        id: "report",
        title: "Report a vulnerability",
        paragraphs: [
          "Use the repository’s private vulnerability reporting channel for suspected security issues. Do not open a public issue containing exploit details or sensitive evidence.",
        ],
        code: `https://github.com/princebabou/Latch/security`,
      },
    ],
  },
];

export const docBySlug = new Map(docs.map((doc) => [doc.slug, doc]));

export const groupedDocs = docs.reduce<Record<string, DocPage[]>>(
  (groups, doc) => {
    groups[doc.group] ??= [];
    groups[doc.group].push(doc);
    return groups;
  },
  {},
);

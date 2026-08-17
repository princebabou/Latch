import Link from "next/link";
import { DecisionPlayground } from "./components/DecisionPlayground";
import { LatchMark, SiteHeader } from "./components/SiteHeader";

const githubUrl = "https://github.com/princebabou/Latch";

const guarantees = [
  {
    title: "Policy before execution",
    copy: "Every normalized action is evaluated before it reaches the real tool, file, shell, API, database, or MCP server. There is no path around the boundary.",
  },
  {
    title: "Deterministic risk",
    copy: "Structured shell, PowerShell, HTTP, and SQL analysis produces concrete, repeatable signals — destructive behavior, credential movement, privilege escalation, persistence — not an opaque model judgment.",
  },
  {
    title: "Explainable outcomes",
    copy: "Every allow, block, and approval records its source, matched policy, identity, budget state, and reasons. You can always answer why.",
  },
];

const integrationGroups: [string, [string, string][]][] = [
  [
    "Protocol gateways",
    [
      ["MCP stdio proxy", "Transparent bidirectional enforcement for any MCP server"],
      ["MCP Streamable HTTP", "Enforced streaming and SSE transport protection"],
      ["HTTP/API gateway", "Reverse gateway with semantic body inspection and separated credentials"],
    ],
  ],
  [
    "Framework adapters",
    [
      ["Anthropic tool use", "Guarded Claude Messages API tool_use blocks in Go, Python, and TypeScript"],
      ["OpenAI-compatible tools", "Responses and Chat Completions function guards in Go, Python, and TypeScript"],
      ["LangChain & LangGraph", "Native middleware and whole-batch protected ToolNodes"],
      ["Local processes", "Fingerprint-bound argv and shell execution with replay protection"],
      ["Fail-closed SDKs", "Official Go, Python, and TypeScript clients with guarded execution"],
    ],
  ],
  [
    "Client launchers",
    [
      ["Claude Desktop", "Native protected launcher configuration"],
      ["Cursor", "Project-level MCP protection"],
      ["VS Code", "Generated stdio server registration"],
    ],
  ],
  [
    "Pipeline & tooling",
    [
      ["Remote approvals", "Out-of-band webhook alerts and a separate-token HTTP grant endpoint"],
      ["CI/CD gate", "Native GitHub Action with summaries and typed outputs"],
      ["Conformance suite", "Versioned cross-adapter security corpus certification"],
      ["Policy Lab", "Actual-engine policy simulation, comparison, and weakening detection"],
    ],
  ],
];

const failClosedCases = [
  "Malformed or excessively nested command syntax",
  "Invalid or oversized MCP and HTTP messages",
  "Invalid upstream protocol output",
  "Approval-store read or write failure",
  "Budget corruption or contention",
  "Required audit write failure",
];

export default function Home() {
  return (
    <main>
      <SiteHeader />

      <section className="hero shell" id="overview">
        <div className="hero-copy">
          <span className="kicker">Open-source security enforcement for AI agents</span>
          <h1>
            Let agents move. <em>Keep control.</em>
          </h1>
          <p className="hero-lede">
            Latch sits between AI agents and their tools, enforcing policy,
            budgets, approvals, and auditability before actions execute — a
            control plane at the point where intent becomes impact.
          </p>
          <div className="hero-actions">
            <Link className="button button-primary" href="/docs/quickstart">
              Get started
            </Link>
            <Link className="text-link" href="/playground">
              Try the playground →
            </Link>
          </div>
          <div className="hero-meta">
            <span>v0.2 preview</span>
            <span>Apache-2.0</span>
            <span>Fail closed by design</span>
            <span>Go · Python · TypeScript</span>
          </div>
        </div>

        <div className="terminal hero-terminal" aria-label="Example Latch decision">
          <div className="terminal-bar">
            <span>latch — decision</span>
            <span>exit 3</span>
          </div>
          <pre>
            <code>
              <span className="t-prompt">$</span> latch check --tool filesystem.read \{"\n"}
              {"    "}--arg path=~/.ssh/id_rsa{"\n"}
              {"\n"}
              <span className="t-key">  decision   </span>
              <span className="t-block">BLOCK</span>
              {"\n"}
              <span className="t-key">  source     </span>policy_block · block-private-keys{"\n"}
              <span className="t-key">  risk       </span>100/100 · critical · hard deny{"\n"}
              <span className="t-key">  signals    </span>credential material, sensitive path{"\n"}
              {"\n"}
              <span className="t-dim">
                {"  "}Private key material is a hard-deny class.{"\n"}
                {"  "}Ordinary allow rules cannot override it.
              </span>
              {"\n\n"}
              <span className="t-prompt">$</span> latch check --tool filesystem.read \{"\n"}
              {"    "}--arg path=./README.md{"\n"}
              {"\n"}
              <span className="t-key">  decision   </span>
              <span className="t-allow">ALLOW</span>
              {"\n"}
              <span className="t-key">  source     </span>policy_allow · workspace-read
            </code>
          </pre>
        </div>
      </section>

      <hr className="section-rule" />

      <section className="section shell">
        <div className="section-head">
          <span className="kicker">The control boundary</span>
          <h2>One enforcement path. No silent bypass.</h2>
          <p>
            Latch is deliberately not a prompt scanner. It protects the point
            where an agent&rsquo;s intent becomes an action with real-world
            consequences — and it returns an explainable verdict every time.
          </p>
        </div>
        <div className="pipeline" aria-label="Latch enforcement pipeline">
          <div className="pipeline-node">
            <strong>Agent call</strong>
            <small>Normalized tool intent</small>
          </div>
          <div className="pipeline-arrow" />
          <div className="pipeline-core">
            <div className="pipeline-core-label">Latch enforcement core</div>
            <div className="pipeline-stages">
              <div>
                <strong>Normalize</strong>
                <small>Protocol-neutral action</small>
              </div>
              <div>
                <strong>Policy</strong>
                <small>Deny-overrides YAML rules</small>
              </div>
              <div>
                <strong>Risk</strong>
                <small>Deterministic shell, PowerShell, HTTP, SQL analysis</small>
              </div>
              <div>
                <strong>Identity</strong>
                <small>Verified agents and capability ceilings</small>
              </div>
              <div>
                <strong>Budget</strong>
                <small>Durable rolling action limits</small>
              </div>
            </div>
          </div>
          <div className="pipeline-arrow" />
          <div className="pipeline-node">
            <strong>Verdict</strong>
            <small>Allow · Block · Require approval</small>
          </div>
        </div>
        <div className="pipeline-tail">
          <span>Allowed actions execute</span>
          <span>Everything lands in a redacted audit trail</span>
        </div>
      </section>

      <section className="section shell" id="why-latch">
        <div className="section-head">
          <span className="kicker">Why Latch</span>
          <h2>Security that explains itself.</h2>
        </div>
        <div className="guarantees">
          {guarantees.map((item) => (
            <article key={item.title}>
              <h3>{item.title}</h3>
              <p>{item.copy}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="playground-band">
        <div className="shell">
          <div className="section-head">
            <span className="kicker">Decision playground</span>
            <h2>See the boundary think.</h2>
            <p>
              Explore representative actions here, then run the local Policy
              Lab to edit real YAML and inspect the exact decision path.
            </p>
          </div>
          <DecisionPlayground compact />
          <div className="band-link">
            <Link className="text-link" href="/playground">
              Open the full playground →
            </Link>
          </div>
        </div>
      </section>

      <section className="section shell quickstart" id="quickstart">
        <div className="quickstart-copy">
          <span className="kicker">Quickstart</span>
          <h2>Protect your first MCP server in minutes.</h2>
          <ol className="quickstart-steps">
            <li>
              <span>01</span>
              <div>
                <strong>Create a policy</strong>
                <p>Start from a balanced, strict, or developer profile.</p>
              </div>
            </li>
            <li>
              <span>02</span>
              <div>
                <strong>Run diagnostics</strong>
                <p>Validate identity, state, policy, and server readiness.</p>
              </div>
            </li>
            <li>
              <span>03</span>
              <div>
                <strong>Generate the integration</strong>
                <p>Emit native configuration for your MCP client.</p>
              </div>
            </li>
          </ol>
          <Link className="text-link" href="/docs/quickstart">
            Follow the complete quickstart →
          </Link>
        </div>
        <div className="terminal">
          <div className="terminal-bar">
            <span>terminal — quickstart</span>
          </div>
          <pre>
            <code>
              <span className="t-comment"># 1 — create policy</span>
              {"\n"}
              <span className="t-prompt">$</span> latch init --profile balanced --agent desktop-agent
              {"\n\n"}
              <span className="t-comment"># 2 — verify deployment</span>
              {"\n"}
              <span className="t-prompt">$</span> latch doctor --config latch.yaml \{"\n"}
              {"    "}--agent desktop-agent -- my-mcp-server
              {"\n\n"}
              <span className="t-comment"># 3 — wire the client</span>
              {"\n"}
              <span className="t-prompt">$</span> latch integrations mcp --client vscode \{"\n"}
              {"    "}--name protected-server --config latch.yaml \{"\n"}
              {"    "}--agent desktop-agent -- my-mcp-server
            </code>
          </pre>
          <div className="terminal-ready">✓ ready — Latch can enforce this integration</div>
        </div>
      </section>

      <section className="section shell" id="integrations">
        <div className="section-head">
          <span className="kicker">Integrations</span>
          <h2>One boundary. Every entry point.</h2>
          <p>
            Generate native client configurations, or use Latch as a
            protocol-neutral gate in the wrappers and pipelines you already
            run.
          </p>
        </div>
        <div className="integration-groups">
          {integrationGroups.map(([group, items]) => (
            <div className="integration-group" key={group}>
              <h3>{group}</h3>
              <div className="integration-items">
                {items.map(([name, detail]) => (
                  <div key={name}>
                    <strong>{name}</strong>
                    <p>{detail}</p>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="failclosed-band">
        <div className="shell failclosed-grid">
          <div>
            <span className="kicker">Fail closed by design</span>
            <h2>
              Security failures become <em>denials</em> — not invisible gaps.
            </h2>
            <p>
              When Latch cannot evaluate an action safely, the action does not
              run. Ambiguity is treated as risk, and every denial is recorded
              with its reason.
            </p>
            <Link className="text-link" href="/docs/security-model">
              Read the security model →
            </Link>
          </div>
          <ul className="failclosed-list">
            {failClosedCases.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </section>

      <section className="final-cta shell">
        <span className="kicker">The agent can move. The boundary holds.</span>
        <h2>
          Put Latch between <em>intent</em> and <em>impact</em>.
        </h2>
        <div className="final-cta-actions">
          <Link className="button button-primary" href="/docs/quickstart">
            Get started
          </Link>
          <a className="button button-secondary" href={githubUrl}>
            View on GitHub ↗
          </a>
        </div>
      </section>

      <footer className="site-footer">
        <div className="shell footer-grid">
          <div>
            <Link className="brand footer-brand" href="/">
              <LatchMark size={20} />
              <strong>Latch</strong>
            </Link>
            <p>Open-source security enforcement for AI agent actions.</p>
            <small className="footer-note">v0.2 preview · Apache-2.0</small>
          </div>
          <div>
            <strong>Explore</strong>
            <Link href="/playground">Playground</Link>
            <Link href="/docs">Documentation</Link>
            <a href={`${githubUrl}/releases`}>Releases</a>
          </div>
          <div>
            <strong>Project</strong>
            <a href={githubUrl}>GitHub</a>
            <a href={`${githubUrl}/blob/main/SECURITY.md`}>Security</a>
            <a href={`${githubUrl}/blob/main/CONTRIBUTING.md`}>Contributing</a>
          </div>
          <div>
            <strong>Principles</strong>
            <small>Enforce before execution.</small>
            <small>Explain every decision.</small>
            <small>Fail closed, always.</small>
          </div>
        </div>
      </footer>
    </main>
  );
}

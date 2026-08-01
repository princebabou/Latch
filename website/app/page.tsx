import Link from "next/link";
import { DecisionPlayground } from "./components/DecisionPlayground";
import { SiteHeader } from "./components/SiteHeader";

const githubUrl = "https://github.com/princebabou/Latch";

const guarantees = [
  {
    index: "01",
    title: "Policy before execution",
    copy: "Every normalized action is evaluated before it reaches the real tool, file, shell, API, database, or MCP server.",
  },
  {
    index: "02",
    title: "Deterministic risk",
    copy: "Structured shell, HTTP, SQL, and filesystem analysis produces concrete signals—not an opaque model judgment.",
  },
  {
    index: "03",
    title: "Explainable outcomes",
    copy: "Every allow, block, and approval decision records its source, matched policy, identity, budget state, and reasons.",
  },
];

const integrations = [
  ["MCP stdio", "Transparent bidirectional enforcement proxy"],
  ["HTTP / API", "Drop-in reverse enforcement gateway"],
  ["MCP HTTP", "Streamable HTTP and SSE protection"],
  ["Claude Desktop", "Native launcher configuration"],
  ["Cursor", "Project-level MCP protection"],
  ["VS Code", "Generated stdio server registration"],
  ["CI / CD", "Exit-code friendly policy gates"],
  ["Any tool wrapper", "Protocol-neutral check contract"],
];

export default function Home() {
  return (
    <main>
      <SiteHeader />

      <section className="hero section-shell" id="overview">
        <div className="hero-copy">
          <div className="eyebrow">
            <span className="live-dot" />
            Open-source security enforcement for AI agents
          </div>
          <h1>
            Let agents move.
            <span> Keep control.</span>
          </h1>
          <p className="hero-lede">
            Latch sits between AI agents and their tools—enforcing policy,
            budgets, approvals, and auditability before actions execute.
          </p>
          <div className="hero-actions">
            <Link className="button button-primary" href="/playground">
              Try the playground <span aria-hidden="true">↗</span>
            </Link>
            <Link className="button button-secondary" href="/docs">
              Read the docs <span aria-hidden="true">→</span>
            </Link>
          </div>
          <div className="hero-proof" aria-label="Project status">
            <span>v0.1.1</span>
            <span>Apache-2.0</span>
            <span>Fail closed</span>
          </div>
        </div>

        <div className="decision-stage" aria-label="Example Latch decision">
          <div className="trace trace-one" />
          <div className="trace trace-two" />
          <div className="decision-console">
            <div className="console-topline">
              <span>
                <i className="live-dot" /> Live decision
              </span>
              <code>req_8f2c</code>
            </div>
            <div className="console-route">
              <span>AGENT</span>
              <b />
              <span>LATCH</span>
              <b />
              <span>TOOL</span>
            </div>
            <div className="console-fields">
              <div>
                <span>action</span>
                <code>filesystem.delete</code>
              </div>
              <div>
                <span>target</span>
                <code>/prod/snapshots</code>
              </div>
              <div>
                <span>identity</span>
                <code>deploy-agent · verified</code>
              </div>
              <div>
                <span>risk</span>
                <strong className="risk-critical">CRITICAL · 76</strong>
              </div>
            </div>
            <div className="console-verdict">
              <div>
                <span>DECISION</span>
                <strong>REQUIRE APPROVAL</strong>
              </div>
              <span className="verdict-key">03</span>
            </div>
            <div className="console-policy">
              <span>Matched policy</span>
              <code>protect-production</code>
            </div>
          </div>
          <div className="stage-caption">
            <span>DENY OVERRIDES</span>
            <span>POLICY DIGEST 7A91</span>
          </div>
        </div>
      </section>

      <section className="trust-ledger" aria-label="Latch capabilities">
        <div className="section-shell trust-ledger-inner">
          {[
            ["01", "Policy as code"],
            ["02", "Verified identities"],
            ["03", "Rolling budgets"],
            ["04", "Exact approvals"],
            ["05", "Redacted audit"],
          ].map(([number, label]) => (
            <div key={number}>
              <span>{number}</span>
              <strong>{label}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="section-shell section-block">
        <div className="section-heading">
          <div>
            <span className="kicker">THE CONTROL BOUNDARY</span>
            <h2>One enforcement path. No silent bypass.</h2>
          </div>
          <p>
            Latch is deliberately not a prompt scanner. It protects the point
            where intent becomes an action with real-world consequences.
          </p>
        </div>
        <div className="pipeline" aria-label="Latch enforcement pipeline">
          <div className="pipeline-node pipeline-source">
            <span>01</span>
            <strong>Agent call</strong>
            <small>Tool intent</small>
          </div>
          <div className="pipeline-connector" />
          <div className="pipeline-core">
            <div className="core-label">LATCH / ENFORCEMENT CORE</div>
            <div>
              <span>Normalize</span>
              <span>Policy</span>
              <span>Risk</span>
              <span>Identity</span>
              <span>Budget</span>
            </div>
          </div>
          <div className="pipeline-connector" />
          <div className="pipeline-node pipeline-decision">
            <span>03</span>
            <strong>Verdict</strong>
            <small>Allow · Block · Approve</small>
          </div>
          <div className="pipeline-tail">
            <div>Tool execution</div>
            <div>Redacted audit</div>
          </div>
        </div>
      </section>

      <section className="section-shell section-block" id="why-latch">
        <div className="section-heading compact-heading">
          <div>
            <span className="kicker">SECURITY THAT EXPLAINS ITSELF</span>
            <h2>Control without slowing agents to a crawl.</h2>
          </div>
        </div>
        <div className="guarantee-grid">
          {guarantees.map((item) => (
            <article className="guarantee-card" key={item.index}>
              <span>{item.index}</span>
              <h3>{item.title}</h3>
              <p>{item.copy}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="playground-band">
        <div className="section-shell">
          <div className="section-heading">
            <div>
              <span className="kicker">DECISION PLAYGROUND</span>
              <h2>See the boundary think.</h2>
            </div>
            <p>
              Explore representative actions and inspect the exact signal,
              policy, and enforcement path behind each result.
            </p>
          </div>
          <DecisionPlayground compact />
          <div className="band-link">
            <Link href="/playground">
              Open the full playground <span aria-hidden="true">→</span>
            </Link>
          </div>
        </div>
      </section>

      <section className="section-shell section-block quickstart" id="quickstart">
        <div className="quickstart-copy">
          <span className="kicker">THREE COMMANDS TO A BOUNDARY</span>
          <h2>Protect your first MCP server in minutes.</h2>
          <ol>
            <li>
              <span>1</span>
              <div>
                <strong>Create a policy</strong>
                <p>Start from a balanced, strict, or developer profile.</p>
              </div>
            </li>
            <li>
              <span>2</span>
              <div>
                <strong>Run diagnostics</strong>
                <p>Validate identity, state, policy, and server readiness.</p>
              </div>
            </li>
            <li>
              <span>3</span>
              <div>
                <strong>Generate the integration</strong>
                <p>Emit native configuration for your MCP client.</p>
              </div>
            </li>
          </ol>
          <Link className="text-link" href="/docs/quickstart">
            Follow the complete quickstart <span aria-hidden="true">→</span>
          </Link>
        </div>
        <div className="terminal-card">
          <div className="terminal-header">
            <span>TERMINAL / QUICKSTART</span>
            <span>● ● ●</span>
          </div>
          <pre>
            <code>
              <span className="terminal-comment"># 01 · create policy</span>
              {"\n"}
              <span className="terminal-prompt">$</span> latch init --profile
              balanced --agent desktop-agent{"\n\n"}
              <span className="terminal-comment"># 02 · verify deployment</span>
              {"\n"}
              <span className="terminal-prompt">$</span> latch doctor --config
              latch.yaml --agent desktop-agent -- my-mcp-server{"\n\n"}
              <span className="terminal-comment"># 03 · wire the client</span>
              {"\n"}
              <span className="terminal-prompt">$</span> latch integrations mcp
              --client vscode --name protected-server --config latch.yaml
              --agent desktop-agent -- my-mcp-server
            </code>
          </pre>
          <div className="terminal-ready">✓ READY: Latch can enforce this integration.</div>
        </div>
      </section>

      <section className="section-shell section-block" id="integrations">
        <div className="section-heading">
          <div>
            <span className="kicker">MEET DEVELOPERS WHERE THEY WORK</span>
            <h2>One boundary. Multiple entry points.</h2>
          </div>
          <p>
            Generate native client configurations or use Latch as a
            protocol-neutral gate in the wrappers and pipelines you already run.
          </p>
        </div>
        <div className="integration-grid">
          {integrations.map(([name, detail], index) => (
            <article key={name}>
              <span>{String(index + 1).padStart(2, "0")}</span>
              <h3>{name}</h3>
              <p>{detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="section-shell section-block security-callout">
        <div className="security-seal" aria-hidden="true">
          <span>L</span>
        </div>
        <div>
          <span className="kicker">FAIL CLOSED BY DESIGN</span>
          <h2>Security failures become denials—not invisible gaps.</h2>
          <p>
            Invalid protocol output, oversized messages, ambiguous parsers,
            approval-store errors, budget contention, and audit failures stop
            protected actions before execution.
          </p>
        </div>
        <Link className="button button-secondary" href="/docs/security-model">
          Read the security model
        </Link>
      </section>

      <section className="final-cta">
        <div className="section-shell">
          <span className="kicker">THE AGENT CAN MOVE. THE BOUNDARY HOLDS.</span>
          <h2>Put Latch between intent and impact.</h2>
          <div>
            <Link className="button button-primary" href="/docs/quickstart">
              Get started <span aria-hidden="true">→</span>
            </Link>
            <a className="button button-secondary" href={githubUrl}>
              View on GitHub <span aria-hidden="true">↗</span>
            </a>
          </div>
        </div>
      </section>

      <footer className="site-footer">
        <div className="section-shell footer-grid">
          <div>
            <Link className="brand footer-brand" href="/">
              <span className="brand-mark" aria-hidden="true">
                L
              </span>
              <strong>LATCH</strong>
            </Link>
            <p>Open-source security enforcement for AI agent actions.</p>
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
          <div className="footer-status">
            <span>
              <i className="live-dot" /> Project operational
            </span>
            <small>v0.1.1 · Apache-2.0</small>
          </div>
        </div>
      </footer>
    </main>
  );
}

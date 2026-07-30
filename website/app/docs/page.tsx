import type { Metadata } from "next";
import Link from "next/link";
import { DocsShell } from "./DocsShell";
import { groupedDocs } from "./docs-data";

export const metadata: Metadata = {
  title: "Documentation",
  description:
    "Install, configure, integrate, operate, and understand Latch’s AI-agent security boundary.",
};

export default function DocsIndex() {
  return (
    <DocsShell>
      <div className="docs-index-hero">
        <span className="kicker">LATCH DOCUMENTATION / v0.1.1</span>
        <h1>Build a boundary you can explain.</h1>
        <p>
          Everything you need to install Latch, protect an MCP server, write
          policy, bind identities, operate approvals and budgets, and understand
          the security model.
        </p>
        <div>
          <Link className="button button-primary" href="/docs/quickstart">
            Start the quickstart <span aria-hidden="true">→</span>
          </Link>
          <Link className="button button-secondary" href="/playground">
            Explore decisions
          </Link>
        </div>
      </div>
      <div className="docs-groups">
        {Object.entries(groupedDocs).map(([group, pages], groupIndex) => (
          <section key={group}>
            <div className="docs-group-title">
              <span>{String(groupIndex + 1).padStart(2, "0")}</span>
              <h2>{group}</h2>
            </div>
            <div className="docs-card-grid">
              {pages.map((page) => (
                <Link href={`/docs/${page.slug}`} key={page.slug}>
                  <span>{page.readingTime}</span>
                  <h3>{page.title}</h3>
                  <p>{page.summary}</p>
                  <strong aria-hidden="true">→</strong>
                </Link>
              ))}
            </div>
          </section>
        ))}
      </div>
    </DocsShell>
  );
}

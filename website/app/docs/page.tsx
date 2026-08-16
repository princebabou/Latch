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
        <span className="kicker">Latch documentation · v0.2 preview</span>
        <h1>
          Build a boundary you can <em>explain</em>.
        </h1>
        <p>
          Everything you need to install Latch, protect an MCP server, write
          policy, bind identities, gate CI/CD, operate approvals and budgets,
          simulate policy changes, certify integrations, and understand the
          security model.
        </p>
        <div className="docs-index-actions">
          <Link className="button button-primary" href="/docs/quickstart">
            Start the quickstart
          </Link>
          <Link className="button button-secondary" href="/playground">
            Explore decisions
          </Link>
        </div>
      </div>
      <div className="docs-groups">
        {Object.entries(groupedDocs).map(([group, pages]) => (
          <section key={group}>
            <div className="docs-group-title">
              <h2>{group}</h2>
            </div>
            <div className="docs-card-grid">
              {pages.map((page) => (
                <Link href={`/docs/${page.slug}`} key={page.slug}>
                  <h3>{page.title}</h3>
                  <p>{page.summary}</p>
                  <span>{page.readingTime} read</span>
                </Link>
              ))}
            </div>
          </section>
        ))}
      </div>
    </DocsShell>
  );
}

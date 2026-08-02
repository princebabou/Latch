import Link from "next/link";
import type { ReactNode } from "react";
import { SiteHeader } from "../components/SiteHeader";
import { groupedDocs } from "./docs-data";

export function DocsShell({
  children,
  activeSlug,
}: {
  children: ReactNode;
  activeSlug?: string;
}) {
  return (
    <main>
      <SiteHeader />
      <div className="docs-layout section-shell">
        <aside className="docs-sidebar">
          <Link className="docs-home-link" href="/docs">
            <span>DOCS</span>
            <strong>Latch manual</strong>
          </Link>
          <nav aria-label="Documentation navigation">
            {Object.entries(groupedDocs).map(([group, pages]) => (
              <div key={group}>
                <span>{group}</span>
                {pages.map((page) => (
                  <Link
                    className={activeSlug === page.slug ? "active" : ""}
                    href={`/docs/${page.slug}`}
                    key={page.slug}
                  >
                    {page.title}
                  </Link>
                ))}
              </div>
            ))}
          </nav>
          <div className="docs-sidebar-status">
            <i className="live-dot" />
            <div>
              <strong>Docs for v0.2</strong>
              <span>Preview</span>
            </div>
          </div>
        </aside>
        <div className="docs-content">{children}</div>
      </div>
    </main>
  );
}

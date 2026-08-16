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
      <div className="docs-layout shell">
        <aside className="docs-sidebar">
          <Link className="docs-home-link" href="/docs">
            Latch manual
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
          <div className="docs-sidebar-status">Docs for v0.2 preview</div>
        </aside>
        <div className="docs-content">{children}</div>
      </div>
    </main>
  );
}

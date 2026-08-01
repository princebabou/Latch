import Link from "next/link";

const githubUrl = "https://github.com/princebabou/Latch";

export function SiteHeader() {
  return (
    <header className="site-header">
      <div className="section-shell header-inner">
        <Link className="brand" href="/" aria-label="Latch home">
          <span className="brand-mark" aria-hidden="true">
            L
          </span>
          <strong>LATCH</strong>
          <small>SECURITY LAYER</small>
        </Link>
        <nav aria-label="Primary navigation">
          <Link href="/#why-latch">Why Latch</Link>
          <Link href="/playground">Playground</Link>
          <Link href="/docs">Docs</Link>
          <Link href="/#integrations">Integrations</Link>
        </nav>
        <a className="github-link" href={githubUrl}>
          <span>GitHub</span>
          <strong>↗</strong>
        </a>
      </div>
    </header>
  );
}

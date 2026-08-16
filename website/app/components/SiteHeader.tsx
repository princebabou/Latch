import Link from "next/link";

const githubUrl = "https://github.com/princebabou/Latch";

export function LatchMark({ size = 22 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 22 22"
      fill="none"
      aria-hidden="true"
    >
      <rect
        x="6.3"
        y="3.8"
        width="12.4"
        height="14.4"
        rx="2"
        stroke="currentColor"
        strokeWidth="1.6"
      />
      <path
        d="M1.5 11h10.5"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
      <circle cx="12.5" cy="11" r="1.7" fill="currentColor" />
    </svg>
  );
}

export function SiteHeader() {
  return (
    <header className="site-header">
      <div className="shell header-inner">
        <Link className="brand" href="/" aria-label="Latch home">
          <LatchMark />
          <strong>Latch</strong>
        </Link>
        <nav aria-label="Primary navigation">
          <Link href="/#why-latch">Why Latch</Link>
          <Link href="/playground">Playground</Link>
          <Link href="/docs">Docs</Link>
          <Link href="/#integrations">Integrations</Link>
        </nav>
        <a className="header-github" href={githubUrl}>
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
          </svg>
          <span>GitHub</span>
        </a>
      </div>
    </header>
  );
}

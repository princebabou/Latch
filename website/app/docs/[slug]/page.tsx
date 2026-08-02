import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { CopyButton } from "../../components/CopyButton";
import { DocsShell } from "../DocsShell";
import { docBySlug, docs } from "../docs-data";

type Params = Promise<{ slug: string }>;

export function generateStaticParams() {
  return docs.map((doc) => ({ slug: doc.slug }));
}

export async function generateMetadata({
  params,
}: {
  params: Params;
}): Promise<Metadata> {
  const { slug } = await params;
  const doc = docBySlug.get(slug);
  return doc
    ? { title: doc.title, description: doc.summary }
    : { title: "Documentation" };
}

export default async function DocArticle({ params }: { params: Params }) {
  const { slug } = await params;
  const doc = docBySlug.get(slug);
  if (!doc) notFound();

  const currentIndex = docs.findIndex((item) => item.slug === slug);
  const previous = currentIndex > 0 ? docs[currentIndex - 1] : null;
  const next = currentIndex < docs.length - 1 ? docs[currentIndex + 1] : null;

  return (
    <DocsShell activeSlug={slug}>
      <article className="doc-article">
        <header>
          <div className="doc-breadcrumb">
            <Link href="/docs">Docs</Link>
            <span>/</span>
            <span>{doc.group}</span>
          </div>
          <h1>{doc.title}</h1>
          <p>{doc.summary}</p>
          <div className="doc-meta">
            <span>v0.2 preview</span>
            <span>{doc.readingTime} read</span>
            <span>Source grounded</span>
          </div>
        </header>

        <nav className="on-this-page" aria-label="On this page">
          <span>ON THIS PAGE</span>
          {doc.sections.map((section) => (
            <a href={`#${section.id}`} key={section.id}>
              {section.title}
            </a>
          ))}
        </nav>

        <div className="doc-sections">
          {doc.sections.map((section, index) => (
            <section id={section.id} key={section.id}>
              <span className="section-number">
                {String(index + 1).padStart(2, "0")}
              </span>
              <h2>{section.title}</h2>
              {section.paragraphs?.map((paragraph) => (
                <p key={paragraph}>{paragraph}</p>
              ))}
              {section.bullets && (
                <ul>
                  {section.bullets.map((bullet) => (
                    <li key={bullet}>{bullet}</li>
                  ))}
                </ul>
              )}
              {section.code && (
                <div className="doc-code">
                  <div>
                    <span>{section.language ?? "shell"}</span>
                    <CopyButton value={section.code} />
                  </div>
                  <pre>
                    <code>{section.code}</code>
                  </pre>
                </div>
              )}
              {section.note && (
                <aside className="doc-note">
                  <span>BOUNDARY NOTE</span>
                  <p>{section.note}</p>
                </aside>
              )}
            </section>
          ))}
        </div>

        <nav className="doc-pagination" aria-label="Documentation pagination">
          {previous ? (
            <Link href={`/docs/${previous.slug}`}>
              <span>← Previous</span>
              <strong>{previous.title}</strong>
            </Link>
          ) : (
            <span />
          )}
          {next ? (
            <Link href={`/docs/${next.slug}`}>
              <span>Next →</span>
              <strong>{next.title}</strong>
            </Link>
          ) : (
            <span />
          )}
        </nav>
      </article>
    </DocsShell>
  );
}

import type { Metadata } from "next";
import Link from "next/link";
import { DecisionPlayground } from "../components/DecisionPlayground";
import { SiteHeader } from "../components/SiteHeader";

export const metadata: Metadata = {
  title: "Decision playground",
  description:
    "Explore representative Latch decisions and inspect their policy, risk, identity, and enforcement paths.",
};

export default function PlaygroundPage() {
  return (
    <main>
      <SiteHeader />
      <section className="interior-hero section-shell">
        <div>
          <span className="kicker">INTERACTIVE / LOCAL SIMULATION</span>
          <h1>Decision playground</h1>
        </div>
        <p>
          Explore representative normalized actions. This visualization mirrors
          Latch’s deterministic decision contract; it does not execute tools or
          send data anywhere.
        </p>
      </section>
      <section className="section-shell playground-page">
        <DecisionPlayground />
        <aside className="playground-note">
          <span>SIMULATION BOUNDARY</span>
          <p>
            Production decisions come from your YAML policy, verified launcher
            identity, durable budget state, approvals, and the exact normalized
            action. Use <code>latch check --json</code> to inspect a real local
            assessment.
          </p>
          <Link href="/docs/policies">
            Learn how decisions are made <span aria-hidden="true">→</span>
          </Link>
        </aside>
      </section>
    </main>
  );
}

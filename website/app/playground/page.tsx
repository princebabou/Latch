import type { Metadata } from "next";
import Link from "next/link";
import { DecisionPlayground } from "../components/DecisionPlayground";
import { SiteHeader } from "../components/SiteHeader";

export const metadata: Metadata = {
  title: "Decision playground",
  description:
    "Explore representative Latch decisions, then run the actual local Policy Lab against editable YAML and action JSON.",
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
          Explore representative normalized actions here, then run the actual
          local Policy Lab against your own editable YAML and action JSON.
        </p>
      </section>
      <section className="section-shell playground-page">
        <DecisionPlayground />
        <aside className="playground-note">
          <span>ACTUAL LOCAL ENGINE</span>
          <p>
            Launch the loopback-only workbench with{" "}
            <code>latch playground --config latch.yaml --open</code>. It compares
            policy edits, exposes the complete evidence trail, and never saves,
            forwards, or executes an action.
          </p>
          <Link href="/docs/policy-playground">
            Open the Policy Lab guide <span aria-hidden="true">→</span>
          </Link>
        </aside>
      </section>
    </main>
  );
}

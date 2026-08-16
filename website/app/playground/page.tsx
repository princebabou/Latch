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
      <section className="interior-hero">
        <div className="shell">
          <span className="kicker">Interactive · local simulation</span>
          <h1>Decision playground</h1>
          <p className="interior-lede">
            Explore representative normalized actions here, then run the actual
            local Policy Lab against your own editable YAML and action JSON.
          </p>
        </div>
      </section>
      <section className="shell playground-page">
        <DecisionPlayground />
        <aside className="playground-note">
          <span>Actual local engine</span>
          <p>
            Launch the loopback-only workbench with{" "}
            <code>latch playground --config latch.yaml --open</code>. It
            compares policy edits, exposes the complete evidence trail, and
            never saves, forwards, or executes an action.
          </p>
          <Link className="text-link" href="/docs/policy-playground">
            Open the Policy Lab guide →
          </Link>
        </aside>
      </section>
    </main>
  );
}

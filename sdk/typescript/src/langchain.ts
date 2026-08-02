import { LatchError } from "./errors.js";
import type { OpenAIDecisionClient, OpenAIDecideOptions } from "./openai.js";

export interface LangChainToolCall {
  id?: string;
  name: string;
  args: Record<string, unknown>;
  type?: string;
}

export interface ProtectedLangChainToolCall extends LangChainToolCall {
  id: string;
}

export interface LangChainToolGuardOptions {
  maxCalls?: number;
  maxArgumentBytes?: number;
  replayCapacity?: number;
}

export interface LangChainToolCallRequest {
  toolCall: LangChainToolCall;
  tool?: unknown;
  runtime?: { signal?: AbortSignal };
}

export type LangChainToolCallHandler = (request: any) => any;
export type LangChainToolCallHook = (
  request: LangChainToolCallRequest,
  handler: LangChainToolCallHandler,
) => Promise<any>;

export interface LangChainMiddlewareLike {
  readonly name: string;
  readonly wrapToolCall?: LangChainToolCallHook;
  [key: string]: unknown;
}

export interface LangGraphToolNodeLike {
  invoke(input: unknown, config?: unknown): Promise<unknown>;
  [key: string]: unknown;
}

export class LangChainAdapterError extends LatchError {
  override readonly name: string = "LangChainAdapterError";
}

export class LangChainDependencyError extends LangChainAdapterError {
  override readonly name = "LangChainDependencyError";
}

export class LangChainProtocolError extends LangChainAdapterError {
  override readonly name = "LangChainProtocolError";
}

export class LangChainReplayError extends LangChainAdapterError {
  override readonly name = "LangChainReplayError";
  constructor(readonly callId: string) {
    super(`LangChain tool call ${JSON.stringify(callId)} was duplicated or replayed; execution stopped`);
  }
}

export class LangChainNotAllowedError extends LangChainAdapterError {
  override readonly name = "LangChainNotAllowedError";
  constructor(
    readonly callId: string,
    readonly tool: string,
    readonly decision: { readonly decision: string; readonly allowed: boolean },
  ) {
    super(`Latch decision for LangChain tool ${JSON.stringify(tool)} call ${JSON.stringify(callId)} is ${decision.decision}; execution stopped`);
  }
}

export class UnknownLangChainToolError extends LangChainAdapterError {
  override readonly name = "UnknownLangChainToolError";
  constructor(readonly callId: string, readonly tool: string) {
    super(`LangChain tool ${JSON.stringify(tool)} for call ${JSON.stringify(callId)} is not registered; batch not executed`);
  }
}

/** Shared guard for LangChain middleware and full-batch LangGraph execution. */
export class LangChainToolGuard {
  readonly #client: OpenAIDecisionClient;
  readonly #maxCalls: number;
  readonly #maxArgumentBytes: number;
  readonly #replayCapacity: number;
  readonly #replayed = new Set<string>();
  readonly #replayOrder: string[] = [];

  constructor(client: OpenAIDecisionClient, options: LangChainToolGuardOptions = {}) {
    if (client === null || typeof client !== "object" || typeof client.decide !== "function") {
      throw new TypeError("client must provide decide(action)");
    }
    this.#maxCalls = boundedInteger(options.maxCalls ?? 128, 1, 1024, "maxCalls");
    this.#maxArgumentBytes = boundedInteger(options.maxArgumentBytes ?? 1 << 20, 1, 16 << 20, "maxArgumentBytes");
    this.#replayCapacity = boundedInteger(options.replayCapacity ?? 10_000, 128, 1_000_000, "replayCapacity");
    if (this.#replayCapacity < this.#maxCalls) throw new TypeError("replayCapacity cannot be smaller than maxCalls");
    this.#client = client;
  }

  async protect(
    rawCalls: readonly unknown[],
    surface: "langchain_agent" | "langgraph_tool_node",
    options: OpenAIDecideOptions & { allowedTools?: ReadonlySet<string> } = {},
  ): Promise<readonly ProtectedLangChainToolCall[]> {
    if (!Array.isArray(rawCalls)) throw new LangChainProtocolError("tool calls must be an array");
    if (rawCalls.length > this.#maxCalls) throw new LangChainProtocolError(`tool call batch exceeds ${this.#maxCalls} calls`);
    const calls = rawCalls.map((call) => normalizeCall(call, this.#maxArgumentBytes));
    const seen = new Set<string>();
    for (const call of calls) {
      if (seen.has(call.id)) throw new LangChainReplayError(call.id);
      seen.add(call.id);
      if (options.allowedTools !== undefined && !options.allowedTools.has(call.name)) {
        throw new UnknownLangChainToolError(call.id, call.name);
      }
    }
    for (const call of calls) {
      const decision = await this.#client.decide({
        tool: call.name,
        arguments: call.args,
        metadata: {
          protocol: "langchain",
          surface,
          tool_call_id: call.id,
          tool_call_kind: "function",
        },
      }, { signal: options.signal });
      if (!decision.allowed) throw new LangChainNotAllowedError(call.id, call.name, decision);
    }
    this.#reserve(calls);
    return calls;
  }

  #reserve(calls: readonly ProtectedLangChainToolCall[]): void {
    for (const call of calls) if (this.#replayed.has(call.id)) throw new LangChainReplayError(call.id);
    for (const call of calls) {
      this.#replayed.add(call.id);
      this.#replayOrder.push(call.id);
    }
    while (this.#replayOrder.length > this.#replayCapacity) {
      this.#replayed.delete(this.#replayOrder.shift()!);
    }
  }
}

/** Create the native wrapToolCall hook for an existing createMiddleware call. */
export function createLatchToolCallHook(
  client: OpenAIDecisionClient,
  options: LangChainToolGuardOptions = {},
): LangChainToolCallHook {
  const guard = new LangChainToolGuard(client, options);
  return async (request, handler) => {
    if (request === null || typeof request !== "object" || request.tool == null) {
      throw new LangChainProtocolError("tool call has no resolved LangChain tool");
    }
    await guard.protect([request.toolCall], "langchain_agent", { signal: request.runtime?.signal });
    return await handler(request);
  };
}

/** Load LangChain lazily and return middleware ready for createAgent. */
export async function createLatchAgentMiddleware(
  client: OpenAIDecisionClient,
  options: LangChainToolGuardOptions = {},
): Promise<LangChainMiddlewareLike> {
  const langchain = await optionalImport("langchain", 'Install the optional peer dependency with: npm install langchain');
  const createMiddleware = langchain.createMiddleware;
  if (typeof createMiddleware !== "function") throw new LangChainDependencyError("installed langchain does not export createMiddleware");
  return createMiddleware({
    name: "LatchSecurityMiddleware",
    wrapToolCall: createLatchToolCallHook(client, options),
  }) as LangChainMiddlewareLike;
}

/**
 * Build a real LangGraph ToolNode whose invoke boundary preflights every tool
 * call before LangGraph begins its parallel execution.
 */
export async function createLatchToolNode(
  tools: readonly unknown[],
  client: OpenAIDecisionClient,
  nodeOptions: Readonly<Record<string, unknown>> = {},
  guardOptions: LangChainToolGuardOptions = {},
): Promise<any> {
  const prebuilt = await optionalImport(
    "@langchain/langgraph/prebuilt",
    "Install the optional peer dependency with: npm install @langchain/langgraph",
  );
  const ToolNode = prebuilt.ToolNode;
  if (typeof ToolNode !== "function") throw new LangChainDependencyError("installed @langchain/langgraph does not export ToolNode");
  const allowedTools = new Set(tools.map(toolName));
  const guard = new LangChainToolGuard(client, guardOptions);
  const messagesKey = typeof nodeOptions.messagesKey === "string" ? nodeOptions.messagesKey : "messages";

  class ProtectedToolNode extends (ToolNode as new (tools_: readonly unknown[], options_: Readonly<Record<string, unknown>>) => LangGraphToolNodeLike) {
    constructor() {
      super(tools, nodeOptions);
    }

    override async invoke(input: unknown, config?: unknown): Promise<unknown> {
      const calls = extractToolCalls(input, messagesKey);
      const signal = recordOrUndefined(config)?.signal;
      await guard.protect(calls, "langgraph_tool_node", {
        allowedTools,
        signal: signal instanceof AbortSignal ? signal : undefined,
      });
      return await super.invoke(input, config);
    }

    batch(): never {
      throw new LangChainProtocolError("protected ToolNode batch() is disabled; invoke the node through LangGraph");
    }

    stream(): never {
      throw new LangChainProtocolError("protected ToolNode stream() is disabled; stream the compiled LangGraph instead");
    }
  }

  return new ProtectedToolNode();
}

function extractToolCalls(input: unknown, messagesKey: string): readonly unknown[] {
  if (Array.isArray(input)) {
    if (input.length === 0) return [];
    if (input.every(isDirectToolCall)) return input;
    return callsFromMessage(input.at(-1));
  }
  const state = record(input, "LangGraph state");
  const messages = state[messagesKey];
  if (!Array.isArray(messages) || messages.length === 0) {
    throw new LangChainProtocolError(`LangGraph state must contain a non-empty ${JSON.stringify(messagesKey)} array`);
  }
  return callsFromMessage(messages.at(-1));
}

function callsFromMessage(messageValue: unknown): readonly unknown[] {
  const message = record(messageValue, "last LangGraph message");
  const calls = message.tool_calls ?? message.toolCalls;
  if (calls === undefined) return [];
  if (!Array.isArray(calls)) throw new LangChainProtocolError("the last message tool calls must be an array");
  return calls;
}

function isDirectToolCall(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const call = value as Record<string, unknown>;
  return "id" in call && "name" in call && "args" in call;
}

function normalizeCall(value: unknown, maxArgumentBytes: number): ProtectedLangChainToolCall {
  const call = record(value, "tool call");
  const id = callId(call.id);
  const name = toolCallName(call.name);
  const args = normalizeArguments(call.args, id);
  const encoded = JSON.stringify(args);
  if (byteLength(encoded) > maxArgumentBytes) {
    throw new LangChainProtocolError(`arguments for call ${JSON.stringify(id)} exceed ${maxArgumentBytes} bytes`);
  }
  return { id, name, args, type: typeof call.type === "string" ? call.type : undefined };
}

function normalizeArguments(value: unknown, callIdValue: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new LangChainProtocolError(`arguments for call ${JSON.stringify(callIdValue)} must be an object`);
  }
  return normalizeJSON(value, new WeakSet<object>()) as Record<string, unknown>;
}

function normalizeJSON(value: unknown, ancestors: WeakSet<object>): unknown {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") { validateUnicode(value, "JSON string"); return value; }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new LangChainProtocolError("JSON number is outside the finite range");
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new LangChainProtocolError("JSON integer is outside the interoperable safe range");
    }
    return value;
  }
  if (typeof value !== "object" || value === undefined) {
    throw new LangChainProtocolError(`unsupported JSON argument type ${typeof value}`);
  }
  if (ancestors.has(value)) throw new LangChainProtocolError("JSON arguments cannot contain cycles");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const output: unknown[] = [];
      for (let index = 0; index < value.length; index++) {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor)) {
          throw new LangChainProtocolError("JSON arrays cannot be sparse or contain accessors");
        }
        output.push(normalizeJSON(descriptor.value, ancestors));
      }
      for (const key of Reflect.ownKeys(descriptors)) {
        if (typeof key === "symbol") throw new LangChainProtocolError("JSON arrays cannot contain symbol properties");
        if (key !== "length" && !/^(0|[1-9]\d*)$/.test(key)) {
          throw new LangChainProtocolError("JSON arrays cannot contain named properties");
        }
      }
      return output;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new LangChainProtocolError("JSON objects must be plain objects");
    }
    const output: Record<string, unknown> = {};
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") throw new LangChainProtocolError("JSON objects cannot contain symbol keys");
      validateUnicode(key, "JSON object key");
      const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
      if (!("value" in descriptor) || !descriptor.enumerable) {
        throw new LangChainProtocolError("JSON objects cannot contain accessors or hidden properties");
      }
      Object.defineProperty(output, key, {
        value: normalizeJSON(descriptor.value, ancestors), enumerable: true, writable: true, configurable: true,
      });
    }
    return output;
  } finally {
    ancestors.delete(value);
  }
}

function callId(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 256) {
    throw new LangChainProtocolError("tool call id must be 1-256 visible ASCII characters");
  }
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (code < 0x21 || code > 0x7e) throw new LangChainProtocolError("tool call id must be 1-256 visible ASCII characters");
  }
  return value;
}

function toolCallName(value: unknown): string {
  if (typeof value !== "string" || value.trim() === "") throw new LangChainProtocolError("tool name must be a non-empty string");
  validateUnicode(value, "tool name");
  if (byteLength(value) > 256) throw new LangChainProtocolError("tool name cannot exceed 256 UTF-8 bytes");
  return value;
}

function toolName(value: unknown): string {
  if ((typeof value !== "object" || value === null) && typeof value !== "function") {
    throw new TypeError("LangGraph tools must expose a name");
  }
  return toolCallName((value as { name?: unknown }).name);
}

function validateUnicode(value: string, name: string): void {
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (code === 0xfffd || (character.length === 1 && code >= 0xd800 && code <= 0xdfff)) {
      throw new LangChainProtocolError(`${name} cannot contain replacement or unpaired-surrogate characters`);
    }
  }
}

function boundedInteger(value: number, minimum: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new LangChainProtocolError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function recordOrUndefined(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

async function optionalImport(specifier: string, installation: string): Promise<Record<string, unknown>> {
  try {
    return await import(specifier) as Record<string, unknown>;
  } catch (error) {
    throw new LangChainDependencyError(`${installation}. ${errorMessage(error)}`);
  }
}

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

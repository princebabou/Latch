import { LatchError } from "./errors.js";

export interface AnthropicAction {
  tool: string;
  arguments?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface AnthropicDecideOptions {
  signal?: AbortSignal;
}

export interface AnthropicDecision {
  readonly decision: string;
  readonly allowed: boolean;
}

export type AnthropicToolHandler = (input: Record<string, unknown>) => unknown | Promise<unknown>;

export interface AnthropicDecisionClient {
  decide(action: AnthropicAction, options?: AnthropicDecideOptions): Promise<AnthropicDecision>;
}

export interface AnthropicToolAdapterOptions {
  maxCalls?: number;
  maxInputBytes?: number;
  maxOutputBytes?: number;
  replayCapacity?: number;
}

export interface AnthropicToolResult {
  type: "tool_result";
  tool_use_id: string;
  content: string;
}

export class AnthropicToolError extends LatchError {
  override readonly name: string = "AnthropicToolError";
}

export class AnthropicToolProtocolError extends AnthropicToolError {
  override readonly name = "AnthropicToolProtocolError";
}

export class UnknownAnthropicToolError extends AnthropicToolError {
  override readonly name = "UnknownAnthropicToolError";
  constructor(readonly toolUseId: string, readonly tool: string) {
    super(`Anthropic tool ${JSON.stringify(tool)} for tool_use ${JSON.stringify(toolUseId)} has no registered handler; batch not executed`);
  }
}

export class AnthropicToolReplayError extends AnthropicToolError {
  override readonly name = "AnthropicToolReplayError";
  constructor(readonly toolUseId: string) {
    super(`Anthropic tool_use ${JSON.stringify(toolUseId)} was duplicated or replayed; batch not executed`);
  }
}

export class AnthropicToolNotAllowedError extends AnthropicToolError {
  override readonly name = "AnthropicToolNotAllowedError";
  constructor(readonly toolUseId: string, readonly tool: string, readonly decision: AnthropicDecision) {
    super(`Latch decision for Anthropic tool ${JSON.stringify(tool)} tool_use ${JSON.stringify(toolUseId)} is ${decision.decision}; batch not executed`);
  }
}

export class AnthropicToolExecutionError extends AnthropicToolError {
  override readonly name = "AnthropicToolExecutionError";
  constructor(readonly toolUseId: string, readonly tool: string, options: { cause: unknown }) {
    super(`execute Anthropic tool ${JSON.stringify(tool)} tool_use ${JSON.stringify(toolUseId)}: ${errorMessage(options.cause)}`, options);
  }
}

interface ToolUse {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

/** Protects tool_use blocks from a completed Anthropic Messages API response without an Anthropic SDK dependency. */
export class AnthropicToolAdapter {
  readonly #client: AnthropicDecisionClient;
  readonly #handlers: ReadonlyMap<string, AnthropicToolHandler>;
  readonly #maxCalls: number;
  readonly #maxInputBytes: number;
  readonly #maxOutputBytes: number;
  readonly #replayCapacity: number;
  readonly #replayed = new Set<string>();
  readonly #replayOrder: string[] = [];

  constructor(
    client: AnthropicDecisionClient,
    handlers: Readonly<Record<string, AnthropicToolHandler>>,
    options: AnthropicToolAdapterOptions = {},
  ) {
    if (client === null || typeof client !== "object" || typeof client.decide !== "function") {
      throw new TypeError("client must provide decide(action)");
    }
    this.#maxCalls = boundedInteger(options.maxCalls ?? 128, 1, 1024, "maxCalls");
    this.#maxInputBytes = boundedInteger(options.maxInputBytes ?? 1 << 20, 1, 16 << 20, "maxInputBytes");
    this.#maxOutputBytes = boundedInteger(options.maxOutputBytes ?? 4 << 20, 1, 64 << 20, "maxOutputBytes");
    this.#replayCapacity = boundedInteger(options.replayCapacity ?? 10_000, 128, 1_000_000, "replayCapacity");
    if (this.#replayCapacity < this.#maxCalls) {
      throw new TypeError("replayCapacity cannot be smaller than maxCalls");
    }
    const copied = new Map<string, AnthropicToolHandler>();
    for (const [name, handler] of Object.entries(handlers)) {
      validateName(name);
      if (typeof handler !== "function") throw new TypeError(`handler ${JSON.stringify(name)} must be a function`);
      copied.set(name, handler);
    }
    this.#client = client;
    this.#handlers = copied;
  }

  async executeMessage(message: unknown, options: AnthropicDecideOptions = {}): Promise<AnthropicToolResult[]> {
    const root = record(message, "message");
    if (root.type !== undefined && root.type !== "message") {
      throw new AnthropicToolProtocolError("payload is not a Messages API message");
    }
    if (root.role !== undefined && root.role !== "assistant") {
      throw new AnthropicToolProtocolError("only assistant messages carry tool_use blocks");
    }
    const calls: ToolUse[] = [];
    for (const blockValue of array(root.content, "message.content")) {
      const block = record(blockValue, "message.content[]");
      if (block.type !== "tool_use") continue;
      calls.push(this.#parseToolUse(block.id, block.name, block.input));
    }
    const outputs = await this.#execute(calls, options);
    return calls.map((call, index) => ({ type: "tool_result", tool_use_id: call.id, content: outputs[index]! }));
  }

  #parseToolUse(idValue: unknown, nameValue: unknown, inputValue: unknown): ToolUse {
    const id = validateToolUseId(idValue);
    const name = validateName(nameValue);
    const input = record(inputValue, `input for tool_use ${JSON.stringify(id)}`);
    let serialized: string;
    try {
      serialized = JSON.stringify(input);
    } catch (error) {
      throw new AnthropicToolProtocolError(`input for tool_use ${JSON.stringify(id)} is invalid: ${errorMessage(error)}`);
    }
    if (serialized === undefined) {
      throw new AnthropicToolProtocolError(`input for tool_use ${JSON.stringify(id)} is not serializable`);
    }
    if (byteLength(serialized) > this.#maxInputBytes) {
      throw new AnthropicToolProtocolError(`input for tool_use ${JSON.stringify(id)} exceeds ${this.#maxInputBytes} bytes`);
    }
    validateJSON(input);
    return { id, name, input };
  }

  async #execute(calls: readonly ToolUse[], options: AnthropicDecideOptions): Promise<string[]> {
    if (calls.length > this.#maxCalls) {
      throw new AnthropicToolProtocolError(`tool_use batch exceeds ${this.#maxCalls} blocks`);
    }
    const seen = new Set<string>();
    for (const call of calls) {
      if (seen.has(call.id)) throw new AnthropicToolReplayError(call.id);
      seen.add(call.id);
      if (!this.#handlers.has(call.name)) throw new UnknownAnthropicToolError(call.id, call.name);
    }
    for (const call of calls) {
      const decision = await this.#client.decide({
        tool: call.name,
        arguments: call.input,
        metadata: {
          protocol: "anthropic-messages",
          surface: "messages",
          tool_use_id: call.id,
          tool_call_kind: "tool_use",
        },
      }, options);
      if (!decision.allowed) throw new AnthropicToolNotAllowedError(call.id, call.name, decision);
    }
    this.#reserve(calls);
    const outputs: string[] = [];
    for (const call of calls) {
      try {
        const value = await this.#handlers.get(call.name)!(call.input);
        outputs.push(encodeOutput(value, this.#maxOutputBytes));
      } catch (error) {
        if (error instanceof AnthropicToolExecutionError) throw error;
        throw new AnthropicToolExecutionError(call.id, call.name, { cause: error });
      }
    }
    return outputs;
  }

  #reserve(calls: readonly ToolUse[]): void {
    for (const call of calls) if (this.#replayed.has(call.id)) throw new AnthropicToolReplayError(call.id);
    for (const call of calls) {
      this.#replayed.add(call.id);
      this.#replayOrder.push(call.id);
    }
    while (this.#replayOrder.length > this.#replayCapacity) {
      this.#replayed.delete(this.#replayOrder.shift()!);
    }
  }
}

function validateToolUseId(value: unknown): string {
  if (typeof value !== "string" || byteLength(value) < 1 || byteLength(value) > 256) {
    throw new AnthropicToolProtocolError("tool_use id must be 1-256 UTF-8 bytes");
  }
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (code < 0x21 || code > 0x7e) throw new AnthropicToolProtocolError("tool_use id must contain visible ASCII only");
  }
  return value;
}

function validateName(value: unknown): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new AnthropicToolProtocolError("tool name must be 1-256 UTF-8 bytes");
  }
  validateUnicode(value, "tool name");
  if (byteLength(value) > 256) throw new AnthropicToolProtocolError("tool name must be 1-256 UTF-8 bytes");
  return value;
}

function validateJSON(value: unknown): void {
  if (typeof value === "string") {
    validateUnicode(value, "JSON string");
  } else if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new AnthropicToolProtocolError("JSON number is outside the finite range");
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new AnthropicToolProtocolError("JSON integer is outside the interoperable safe range");
    }
  } else if (Array.isArray(value)) {
    for (const item of value) validateJSON(item);
  } else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      validateUnicode(key, "JSON object key");
      validateJSON(item);
    }
  } else if (typeof value === "bigint" || typeof value === "function" || typeof value === "symbol" || typeof value === "undefined") {
    throw new AnthropicToolProtocolError(`unsupported JSON value of type ${typeof value}`);
  }
}

function encodeOutput(value: unknown, limit: number): string {
  let output: string;
  if (typeof value === "string") output = value;
  else {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError("tool output is not JSON serializable");
    output = encoded;
  }
  if (byteLength(output) > limit) throw new TypeError(`tool output exceeds ${limit} bytes`);
  return output;
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
    throw new AnthropicToolProtocolError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function array(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) throw new AnthropicToolProtocolError(`${name} must be an array`);
  return value;
}

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

function validateUnicode(value: string, name: string): void {
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (code === 0xfffd || (character.length === 1 && code >= 0xd800 && code <= 0xdfff)) {
      throw new AnthropicToolProtocolError(`${name} cannot contain replacement or unpaired-surrogate characters`);
    }
  }
}

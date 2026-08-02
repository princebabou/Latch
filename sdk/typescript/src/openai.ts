import { LatchError } from "./errors.js";

export interface OpenAIAction {
  tool: string;
  arguments?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface OpenAIDecideOptions {
  signal?: AbortSignal;
}

export interface OpenAIDecision {
  readonly decision: string;
  readonly allowed: boolean;
}

export type OpenAIToolHandler = (arguments_: Record<string, unknown>) => unknown | Promise<unknown>;

export interface OpenAIDecisionClient {
  decide(action: OpenAIAction, options?: OpenAIDecideOptions): Promise<OpenAIDecision>;
}

export interface OpenAIToolAdapterOptions {
  maxCalls?: number;
  maxArgumentBytes?: number;
  maxOutputBytes?: number;
  replayCapacity?: number;
}

export interface OpenAIChatExecutionOptions extends OpenAIDecideOptions {
  choiceIndex?: number;
}

export interface OpenAIResponseToolOutput {
  type: "function_call_output";
  call_id: string;
  output: string;
}

export interface OpenAIChatToolMessage {
  role: "tool";
  tool_call_id: string;
  content: string;
}

export class OpenAIToolError extends LatchError {
  override readonly name: string = "OpenAIToolError";
}

export class OpenAIToolProtocolError extends OpenAIToolError {
  override readonly name = "OpenAIToolProtocolError";
}

export class UnknownOpenAIToolError extends OpenAIToolError {
  override readonly name = "UnknownOpenAIToolError";
  constructor(readonly callId: string, readonly tool: string) {
    super(`OpenAI tool ${JSON.stringify(tool)} for call ${JSON.stringify(callId)} has no registered handler; batch not executed`);
  }
}

export class OpenAIToolReplayError extends OpenAIToolError {
  override readonly name = "OpenAIToolReplayError";
  constructor(readonly callId: string) {
    super(`OpenAI tool call ${JSON.stringify(callId)} was duplicated or replayed; batch not executed`);
  }
}

export class OpenAIToolNotAllowedError extends OpenAIToolError {
  override readonly name = "OpenAIToolNotAllowedError";
  constructor(readonly callId: string, readonly tool: string, readonly decision: OpenAIDecision) {
    super(`Latch decision for OpenAI tool ${JSON.stringify(tool)} call ${JSON.stringify(callId)} is ${decision.decision}; batch not executed`);
  }
}

export class OpenAIToolExecutionError extends OpenAIToolError {
  override readonly name = "OpenAIToolExecutionError";
  constructor(readonly callId: string, readonly tool: string, options: { cause: unknown }) {
    super(`execute OpenAI tool ${JSON.stringify(tool)} call ${JSON.stringify(callId)}: ${errorMessage(options.cause)}`, options);
  }
}

interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
  surface: "responses" | "chat_completions";
}

/** Protects completed OpenAI-compatible function calls without an OpenAI SDK dependency. */
export class OpenAIToolAdapter {
  readonly #client: OpenAIDecisionClient;
  readonly #handlers: ReadonlyMap<string, OpenAIToolHandler>;
  readonly #maxCalls: number;
  readonly #maxArgumentBytes: number;
  readonly #maxOutputBytes: number;
  readonly #replayCapacity: number;
  readonly #replayed = new Set<string>();
  readonly #replayOrder: string[] = [];

  constructor(
    client: OpenAIDecisionClient,
    handlers: Readonly<Record<string, OpenAIToolHandler>>,
    options: OpenAIToolAdapterOptions = {},
  ) {
    if (client === null || typeof client !== "object" || typeof client.decide !== "function") {
      throw new TypeError("client must provide decide(action)");
    }
    this.#maxCalls = boundedInteger(options.maxCalls ?? 128, 1, 1024, "maxCalls");
    this.#maxArgumentBytes = boundedInteger(options.maxArgumentBytes ?? 1 << 20, 1, 16 << 20, "maxArgumentBytes");
    this.#maxOutputBytes = boundedInteger(options.maxOutputBytes ?? 4 << 20, 1, 64 << 20, "maxOutputBytes");
    this.#replayCapacity = boundedInteger(options.replayCapacity ?? 10_000, 128, 1_000_000, "replayCapacity");
    if (this.#replayCapacity < this.#maxCalls) {
      throw new TypeError("replayCapacity cannot be smaller than maxCalls");
    }
    const copied = new Map<string, OpenAIToolHandler>();
    for (const [name, handler] of Object.entries(handlers)) {
      validateName(name);
      if (typeof handler !== "function") throw new TypeError(`handler ${JSON.stringify(name)} must be a function`);
      copied.set(name, handler);
    }
    this.#client = client;
    this.#handlers = copied;
  }

  async executeResponses(response: unknown, options: OpenAIDecideOptions = {}): Promise<OpenAIResponseToolOutput[]> {
    const root = record(response, "response");
    if (root.status !== undefined && root.status !== "completed") {
      throw new OpenAIToolProtocolError("Responses payload must be completed before execution");
    }
    const calls: ToolCall[] = [];
    for (const itemValue of array(root.output, "response.output")) {
      const item = record(itemValue, "response.output[]");
      if (item.type === "custom_tool_call") {
        throw new OpenAIToolProtocolError("custom tools are not supported by this function-tool adapter");
      }
      if (item.type !== "function_call") continue;
      if (item.status !== undefined && item.status !== "completed") {
        throw new OpenAIToolProtocolError("function call must be completed before execution");
      }
      calls.push(this.#parseCall(item.call_id, item.name, item.arguments, "responses"));
    }
    const outputs = await this.#execute(calls, options);
    return calls.map((call, index) => ({ type: "function_call_output", call_id: call.id, output: outputs[index]! }));
  }

  async executeChatCompletion(completion: unknown, options: OpenAIChatExecutionOptions = {}): Promise<OpenAIChatToolMessage[]> {
    const root = record(completion, "completion");
    const choiceIndex = boundedInteger(options.choiceIndex ?? 0, 0, Number.MAX_SAFE_INTEGER, "choiceIndex");
    let selected: Record<string, unknown> | undefined;
    for (const choiceValue of array(root.choices, "completion.choices")) {
      const choice = record(choiceValue, "completion.choices[]");
      if (choice.index === choiceIndex) {
        selected = choice;
        break;
      }
    }
    if (selected === undefined) {
      throw new OpenAIToolProtocolError(`Chat Completions choice ${choiceIndex} was not found`);
    }
    const message = record(selected.message, "choice.message");
    const calls: ToolCall[] = [];
    if (message.tool_calls !== undefined) {
      for (const itemValue of array(message.tool_calls, "choice.message.tool_calls")) {
        const item = record(itemValue, "choice.message.tool_calls[]");
        if (item.type !== "function") {
          throw new OpenAIToolProtocolError(`unsupported Chat Completions tool call type ${JSON.stringify(item.type)}`);
        }
        const function_ = record(item.function, "tool_call.function");
        calls.push(this.#parseCall(item.id, function_.name, function_.arguments, "chat_completions"));
      }
    }
    const outputs = await this.#execute(calls, { signal: options.signal });
    return calls.map((call, index) => ({ role: "tool", tool_call_id: call.id, content: outputs[index]! }));
  }

  #parseCall(idValue: unknown, nameValue: unknown, rawValue: unknown, surface: ToolCall["surface"]): ToolCall {
    const id = validateCallId(idValue);
    const name = validateName(nameValue);
    if (typeof rawValue !== "string") {
      throw new OpenAIToolProtocolError(`arguments for call ${JSON.stringify(id)} must be a JSON string`);
    }
    validateUnicode(rawValue, "arguments JSON");
    if (byteLength(rawValue) > this.#maxArgumentBytes) {
      throw new OpenAIToolProtocolError(`arguments for call ${JSON.stringify(id)} exceed ${this.#maxArgumentBytes} bytes`);
    }
    let arguments_: unknown;
    try {
      arguments_ = new StrictJSONParser(rawValue).parse();
    } catch (error) {
      throw new OpenAIToolProtocolError(`arguments for call ${JSON.stringify(id)} are invalid: ${errorMessage(error)}`);
    }
    return { id, name, arguments: record(arguments_, `arguments for call ${JSON.stringify(id)}`), surface };
  }

  async #execute(calls: readonly ToolCall[], options: OpenAIDecideOptions): Promise<string[]> {
    if (calls.length > this.#maxCalls) {
      throw new OpenAIToolProtocolError(`tool call batch exceeds ${this.#maxCalls} calls`);
    }
    const seen = new Set<string>();
    for (const call of calls) {
      if (seen.has(call.id)) throw new OpenAIToolReplayError(call.id);
      seen.add(call.id);
      if (!this.#handlers.has(call.name)) throw new UnknownOpenAIToolError(call.id, call.name);
    }
    for (const call of calls) {
      const decision = await this.#client.decide({
        tool: call.name,
        arguments: call.arguments,
        metadata: {
          protocol: "openai-compatible",
          surface: call.surface,
          tool_call_id: call.id,
          tool_call_kind: "function",
        },
      }, options);
      if (!decision.allowed) throw new OpenAIToolNotAllowedError(call.id, call.name, decision);
    }
    this.#reserve(calls);
    const outputs: string[] = [];
    for (const call of calls) {
      try {
        const value = await this.#handlers.get(call.name)!(call.arguments);
        outputs.push(encodeOutput(value, this.#maxOutputBytes));
      } catch (error) {
        if (error instanceof OpenAIToolExecutionError) throw error;
        throw new OpenAIToolExecutionError(call.id, call.name, { cause: error });
      }
    }
    return outputs;
  }

  #reserve(calls: readonly ToolCall[]): void {
    for (const call of calls) if (this.#replayed.has(call.id)) throw new OpenAIToolReplayError(call.id);
    for (const call of calls) {
      this.#replayed.add(call.id);
      this.#replayOrder.push(call.id);
    }
    while (this.#replayOrder.length > this.#replayCapacity) {
      this.#replayed.delete(this.#replayOrder.shift()!);
    }
  }
}

function validateCallId(value: unknown): string {
  if (typeof value !== "string" || byteLength(value) < 1 || byteLength(value) > 256) {
    throw new OpenAIToolProtocolError("tool call id must be 1-256 UTF-8 bytes");
  }
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (code < 0x21 || code > 0x7e) throw new OpenAIToolProtocolError("tool call id must contain visible ASCII only");
  }
  return value;
}

function validateName(value: unknown): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new OpenAIToolProtocolError("function name must be 1-256 UTF-8 bytes");
  }
  validateUnicode(value, "function name");
  if (byteLength(value) > 256) throw new OpenAIToolProtocolError("function name must be 1-256 UTF-8 bytes");
  return value;
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
    throw new OpenAIToolProtocolError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function array(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) throw new OpenAIToolProtocolError(`${name} must be an array`);
  return value;
}

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

/** Minimal strict parser used to reject duplicate keys before policy evaluation. */
class StrictJSONParser {
  #offset = 0;
  #depth = 0;
  constructor(private readonly source: string) {}

  parse(): unknown {
    const value = this.#value();
    this.#space();
    if (this.#offset !== this.source.length) throw new SyntaxError("trailing JSON data");
    return value;
  }

  #value(): unknown {
    this.#space();
    if (++this.#depth > 128) throw new SyntaxError("JSON nesting exceeds 128 levels");
    try {
      const character = this.source[this.#offset];
      if (character === "{") return this.#object();
      if (character === "[") return this.#array();
      if (character === '"') return this.#string();
      if (character === "t") return this.#literal("true", true);
      if (character === "f") return this.#literal("false", false);
      if (character === "n") return this.#literal("null", null);
      return this.#number();
    } finally {
      this.#depth--;
    }
  }

  #object(): Record<string, unknown> {
    this.#offset++;
    const result: Record<string, unknown> = {};
    const keys = new Set<string>();
    this.#space();
    if (this.source[this.#offset] === "}") { this.#offset++; return result; }
    for (;;) {
      this.#space();
      if (this.source[this.#offset] !== '"') throw new SyntaxError("object key must be a string");
      const key = this.#string();
      if (keys.has(key)) throw new SyntaxError(`duplicate JSON object key ${JSON.stringify(key)}`);
      keys.add(key);
      this.#space();
      if (this.source[this.#offset++] !== ":") throw new SyntaxError("expected ':' after object key");
      Object.defineProperty(result, key, { value: this.#value(), enumerable: true, writable: true, configurable: true });
      this.#space();
      const separator = this.source[this.#offset++];
      if (separator === "}") return result;
      if (separator !== ",") throw new SyntaxError("expected ',' or '}' in object");
    }
  }

  #array(): unknown[] {
    this.#offset++;
    const result: unknown[] = [];
    this.#space();
    if (this.source[this.#offset] === "]") { this.#offset++; return result; }
    for (;;) {
      result.push(this.#value());
      this.#space();
      const separator = this.source[this.#offset++];
      if (separator === "]") return result;
      if (separator !== ",") throw new SyntaxError("expected ',' or ']' in array");
    }
  }

  #string(): string {
    const start = this.#offset++;
    for (;;) {
      const character = this.source[this.#offset++];
      if (character === undefined) throw new SyntaxError("unterminated JSON string");
      if (character === '"') {
        const value = JSON.parse(this.source.slice(start, this.#offset)) as string;
        validateUnicode(value, "JSON string");
        return value;
      }
      if (character === "\\") {
        if (this.source[this.#offset] === undefined) throw new SyntaxError("unterminated JSON escape");
        this.#offset++;
      }
    }
  }

  #literal(token: string, value: unknown): unknown {
    if (this.source.slice(this.#offset, this.#offset + token.length) !== token) throw new SyntaxError("invalid JSON value");
    this.#offset += token.length;
    return value;
  }

  #number(): number {
    const remaining = this.source.slice(this.#offset);
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(remaining);
    if (match === null) throw new SyntaxError("invalid JSON value");
    this.#offset += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) throw new SyntaxError("JSON number is outside the finite range");
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new SyntaxError("JSON integer is outside the interoperable safe range");
    }
    return value;
  }

  #space(): void {
    while (" \t\r\n".includes(this.source[this.#offset] ?? "\u0000")) this.#offset++;
  }
}

function validateUnicode(value: string, name: string): void {
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (code === 0xfffd || (character.length === 1 && code >= 0xd800 && code <= 0xdfff)) {
      throw new SyntaxError(`${name} cannot contain replacement or unpaired-surrogate characters`);
    }
  }
}

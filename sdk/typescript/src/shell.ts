import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants, createReadStream } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { delimiter, extname, isAbsolute, join } from "node:path";
import { LatchError } from "./errors.js";

export interface ShellAction {
  tool: string;
  operation: "execute";
  resource: string;
  arguments: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface ShellDecision {
  readonly decision: string;
  readonly allowed: boolean;
}

export interface ShellDecisionClient {
  decide(action: ShellAction, options?: { signal?: AbortSignal }): Promise<ShellDecision>;
}

export interface ShellCommand {
  executionId: string;
  executable: string;
  args?: readonly string[];
  cwd?: string;
  env?: Readonly<Record<string, string>>;
  unsetEnv?: readonly string[];
  clearEnv?: boolean;
  stdin?: string;
}

export interface ShellScript {
  executionId: string;
  command: string;
  cwd?: string;
  env?: Readonly<Record<string, string>>;
  unsetEnv?: readonly string[];
  clearEnv?: boolean;
  stdin?: string;
}

export interface ShellExecutorOptions {
  timeoutMs?: number;
  maxInputBytes?: number;
  maxOutputBytes?: number;
  replayCapacity?: number;
}

export interface ShellRunOptions {
  signal?: AbortSignal;
}

export interface ShellResult {
  readonly decision: ShellDecision;
  readonly exitCode: number;
  readonly signal: string | null;
  readonly stdout: Uint8Array;
  readonly stderr: Uint8Array;
}

export class ShellAdapterError extends LatchError {
  override readonly name: string = "ShellAdapterError";
}

export class ShellProtocolError extends ShellAdapterError {
  override readonly name = "ShellProtocolError";
}

export class ShellReplayError extends ShellAdapterError {
  override readonly name = "ShellReplayError";
  constructor(readonly executionId: string) {
    super(`shell execution ${JSON.stringify(executionId)} was duplicated or replayed; process not executed`);
  }
}

export class ShellNotAllowedError extends ShellAdapterError {
  override readonly name = "ShellNotAllowedError";
  constructor(readonly executionId: string, readonly decision: ShellDecision) {
    super(`Latch decision for shell execution ${JSON.stringify(executionId)} is ${decision.decision}; process not executed`);
  }
}

export class ShellExecutionError extends ShellAdapterError {
  override readonly name = "ShellExecutionError";
  constructor(
    readonly executionId: string,
    readonly result: ShellResult | undefined,
    options: { cause: unknown },
  ) {
    super(`execute allowed shell action ${JSON.stringify(executionId)}: ${errorMessage(options.cause)}`, options);
  }
}

interface PreparedCommand {
  executionId: string;
  mode: "argv" | "shell";
  executable: string;
  executableSha256: string;
  args: readonly string[];
  cwd: string;
  environment: NodeJS.ProcessEnv;
  stdin: Uint8Array;
  action: ShellAction;
}

const executionIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;

/** Starts a local process only after an explicit, valid Latch ALLOW. */
export class ShellExecutor {
  readonly #client: ShellDecisionClient;
  readonly #timeoutMs: number;
  readonly #maxInputBytes: number;
  readonly #maxOutputBytes: number;
  readonly #replayCapacity: number;
  readonly #replayed = new Set<string>();
  readonly #replayOrder: string[] = [];

  constructor(client: ShellDecisionClient, options: ShellExecutorOptions = {}) {
    if (client === null || typeof client !== "object" || typeof client.decide !== "function") {
      throw new TypeError("client must provide decide(action)");
    }
    this.#timeoutMs = boundedInteger(options.timeoutMs ?? 30_000, 1, 86_400_000, "timeoutMs");
    this.#maxInputBytes = boundedInteger(options.maxInputBytes ?? 1 << 20, 0, 16 << 20, "maxInputBytes");
    this.#maxOutputBytes = boundedInteger(options.maxOutputBytes ?? 4 << 20, 1024, 64 << 20, "maxOutputBytes");
    this.#replayCapacity = boundedInteger(options.replayCapacity ?? 10_000, 128, 1_000_000, "replayCapacity");
    this.#client = client;
  }

  /** Execute a structured argv command without invoking a command shell. */
  async run(command: ShellCommand, options: ShellRunOptions = {}): Promise<ShellResult> {
    const prepared = await this.#prepare({
      executionId: command.executionId,
      mode: "argv",
      executable: command.executable,
      args: command.args ?? [],
      shellCommand: undefined,
      cwd: command.cwd,
      env: command.env,
      unsetEnv: command.unsetEnv ?? [],
      clearEnv: command.clearEnv ?? false,
      stdin: command.stdin ?? "",
    });
    return this.#execute(prepared, options);
  }

  /** Execute explicit shell text through the platform system shell. */
  async runShell(script: ShellScript, options: ShellRunOptions = {}): Promise<ShellResult> {
    validateText(script.command, "shell command", 1 << 20, false);
    const windows = process.platform === "win32";
    const executable = windows ? "cmd.exe" : "sh";
    const args = windows ? ["/d", "/s", "/c", script.command] : ["-c", script.command];
    const prepared = await this.#prepare({
      executionId: script.executionId,
      mode: "shell",
      executable,
      args,
      shellCommand: script.command,
      cwd: script.cwd,
      env: script.env,
      unsetEnv: script.unsetEnv ?? [],
      clearEnv: script.clearEnv ?? false,
      stdin: script.stdin ?? "",
    });
    return this.#execute(prepared, options);
  }

  async #prepare(input: {
    executionId: string;
    mode: "argv" | "shell";
    executable: string;
    args: readonly string[];
    shellCommand: string | undefined;
    cwd: string | undefined;
    env: Readonly<Record<string, string>> | undefined;
    unsetEnv: readonly string[];
    clearEnv: boolean;
    stdin: string;
  }): Promise<PreparedCommand> {
    if (typeof input.executionId !== "string" || !executionIdPattern.test(input.executionId)) {
      throw new ShellProtocolError("execution ID must be 8-128 safe ASCII characters");
    }
    if (this.#replayed.has(input.executionId)) throw new ShellReplayError(input.executionId);
    const executable = await resolveExecutable(input.executable);
    const executableSha256 = await fileSha256(executable);
    const cwd = await resolveDirectory(input.cwd);
    const args = validateArgs(input.args);
    const stdin = encodeText(input.stdin, "stdin", this.#maxInputBytes, true);
    const environment = prepareEnvironment(input.env, input.unsetEnv, input.clearEnv);
    const arguments_: Record<string, unknown> = {
      execution_id: input.executionId,
      mode: input.mode,
      executable,
      executable_sha256: executableSha256,
      args,
      cwd,
      clear_environment: input.clearEnv,
      environment_sha256: environment.digest,
      environment_changes: environment.changes,
      stdin_sha256: sha256(stdin),
      stdin_bytes: stdin.byteLength,
      timeout_ms: this.#timeoutMs,
      command: input.mode === "shell" ? input.shellCommand : [executable, ...args],
    };
    return {
      executionId: input.executionId,
      mode: input.mode,
      executable,
      executableSha256,
      args,
      cwd,
      environment: environment.values,
      stdin,
      action: {
        tool: "shell.exec",
        operation: "execute",
        resource: executable,
        arguments: arguments_,
        metadata: { protocol: "local-process", surface: input.mode, platform: process.platform },
      },
    };
  }

  async #execute(prepared: PreparedCommand, options: ShellRunOptions): Promise<ShellResult> {
    const decision = await this.#client.decide(prepared.action, options);
    if (!decision.allowed) throw new ShellNotAllowedError(prepared.executionId, decision);
    if (await fileSha256(prepared.executable) !== prepared.executableSha256) {
      throw new ShellProtocolError("executable changed after approval; process not executed");
    }
    if (await resolveDirectory(prepared.cwd) !== prepared.cwd) {
      throw new ShellProtocolError("working directory changed after approval; process not executed");
    }
    if (options.signal?.aborted) {
      throw new ShellExecutionError(prepared.executionId, undefined, { cause: options.signal.reason ?? new Error("aborted") });
    }
    this.#reserve(prepared.executionId);
    try {
      return await runProcess(prepared, decision, this.#timeoutMs, this.#maxOutputBytes, options.signal);
    } catch (error) {
      if (error instanceof ShellExecutionError) throw error;
      throw new ShellExecutionError(prepared.executionId, undefined, { cause: error });
    }
  }

  #reserve(executionId: string): void {
    if (this.#replayed.has(executionId)) throw new ShellReplayError(executionId);
    this.#replayed.add(executionId);
    this.#replayOrder.push(executionId);
    while (this.#replayOrder.length > this.#replayCapacity) {
      this.#replayed.delete(this.#replayOrder.shift()!);
    }
  }
}

async function runProcess(
  prepared: PreparedCommand,
  decision: ShellDecision,
  timeoutMs: number,
  maxOutputBytes: number,
  abortSignal: AbortSignal | undefined,
): Promise<ShellResult> {
  return new Promise<ShellResult>((resolve, reject) => {
    let child;
    try {
      child = spawn(prepared.executable, prepared.args, {
        cwd: prepared.cwd,
        env: prepared.environment,
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (error) {
      reject(new ShellExecutionError(prepared.executionId, undefined, { cause: error }));
      return;
    }
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let timedOut = false;
    let aborted = false;
    let spawnError: unknown;
    let settled = false;

    const terminate = (): void => {
      try {
        child.kill("SIGKILL");
      } catch {
        // The close event will provide the final result.
      }
    };
    const collect = (chunks: Buffer[], current: number, value: Buffer): number => {
      const remaining = maxOutputBytes - current;
      if (remaining > 0) chunks.push(value.subarray(0, remaining));
      if (value.byteLength > remaining) {
        overflow = true;
        terminate();
      }
      return Math.min(maxOutputBytes, current + value.byteLength);
    };
    child.stdout.on("data", (value: Buffer) => { stdoutBytes = collect(stdout, stdoutBytes, value); });
    child.stderr.on("data", (value: Buffer) => { stderrBytes = collect(stderr, stderrBytes, value); });
    child.on("error", (error) => { spawnError = error; });
    const timer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, timeoutMs);
    timer.unref?.();
    const onAbort = (): void => {
      aborted = true;
      terminate();
    };
    abortSignal?.addEventListener("abort", onAbort, { once: true });
    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      abortSignal?.removeEventListener("abort", onAbort);
      const result: ShellResult = {
        decision,
        exitCode: code ?? -1,
        signal,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      };
      if (spawnError !== undefined) {
        reject(new ShellExecutionError(prepared.executionId, result, { cause: spawnError }));
      } else if (aborted) {
        reject(new ShellExecutionError(prepared.executionId, result, { cause: abortSignal?.reason ?? new Error("aborted") }));
      } else if (timedOut) {
        reject(new ShellExecutionError(prepared.executionId, result, { cause: new Error("process timed out") }));
      } else if (overflow) {
        reject(new ShellExecutionError(prepared.executionId, result, { cause: new Error(`process output exceeds ${maxOutputBytes} bytes per stream`) }));
      } else if (code !== 0) {
        reject(new ShellExecutionError(prepared.executionId, result, { cause: new Error(`process exited with code ${code ?? -1}`) }));
      } else {
        resolve(result);
      }
    });
    child.stdin.on("error", () => { /* Broken pipes are reflected by process exit. */ });
    child.stdin.end(Buffer.from(prepared.stdin));
  });
}

async function resolveExecutable(value: string): Promise<string> {
  validateText(value, "executable", 16 << 10, false);
  const candidates: string[] = [];
  const hasPath = isAbsolute(value) || value.includes("/") || value.includes("\\");
  if (hasPath) {
    candidates.push(value);
  } else {
    const directories = (process.env.PATH ?? "").split(delimiter).filter((entry) => entry !== "");
    const extensions = process.platform === "win32" && extname(value) === ""
      ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean)
      : [""];
    for (const directory of directories) {
      for (const extension of extensions) candidates.push(join(directory, value + extension));
    }
  }
  for (const candidate of candidates) {
    try {
      await access(candidate, process.platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
      const resolved = await realpath(candidate);
      if ((await stat(resolved)).isFile()) return resolved;
    } catch {
      // Continue searching the captured process PATH.
    }
  }
  throw new ShellProtocolError(`executable ${JSON.stringify(value)} could not be resolved`);
}

async function resolveDirectory(value: string | undefined): Promise<string> {
  const candidate = value === undefined || value === "" ? process.cwd() : value;
  validateText(candidate, "working directory", 16 << 10, false);
  try {
    const resolved = await realpath(candidate);
    if (!(await stat(resolved)).isDirectory()) throw new Error("not a directory");
    return resolved;
  } catch (error) {
    throw new ShellProtocolError(`working directory could not be resolved: ${errorMessage(error)}`);
  }
}

async function fileSha256(path: string): Promise<string> {
  const digest = createHash("sha256");
  try {
    for await (const chunk of createReadStream(path)) digest.update(chunk as Buffer);
  } catch (error) {
    throw new ShellProtocolError(`executable could not be fingerprinted: ${errorMessage(error)}`);
  }
  return digest.digest("hex");
}

function validateArgs(value: readonly string[]): readonly string[] {
  validatePlainArray(value, "args");
  if (value.length > 4096) throw new ShellProtocolError("argv cannot exceed 4096 arguments");
  let total = 0;
  return value.map((argument, index) => {
    const encoded = encodeText(argument, `argv[${index}]`, 1 << 20, true);
    total += encoded.byteLength;
    if (total > 4 << 20) throw new ShellProtocolError("argv exceeds 4194304 bytes");
    return argument;
  });
}

function prepareEnvironment(
  overrides: Readonly<Record<string, string>> | undefined,
  unset: readonly string[],
  clear: boolean,
): { values: NodeJS.ProcessEnv; digest: string; changes: readonly Record<string, unknown>[] } {
  if (typeof clear !== "boolean") throw new ShellProtocolError("clearEnv must be a boolean");
  const source = overrides ?? {};
  validatePlainRecord(source, "env");
  validatePlainArray(unset, "unsetEnv");
  const values: NodeJS.ProcessEnv = clear ? {} : { ...process.env };
  const canonical = new Map<string, string>();
  for (const name of Object.keys(values)) canonical.set(environmentKey(name), name);
  const changed = new Set<string>();
  const changes: Record<string, unknown>[] = [];
  for (const name of Object.keys(source)) {
    validateEnvironmentName(name);
    const value = source[name];
    if (typeof value !== "string") throw new ShellProtocolError(`environment value for ${JSON.stringify(name)} must be a string`);
    const encoded = encodeText(value, `environment value for ${JSON.stringify(name)}`, 1 << 20, true);
    const key = environmentKey(name);
    if (changed.has(key)) throw new ShellProtocolError(`environment variable ${JSON.stringify(name)} is changed more than once`);
    changed.add(key);
    const old = canonical.get(key);
    if (old !== undefined) delete values[old];
    values[name] = value;
    canonical.set(key, name);
    changes.push({ name, value_sha256: sha256(encoded), value_bytes: encoded.byteLength });
  }
  for (const name of unset) {
    validateEnvironmentName(name);
    const key = environmentKey(name);
    if (changed.has(key)) throw new ShellProtocolError(`environment variable ${JSON.stringify(name)} is changed more than once`);
    changed.add(key);
    const old = canonical.get(key);
    if (old !== undefined) delete values[old];
    canonical.delete(key);
    changes.push({ name, unset: true });
  }
  const names = Object.keys(values).sort();
  if (names.length > 16_384) throw new ShellProtocolError("environment snapshot exceeds 16384 variables");
  const entries = names.map((name) => `${name}=${values[name] ?? ""}`);
  changes.sort((left, right) => String(left.name).localeCompare(String(right.name)));
  return { values, digest: sha256(Buffer.from(JSON.stringify(entries), "utf8")), changes };
}

function validatePlainRecord(value: object, name: string): void {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new ShellProtocolError(`${name} must be a plain object`);
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new ShellProtocolError(`${name} cannot contain symbol properties`);
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (descriptor.get !== undefined || descriptor.set !== undefined) throw new ShellProtocolError(`${name}.${key} cannot be an accessor`);
    if (!descriptor.enumerable) throw new ShellProtocolError(`${name}.${key} cannot be hidden`);
  }
}

function validatePlainArray(value: readonly unknown[], name: string): void {
  if (!Array.isArray(value)) throw new ShellProtocolError(`${name} must be an array`);
  if (Object.getPrototypeOf(value) !== Array.prototype) throw new ShellProtocolError(`${name} must be a plain array`);
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new ShellProtocolError(`${name} cannot contain symbol properties`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index++) {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined) throw new ShellProtocolError(`${name} cannot be sparse`);
    if (descriptor.get !== undefined || descriptor.set !== undefined) throw new ShellProtocolError(`${name}[${index}] cannot be an accessor`);
    if (!descriptor.enumerable) throw new ShellProtocolError(`${name}[${index}] cannot be hidden`);
  }
  for (const key of Object.keys(descriptors)) {
    if (key !== "length" && !/^(?:0|[1-9]\d*)$/.test(key)) throw new ShellProtocolError(`${name} cannot contain named properties`);
  }
}

function validateEnvironmentName(value: unknown): asserts value is string {
  if (typeof value !== "string" || value === "" || value.includes("=") || value.includes("\0")) {
    throw new ShellProtocolError(`environment variable name ${JSON.stringify(value)} is invalid`);
  }
  encodeText(value, "environment variable name", 1024, false);
}

function environmentKey(value: string): string {
  return process.platform === "win32" ? value.toUpperCase() : value;
}

function validateText(value: unknown, name: string, limit: number, allowEmpty: boolean): void {
  encodeText(value, name, limit, allowEmpty);
}

function encodeText(value: unknown, name: string, limit: number, allowEmpty: boolean): Uint8Array {
  if (typeof value !== "string") throw new ShellProtocolError(`${name} must be a string`);
  if (!allowEmpty && value.trim() === "") throw new ShellProtocolError(`${name} cannot be empty`);
  if (value.includes("\0")) throw new ShellProtocolError(`${name} cannot contain NUL bytes`);
  validateUnicode(value, name);
  const encoded = Buffer.from(value, "utf8");
  if (encoded.byteLength > limit) throw new ShellProtocolError(`${name} exceeds ${limit} bytes`);
  return encoded;
}

function validateUnicode(value: string, name: string): void {
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (code === 0xfffd || (character.length === 1 && code >= 0xd800 && code <= 0xdfff)) {
      throw new ShellProtocolError(`${name} must contain valid interoperable Unicode`);
    }
  }
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function boundedInteger(value: number, minimum: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

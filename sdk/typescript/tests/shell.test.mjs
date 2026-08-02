import assert from "node:assert/strict";
import { appendFile, copyFile, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";

import {
  ShellExecutionError,
  ShellExecutor,
  ShellNotAllowedError,
  ShellProtocolError,
  ShellReplayError,
} from "../dist/shell.js";

class FakeClient {
  constructor(verdict = "ALLOW", error, after) {
    this.verdict = verdict;
    this.error = error;
    this.after = after;
    this.actions = [];
  }

  async decide(action) {
    this.actions.push(action);
    await this.after?.();
    if (this.error !== undefined) throw this.error;
    return { decision: this.verdict, allowed: this.verdict === "ALLOW" };
  }
}

test("structured command is allowed and normalized without leaking input", async () => {
  const client = new FakeClient();
  const executor = new ShellExecutor(client);
  const code = `let d="";process.stdin.setEncoding("utf8");process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>process.stdout.write(process.argv.slice(1).join(",")+"|"+process.env.LATCH_VALUE+"|"+d));`;
  const result = await executor.run({
    executionId: "exec_node_001",
    executable: process.execPath,
    args: ["-e", code, "one", "two"],
    env: { LATCH_VALUE: "secret-value" },
    stdin: "payload",
  });
  assert.equal(result.exitCode, 0);
  assert.equal(Buffer.from(result.stdout).toString("utf8"), "one,two|secret-value|payload");
  const action = client.actions[0];
  assert.equal(action.tool, "shell.exec");
  assert.equal(action.metadata.surface, "argv");
  const encoded = JSON.stringify(action);
  assert.equal(encoded.includes("secret-value"), false);
  assert.equal(encoded.includes("payload"), false);
  assert.ok(action.arguments.environment_sha256);
  assert.ok(action.arguments.stdin_sha256);
});

test("BLOCK, REQUIRE_APPROVAL, and outage start no process", async (t) => {
  for (const [name, client, ErrorType] of [
    ["block", new FakeClient("BLOCK"), ShellNotAllowedError],
    ["approval", new FakeClient("REQUIRE_APPROVAL"), ShellNotAllowedError],
    ["outage", new FakeClient("ALLOW", new Error("offline")), Error],
  ]) {
    await t.test(name, async () => {
      const directory = await mkdtemp(join(tmpdir(), "latch-shell-"));
      const marker = join(directory, "started");
      try {
        const code = `require("node:fs").writeFileSync(process.argv[1],"started")`;
        await assert.rejects(
          new ShellExecutor(client).run({ executionId: "exec_denied_001", executable: process.execPath, args: ["-e", code, marker] }),
          ErrorType,
        );
        await assert.rejects(stat(marker), { code: "ENOENT" });
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
  }
});

test("failed process remains consumed and replay is rejected", async () => {
  const client = new FakeClient();
  const executor = new ShellExecutor(client);
  const command = { executionId: "exec_replay_001", executable: process.execPath, args: ["-e", "process.exit(7)"] };
  await assert.rejects(executor.run(command), ShellExecutionError);
  await assert.rejects(executor.run(command), ShellReplayError);
  assert.equal(client.actions.length, 1);
});

test("timeout and bounded output stop allowed processes", async () => {
  const timeoutExecutor = new ShellExecutor(new FakeClient(), { timeoutMs: 50 });
  await assert.rejects(
    timeoutExecutor.run({ executionId: "exec_timeout_001", executable: process.execPath, args: ["-e", "setTimeout(()=>{},2000)"] }),
    ShellExecutionError,
  );
  const outputExecutor = new ShellExecutor(new FakeClient(), { maxOutputBytes: 1024 });
  await assert.rejects(
    outputExecutor.run({ executionId: "exec_output_001", executable: process.execPath, args: ["-e", "process.stdout.write('x'.repeat(4096))"] }),
    (error) => error instanceof ShellExecutionError && error.result.stdout.byteLength === 1024,
  );
});

test("changed executable and hostile environment objects fail before start", async () => {
  const directory = await mkdtemp(join(tmpdir(), "latch-shell-"));
  const copied = join(directory, basename(process.execPath));
  try {
    await copyFile(process.execPath, copied);
    const client = new FakeClient("ALLOW", undefined, () => appendFile(copied, "changed"));
    await assert.rejects(
      new ShellExecutor(client).run({ executionId: "exec_changed_001", executable: copied }),
      ShellProtocolError,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }

  const conflictClient = new FakeClient();
  await assert.rejects(
    new ShellExecutor(conflictClient).run({
      executionId: "exec_env_conflict",
      executable: process.execPath,
      env: { LATCH_VALUE: "one" },
      unsetEnv: ["LATCH_VALUE"],
    }),
    ShellProtocolError,
  );
  assert.equal(conflictClient.actions.length, 0);

  let getterRead = false;
  const hostile = {};
  Object.defineProperty(hostile, "LATCH_VALUE", { enumerable: true, get() { getterRead = true; return "secret"; } });
  await assert.rejects(
    new ShellExecutor(new FakeClient()).run({ executionId: "exec_getter_001", executable: process.execPath, env: hostile }),
    ShellProtocolError,
  );
  assert.equal(getterRead, false);

  let argumentRead = false;
  const hostileArgs = [];
  Object.defineProperty(hostileArgs, 0, { enumerable: true, get() { argumentRead = true; return "--version"; } });
  hostileArgs.length = 1;
  await assert.rejects(
    new ShellExecutor(new FakeClient()).run({ executionId: "exec_arg_getter", executable: process.execPath, args: hostileArgs }),
    ShellProtocolError,
  );
  assert.equal(argumentRead, false);
});

test("explicit shell text uses the separate protected surface", async () => {
  const client = new FakeClient();
  const result = await new ShellExecutor(client).runShell({ executionId: "exec_script_001", command: "echo shell-ok" });
  assert.match(Buffer.from(result.stdout).toString("utf8"), /shell-ok/);
  assert.equal(client.actions[0].arguments.command, "echo shell-ok");
  assert.equal(client.actions[0].metadata.surface, "shell");
});

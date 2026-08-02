import { LatchClient } from "../src/index.js";
import { ShellExecutor, type ShellCommand, type ShellResult } from "../src/shell.js";

const client = new LatchClient("http://127.0.0.1:7070");
const shell = new ShellExecutor(client);
const command: ShellCommand = {
  executionId: "agent:typecheck:001",
  executable: "git",
  args: ["status", "--short"],
};
const result: Promise<ShellResult> = shell.run(command, { signal: new AbortController().signal });

void result;

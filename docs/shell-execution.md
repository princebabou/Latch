# Protected shell and local process execution

Latch's shell executors are the safe replacement for calling `exec`,
`subprocess`, or `spawn` directly from an agent tool. They are included in the
official Go, Python, and TypeScript SDKs and share one action contract.

The recommended interface accepts an executable and argv as separate values.
An explicit shell-text interface is available for commands that genuinely need
pipes, redirects, variables, or shell expansion.

## Security boundary

Before a process starts, each executor:

1. validates the caller-supplied execution ID, argv, environment changes,
   working directory, stdin, timeout, and size bounds;
2. resolves the executable and working directory to absolute real paths;
3. fingerprints the executable with SHA-256;
4. snapshots the exact child environment and hashes secret-bearing values;
5. submits the normalized `shell.exec` action to Latch;
6. accepts only an explicit `ALLOW`;
7. rechecks the executable fingerprint and working-directory resolution;
8. consumes the execution ID before starting the child; and
9. enforces timeout plus separate stdout and stderr limits.

`BLOCK`, unresolved `REQUIRE_APPROVAL`, API outage, malformed responses,
replay, path changes, executable replacement, timeout, output overflow, and
process-launch failure all stop or fail the invocation. Once an allowed process
may have started, its execution ID remains consumed even when the process exits
with an error.

## Go

```go
executor, err := latch.NewShellExecutor(client)
if err != nil {
    return err
}

result, err := executor.Run(ctx, latch.ShellCommand{
    ExecutionID:      "agent:git-status:001",
    Executable:       "git",
    Args:             []string{"status", "--short"},
    WorkingDirectory: workspace,
    Environment:      map[string]string{"CI": "true"},
})
if err != nil {
    return err
}
fmt.Print(string(result.Stdout))
```

Use `RunShell` only when shell syntax is required:

```go
result, err := executor.RunShell(ctx, latch.ShellScript{
    ExecutionID: "agent:tests:001",
    Command:     "go test ./... | tee test.log",
})
```

## Python

```python
from latch_sdk import LatchClient, ShellExecutor

latch = LatchClient("http://127.0.0.1:7070", token="...")
shell = ShellExecutor(latch)

result = shell.run(
    "agent:git-status:001",
    "git",
    ("status", "--short"),
    cwd=workspace,
    env={"CI": "true"},
)
print(result.stdout_text)
```

The explicit shell-text form is `shell.run_shell(execution_id, command)`.

## TypeScript

The Node-only executor uses a separate export so importing the base SDK remains
safe in browser bundles:

```ts
import { LatchClient } from "@latch-security/sdk";
import { ShellExecutor } from "@latch-security/sdk/shell";

const latch = new LatchClient("http://127.0.0.1:7070", { token });
const shell = new ShellExecutor(latch);

const result = await shell.run({
  executionId: "agent:git-status:001",
  executable: "git",
  args: ["status", "--short"],
  cwd: workspace,
  env: { CI: "true" },
});

console.log(new TextDecoder().decode(result.stdout));
```

Use `runShell({ executionId, command })` only when shell parsing is intentional.
Both methods accept an `AbortSignal` as their second argument.

## Normalized action

All three SDKs submit the same shape:

```json
{
  "tool": "shell.exec",
  "operation": "execute",
  "resource": "/absolute/path/to/git",
  "arguments": {
    "execution_id": "agent:git-status:001",
    "mode": "argv",
    "command": ["/absolute/path/to/git", "status", "--short"],
    "executable": "/absolute/path/to/git",
    "executable_sha256": "...",
    "args": ["status", "--short"],
    "cwd": "/absolute/workspace",
    "clear_environment": false,
    "environment_sha256": "...",
    "environment_changes": [
      {"name": "CI", "value_sha256": "...", "value_bytes": 4}
    ],
    "stdin_sha256": "...",
    "stdin_bytes": 0,
    "timeout_ms": 30000
  },
  "metadata": {
    "protocol": "local-process",
    "surface": "argv",
    "platform": "..."
  }
}
```

Environment values and stdin are bound by digest rather than copied into the
decision payload. Environment variable names remain visible so Latch can flag
search-path changes and interpreter-startup injection such as `NODE_OPTIONS`,
`PYTHONPATH`, `LD_PRELOAD`, or `COMSPEC`. Opaque stdin sent to a command
interpreter is elevated as a high-risk signal.

Argv and explicit shell text are visible to policy and audit because they are
the code being authorized. Do not place credentials directly in command-line
arguments; pass them through an environment variable or a purpose-built
credential channel.

## Execution IDs and approvals

Execution IDs are 8-128 safe ASCII characters. Generate a new ID for each
logical side effect and retain it across delivery retries. If Latch returns
`REQUIRE_APPROVAL`, retry the exact action with the same ID after approval. A
process that may have started consumes the ID locally, preventing an uncertain
retry from repeating the side effect.

Replay storage is bounded and process-local. It prevents ordinary agent-loop
and message-redelivery replays, but it is not a durable distributed idempotency
store. Use an application-level idempotency key as well for payments,
deployments, migrations, and other remotely committed effects.

## Limits and threat model

Defaults are a 30-second runtime, 1 MiB stdin, 4 MiB stdout, 4 MiB stderr, and
10,000 replay IDs. SDK options can tighten or expand them within hard bounds.

The executor is an enforcement boundary, not an operating-system sandbox. An
allowed process still has the filesystem, network, user identity, and kernel
permissions of its parent. Use containers, restricted service accounts,
seccomp/AppArmor, Windows job and integrity controls, or another sandbox when
untrusted code needs containment. Latch decides whether the intended process
may start; it does not make an allowed program harmless.

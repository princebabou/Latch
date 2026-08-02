# Integration SDKs

Latch provides small, fail-closed clients for Go, Python, and TypeScript. All
three target the same `latch.security/v1` contract and follow one invariant:

> Execute a tool only after receiving a valid, correlated `ALLOW` response.

An unavailable API, timeout, redirect, non-200 response, oversized body,
malformed JSON, request-ID mismatch, unsupported API version, unknown verdict,
`BLOCK`, or `REQUIRE_APPROVAL` stops guarded execution.

All three SDKs also include an `OpenAIToolAdapter`. It protects completed
Responses API and Chat Completions function calls with strict argument parsing,
whole-batch authorization, local replay protection, and provider-native output
objects. See the [OpenAI-compatible integration guide](openai-tool-calling.md).

Python and TypeScript also include optional LangChain v1 middleware and
protected LangGraph ToolNodes. The ToolNode adapters authorize a complete
parallel batch before framework execution begins. See the
[LangChain/LangGraph integration guide](langchain-langgraph.md).

All three SDKs include a protected local process executor. It resolves and
fingerprints the child executable, snapshots cwd and environment, submits the
same `shell.exec` action, and starts the process only after an explicit ALLOW.
See the [shell execution guide](shell-execution.md).

Start an authenticated local API before trying an SDK:

```sh
export LATCH_API_TOKEN="$(openssl rand -hex 32)"
latch serve --config latch.yaml --agent desktop-agent
```

## Go

The package lives at `github.com/princebabou/Latch/sdk/go/latch` and uses only
the Go standard library plus Latch's v1 contract types.

```go
import (
    "context"
    "os"

    latch "github.com/princebabou/Latch/sdk/go/latch"
    v1 "github.com/princebabou/Latch/pkg/api/v1"
)

client, err := latch.New(
    "http://127.0.0.1:7070",
    latch.WithToken(os.Getenv("LATCH_API_TOKEN")),
)
if err != nil {
    return err
}

result, err := client.Guard(ctx, v1.Action{
    Tool:      "filesystem.read",
    Arguments: map[string]any{"path": "./README.md"},
}, func(context.Context) error {
    return runTool()
})

shell, err := latch.NewShellExecutor(client)
result, err := shell.Run(ctx, latch.ShellCommand{
    ExecutionID: "agent:git-status:001",
    Executable:  "git",
    Args:        []string{"status", "--short"},
})
```

`Guard` returns the decision alongside any error. `Decide` is available when an
adapter needs to inspect evidence or manage execution itself. Redirects are
always disabled, even for a supplied `http.Client`.

## Python

The dependency-free package is in `sdk/python` and supports Python 3.9+.

```sh
python -m pip install ./sdk/python
```

```python
import os
from latch_sdk import Action, LatchClient, OpenAIToolAdapter

latch = LatchClient(
    "http://127.0.0.1:7070",
    token=os.environ["LATCH_API_TOKEN"],
)

result = latch.guard(
    Action("filesystem.read", {"path": "./README.md"}),
    lambda: run_tool(),
)
```

Use `decide(...).require_allow()` when the decision and execution naturally
occur in separate code paths. The package includes a `py.typed` marker for
static type checkers.

```python
adapter = OpenAIToolAdapter(latch, {"get_weather": get_weather})
outputs = adapter.execute_responses(response)
```

```python
from latch_sdk import ShellExecutor

shell = ShellExecutor(latch)
result = shell.run("agent:git-status:001", "git", ("status", "--short"))
```

## TypeScript

The zero-runtime-dependency ESM package is in `sdk/typescript`. It supports
Node.js 18+ and browser runtimes with standards-compatible `fetch` and Web
Crypto implementations.

```ts
import { LatchClient, OpenAIToolAdapter } from "@latch-security/sdk";

const latch = new LatchClient("http://127.0.0.1:7070", {
  token: process.env.LATCH_API_TOKEN,
});

const result = await latch.guard(
  { tool: "filesystem.read", arguments: { path: "./README.md" } },
  () => runTool(),
);
```

Each call has a two-second default timeout and accepts an `AbortSignal` for
caller cancellation. Redirects are forbidden and response streams are bounded
while they are read.

```ts
const adapter = new OpenAIToolAdapter(latch, { get_weather: getWeather });
const messages = await adapter.executeChatCompletion(completion);
```

The Node-only executor is a separate export so the base client remains usable
in browsers:

```ts
import { ShellExecutor } from "@latch-security/sdk/shell";

const shell = new ShellExecutor(latch);
const result = await shell.run({
  executionId: "agent:git-status:001",
  executable: "git",
  args: ["status", "--short"],
});
```

## Error handling

| Condition | Go | Python | TypeScript |
|---|---|---|---|
| Connection or timeout | `UnavailableError` | `LatchUnavailable` | `LatchUnavailable` |
| Invalid v1 response | `ProtocolError` | `ProtocolError` | `ProtocolError` |
| HTTP/API rejection | `APIError` | `APIError` | `APIError` |
| Non-allow verdict | `NotAllowedError` | `NotAllowedError` | `NotAllowedError` |

These errors are intentionally exceptional. Do not catch them and continue to
the tool call. Catch them only to report, retry with a fresh request ID where
appropriate, or route `REQUIRE_APPROVAL` to an approval workflow.

# Latch TypeScript SDK

```ts
import { LatchClient, OpenAIToolAdapter } from "@latch-security/sdk";

const latch = new LatchClient("http://127.0.0.1:7070", { token: process.env.LATCH_API_TOKEN });
const decision = await latch.decide({
  tool: "filesystem.read",
  arguments: { path: "./README.md" },
});
decision.requireAllow();
```

The guarded form invokes the tool only after an explicit, valid `ALLOW`:

```ts
const result = await latch.guard(action, () => tool(action.arguments));
```

Connection failures, timeouts, redirects, oversized responses, malformed JSON,
version mismatches, `BLOCK`, and `REQUIRE_APPROVAL` all prevent execution.

Protect completed OpenAI-compatible function calls with the same client:

```ts
const adapter = new OpenAIToolAdapter(latch, { get_weather: getWeather });
const outputs = await adapter.executeResponses(response);
// Or: const messages = await adapter.executeChatCompletion(completion);
```

Every call in the batch must be valid, registered, and allowed before any
handler runs. Duplicate call IDs are rejected to prevent repeated side effects.

Add native LangChain middleware or a whole-batch protected LangGraph ToolNode:

```ts
const middleware = await createLatchAgentMiddleware(latch);
const toolNode = await createLatchToolNode(tools, latch);
```

`langchain` and `@langchain/langgraph` are optional peer dependencies and load
only when these factories are used. Middleware protects individual agent calls;
the ToolNode preflights the complete parallel batch. Current LangChain v1
releases require Node.js 20+; the base Latch client continues to support 18+.

Protect a Node child process through the Node-only subpath export:

```ts
import { ShellExecutor } from "@latch-security/sdk/shell";

const shell = new ShellExecutor(latch);
const result = await shell.run({
  executionId: "agent:git-status:001",
  executable: "git",
  args: ["status", "--short"],
  cwd: workspace,
});
```

`runShell` is a separate explicit method for shell syntax. Keeping it in the
`/shell` export preserves the browser-safe base SDK while providing bounded,
abortable, replay-resistant local execution on Node.js.

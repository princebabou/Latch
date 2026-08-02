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

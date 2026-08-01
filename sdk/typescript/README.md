# Latch TypeScript SDK

```ts
import { LatchClient } from "@latch-security/sdk";

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

# OpenAI-compatible tool calling

Latch's Go, Python, and TypeScript SDKs can protect function calls from the
OpenAI Responses API and Chat Completions API, as well as compatible providers
that preserve those completed-response shapes. The adapter has no runtime
dependency on an OpenAI SDK.

The invariant is stronger than approving calls one at a time:

1. Parse and validate every function call in the selected response.
2. Resolve every function name to a locally registered handler.
3. Require an explicit Latch `ALLOW` for every call.
4. Atomically consume every call ID to prevent duplicate execution.
5. Only then invoke handlers in source order.

If any call is malformed, unknown, replayed, denied, approval-gated, or cannot
reach Latch, no handler in that batch starts. Allowed budget units may be
conservatively reserved before a later call is denied; the adapter favors
preventing side effects over reclaiming capacity after a partial preflight.

## Python: Responses API

```python
from latch_sdk import LatchClient, OpenAIToolAdapter

latch = LatchClient("http://127.0.0.1:7070", token="...")
tools = OpenAIToolAdapter(latch, {
    "get_weather": lambda args: {"city": args["city"], "temperature": 24},
})

response = openai.responses.create(
    model="your-model",
    input="What is the weather in Kigali?",
    tools=tool_definitions,
)

# Accepts the assembled SDK response object directly.
tool_outputs = tools.execute_responses(response)

# Preserve original output items, including reasoning, and append tool results.
conversation = list(response.output)
conversation.extend(tool_outputs)
next_response = openai.responses.create(
    model="your-model",
    input=conversation,
    tools=tool_definitions,
)
```

## TypeScript: Chat Completions

```ts
import { LatchClient, OpenAIToolAdapter } from "@latch-security/sdk";

const latch = new LatchClient("http://127.0.0.1:7070", {
  token: process.env.LATCH_API_TOKEN,
});
const tools = new OpenAIToolAdapter(latch, {
  get_weather: async (args) => ({ city: args.city, temperature: 24 }),
});

const completion = await openai.chat.completions.create({
  model: "your-model",
  messages,
  tools: toolDefinitions,
});

const toolMessages = await tools.executeChatCompletion(completion);
messages.push(completion.choices[0].message, ...toolMessages);
```

Pass `{ choiceIndex: 1 }` as the second argument when intentionally executing
a choice other than index `0`. Calls in unselected choices are never evaluated
or executed.

## Go: Responses API

```go
client, err := latch.New(
    "http://127.0.0.1:7070",
    latch.WithToken(os.Getenv("LATCH_API_TOKEN")),
)
if err != nil {
    return err
}

tools, err := latch.NewOpenAIToolAdapter(client, map[string]latch.OpenAIToolHandler{
    "get_weather": func(ctx context.Context, args map[string]any) (any, error) {
        return map[string]any{"city": args["city"], "temperature": 24}, nil
    },
})
if err != nil {
    return err
}

payload, err := json.Marshal(response)
if err != nil {
    return err
}
toolOutputs, err := tools.ExecuteResponses(ctx, payload)
if err != nil {
    return err // no unapproved handler was run
}
```

`ExecuteChatCompletion` returns `[]OpenAIChatToolMessage` with the exact
`role`, `tool_call_id`, and string `content` fields expected by Chat
Completions.

## Security behavior

- Arguments must be a strict JSON object. Duplicate keys, trailing data,
  malformed or ambiguous Unicode, non-interoperable numbers, non-object
  arguments, and oversized values fail closed.
- Completed assembled responses are required. Do not pass streaming deltas or
  partially accumulated function arguments.
- Strings returned by a handler are forwarded as strings. Other values are
  encoded as compact JSON. Unserializable or oversized results fail.
- Call IDs are held in a bounded in-memory replay cache. A handler failure
  leaves its ID consumed because automatically retrying an uncertain side
  effect is unsafe.
- Replay protection is local to one adapter process. Use a durable queue or
  idempotent tool backend when delivery can move between replicas or survive a
  restart.
- Function tools are supported. Responses API `custom_tool_call` items are
  rejected explicitly in this milestone rather than executed without a
  complete protection contract.

The adapter follows the official [OpenAI function-calling lifecycle](https://developers.openai.com/api/docs/guides/function-calling)
and the completed [Chat Completions tool-call shape](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).

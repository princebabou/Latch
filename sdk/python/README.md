# Latch Python SDK

```python
from latch_sdk import Action, LatchClient, OpenAIToolAdapter

client = LatchClient("http://127.0.0.1:7070", token="...")
decision = client.decide(Action("filesystem.read", {"path": "./README.md"}))
decision.require_allow()
```

For the shortest fail-closed wrapper, `guard` invokes the callback only after
an explicit, valid `ALLOW`:

```python
result = client.guard(action, lambda: tool(**action.arguments))
```

Connection failures, timeouts, redirects, oversized responses, malformed JSON,
version mismatches, `BLOCK`, and `REQUIRE_APPROVAL` all prevent execution.

Protect completed OpenAI-compatible function calls with the same client:

```python
adapter = OpenAIToolAdapter(client, {"get_weather": get_weather})
outputs = adapter.execute_responses(response)
# Or: messages = adapter.execute_chat_completion(completion)
```

Every call in the batch must be valid, registered, and allowed before any
handler runs. Duplicate call IDs are rejected to prevent repeated side effects.

Install the optional LangChain/LangGraph integration and add its middleware or
protected ToolNode:

```sh
python -m pip install "latch-sdk[langchain]"
```

```python
from latch_sdk.langchain import LatchAgentMiddleware, LatchToolNode

middleware = LatchAgentMiddleware(client)
tool_node = LatchToolNode(tools, client)
```

Middleware protects individual agent calls. `LatchToolNode` preflights the
complete parallel LangGraph batch before any tool starts.

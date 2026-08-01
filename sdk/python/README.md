# Latch Python SDK

```python
from latch_sdk import Action, LatchClient

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

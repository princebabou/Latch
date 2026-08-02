# LangChain and LangGraph

Latch provides native LangChain v1 middleware and a protected LangGraph
`ToolNode` for Python and TypeScript. Both use the stable Enforcement API and
execute only after an explicit `ALLOW`.

Choose the boundary that matches the application:

| Integration | Best for | Enforcement unit |
|---|---|---|
| Agent middleware | Standard `create_agent` / `createAgent` applications | One framework tool call |
| Protected `ToolNode` | Custom LangGraph workflows and parallel tool calls | The complete ToolNode batch |

The protected `ToolNode` is the stronger choice when a model can request
multiple tools in parallel. It validates, resolves, and authorizes every call
before LangGraph starts any tool in the batch.

## Install

Python keeps the framework dependency optional:

```sh
python -m pip install "latch-sdk[langchain]"
```

TypeScript projects already using LangChain should install the optional peer
dependencies alongside the Latch SDK. Current LangChain v1 releases require
Node.js 20 or newer for this integration; the base Latch SDK still supports
Node.js 18:

```sh
npm install @latch-security/sdk langchain @langchain/langgraph
```

## Python agent middleware

```python
import os

from langchain.agents import create_agent
from latch_sdk import LatchClient
from latch_sdk.langchain import LatchAgentMiddleware

latch = LatchClient(
    "http://127.0.0.1:7070",
    token=os.environ["LATCH_API_TOKEN"],
)

agent = create_agent(
    model=model,
    tools=tools,
    middleware=[LatchAgentMiddleware(latch)],
)
```

`LatchAgentMiddleware` implements both `wrap_tool_call` and
`awrap_tool_call`. A malformed call, missing resolved tool, duplicate ID,
Latch failure, `BLOCK`, or `REQUIRE_APPROVAL` raises before the handler runs.

LangChain applies middleware to each tool call. If the framework schedules
several tool calls in parallel, a blocked call cannot execute, but a separately
allowed sibling may already be running. Use `LatchToolNode` when the entire
parallel batch must be approved before any side effect starts.

## Python protected ToolNode

```python
from langgraph.graph import END, START, MessagesState, StateGraph
from latch_sdk.langchain import LatchToolNode

tool_node = LatchToolNode(tools, latch)

builder = StateGraph(MessagesState)
builder.add_node("tools", tool_node)
builder.add_edge(START, "tools")
builder.add_edge("tools", END)
graph = builder.compile()
```

Use it anywhere a normal prebuilt `ToolNode` is accepted. Existing options
such as `messages_key`, `handle_tool_errors`, `wrap_tool_call`, and
`awrap_tool_call` pass through unchanged. Latch-specific size and replay bounds
use the `latch_max_calls`, `latch_max_argument_bytes`, and
`latch_replay_capacity` keywords.

## TypeScript agent middleware

```ts
import {
  LatchClient,
  createLatchAgentMiddleware,
} from "@latch-security/sdk";
import { createAgent } from "langchain";

const latch = new LatchClient("http://127.0.0.1:7070", {
  token: process.env.LATCH_API_TOKEN,
});

const agent = createAgent({
  model,
  tools,
  middleware: [await createLatchAgentMiddleware(latch)],
});
```

The asynchronous factory loads the optional LangChain peer only when this
integration is used. `createLatchToolCallHook` is also exported for projects
that already have their own `createMiddleware` factory or middleware bundle.

## TypeScript protected ToolNode

```ts
import { createLatchToolNode } from "@latch-security/sdk";
import {
  END,
  MessagesAnnotation,
  START,
  StateGraph,
} from "@langchain/langgraph";

const toolNode = await createLatchToolNode(tools, latch);

const graph = new StateGraph(MessagesAnnotation)
  .addNode("tools", toolNode)
  .addEdge(START, "tools")
  .addEdge("tools", END)
  .compile();
```

Stream the compiled graph, not the ToolNode directly. Direct `batch()` and
`stream()` calls on the protected TypeScript node are disabled so alternate
Runnable paths cannot bypass its preflight boundary.

## Security contract

- Model-controlled arguments must be plain, bounded, interoperable JSON.
  Cycles, accessors, sparse arrays, non-string keys, ambiguous Unicode,
  non-finite numbers, and unsafe integers fail closed.
- Unknown tools are rejected before Latch is contacted or any sibling runs.
- Every call in a protected ToolNode batch must receive `ALLOW` before tool
  execution begins. A later denial can conservatively consume earlier budget
  reservations, favoring safety over budget reclamation.
- Call IDs are consumed in a bounded, process-local replay cache before tool
  invocation. Tool failure does not make an uncertain side effect retryable.
- LangGraph-injected state, stores, runtime context, and credentials are not
  copied into the model-controlled action arguments. Operators should express
  trusted identity at the Latch API boundary.

The adapters follow LangChain's official [tool middleware contract](https://docs.langchain.com/oss/python/langchain/middleware/custom)
and LangGraph's documented [ToolNode execution model](https://docs.langchain.com/oss/python/langchain/tools#toolnode).

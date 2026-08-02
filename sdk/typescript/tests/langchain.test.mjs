import assert from "node:assert/strict";
import test from "node:test";

import { AIMessage } from "@langchain/core/messages";
import { END, MessagesAnnotation, START, StateGraph } from "@langchain/langgraph";
import { tool } from "langchain";
import * as z from "zod";

import {
  Decision,
  LangChainNotAllowedError,
  LangChainProtocolError,
  LangChainReplayError,
  UnknownLangChainToolError,
  createLatchAgentMiddleware,
  createLatchToolCallHook,
  createLatchToolNode,
} from "../dist/index.js";

function result(value = "ALLOW") {
  return new Decision(
    "req_langchain",
    value,
    { score: 0, level: "LOW" },
    { verified: true },
    { decision_source: "test", hard_deny: value !== "ALLOW" },
  );
}

class FakeClient {
  constructor(decisions = ["ALLOW"], error) {
    this.decisions = decisions;
    this.error = error;
    this.actions = [];
  }

  async decide(action) {
    this.actions.push(action);
    if (this.error) throw this.error;
    return result(this.decisions[Math.min(this.actions.length - 1, this.decisions.length - 1)]);
  }
}

function request(toolCall) {
  return { tool: { name: toolCall.name }, toolCall };
}

function graphFor(node) {
  return new StateGraph(MessagesAnnotation)
    .addNode("tools", node)
    .addEdge(START, "tools")
    .addEdge("tools", END)
    .compile();
}

function state(...toolCalls) {
  return { messages: [new AIMessage({ content: "", tool_calls: toolCalls })] };
}

test("native LangChain hook allows once and submits normalized evidence", async () => {
  const client = new FakeClient();
  const hook = createLatchToolCallHook(client);
  const executions = [];
  const call = { id: "call_search", name: "search", args: { query: "Kigali" }, type: "tool_call" };
  const output = await hook(request(call), async (received) => {
    executions.push(received);
    return "result";
  });
  assert.equal(output, "result");
  assert.equal(executions.length, 1);
  assert.deepEqual(client.actions[0], {
    tool: "search",
    arguments: { query: "Kigali" },
    metadata: {
      protocol: "langchain",
      surface: "langchain_agent",
      tool_call_id: "call_search",
      tool_call_kind: "function",
    },
  });
  await assert.rejects(hook(request(call), async () => "again"), LangChainReplayError);
});

test("native middleware factory uses installed LangChain v1", async () => {
  const client = new FakeClient();
  const middleware = await createLatchAgentMiddleware(client);
  assert.equal(middleware.name, "LatchSecurityMiddleware");
  assert.equal(typeof middleware.wrapToolCall, "function");
  const call = { id: "call_native", name: "lookup", args: { id: 7 }, type: "tool_call" };
  assert.equal(await middleware.wrapToolCall(request(call), async () => "ok"), "ok");
});

test("agent denial and Latch outage never reach the handler", async (t) => {
  for (const [client, expected] of [
    [new FakeClient(["BLOCK"]), LangChainNotAllowedError],
    [new FakeClient(["REQUIRE_APPROVAL"]), LangChainNotAllowedError],
    [new FakeClient(["ALLOW"], new Error("offline")), /offline/],
  ]) {
    await t.test(String(expected), async () => {
      let executions = 0;
      const hook = createLatchToolCallHook(client);
      await assert.rejects(
        hook(request({ id: "call_write", name: "write", args: { path: "report.txt" } }), async () => { executions++; }),
        expected,
      );
      assert.equal(executions, 0);
    });
  }
});

test("cyclic and accessor arguments fail without evaluating attacker getters", async () => {
  for (const kind of ["cycle", "accessor"]) {
    const client = new FakeClient();
    const hook = createLatchToolCallHook(client);
    const args = {};
    let getterReads = 0;
    if (kind === "cycle") args.self = args;
    else Object.defineProperty(args, "secret", {
      enumerable: true,
      get() { getterReads++; return "value"; },
    });
    await assert.rejects(
      hook(request({ id: `call_${kind}`, name: "write", args }), async () => assert.fail("handler ran")),
      LangChainProtocolError,
    );
    assert.equal(client.actions.length, 0);
    assert.equal(getterReads, 0);
  }
});

test("real LangGraph ToolNode executes a fully allowed parallel batch", async () => {
  const executions = [];
  const first = tool(async ({ value }) => {
    executions.push(["first", value]);
    return `first:${value}`;
  }, { name: "first", description: "Record first", schema: z.object({ value: z.number() }) });
  const second = tool(async ({ value }) => {
    executions.push(["second", value]);
    return `second:${value}`;
  }, { name: "second", description: "Record second", schema: z.object({ value: z.number() }) });
  const client = new FakeClient(["ALLOW", "ALLOW"]);
  const node = await createLatchToolNode([first, second], client);
  const output = await graphFor(node).invoke(state(
    { id: "call_first", name: "first", args: { value: 1 }, type: "tool_call" },
    { id: "call_second", name: "second", args: { value: 2 }, type: "tool_call" },
  ));
  assert.deepEqual(executions.sort(), [["first", 1], ["second", 2]]);
  assert.equal(output.messages.length, 3);
  assert.equal(client.actions.every((action) => action.metadata.surface === "langgraph_tool_node"), true);
});

test("mixed LangGraph batch executes no tools", async () => {
  let executions = 0;
  const first = tool(async ({ value }) => { executions++; return value; }, {
    name: "first", description: "First", schema: z.object({ value: z.number() }),
  });
  const second = tool(async ({ value }) => { executions++; return value; }, {
    name: "second", description: "Second", schema: z.object({ value: z.number() }),
  });
  const client = new FakeClient(["ALLOW", "BLOCK"]);
  const node = await createLatchToolNode([first, second], client);
  await assert.rejects(graphFor(node).invoke(state(
    { id: "call_batch_first", name: "first", args: { value: 1 }, type: "tool_call" },
    { id: "call_batch_second", name: "second", args: { value: 2 }, type: "tool_call" },
  )), LangChainNotAllowedError);
  assert.equal(executions, 0);
  assert.equal(client.actions.length, 2);
});

test("unknown, malformed, and duplicate graph calls fail before Latch", async (t) => {
  const executions = [];
  const safe = tool(async ({ value }) => { executions.push(value); return value; }, {
    name: "safe", description: "Safe", schema: z.object({ value: z.number().optional() }),
  });
  const cases = [
    [state({ id: "call_unknown", name: "missing", args: {}, type: "tool_call" }), UnknownLangChainToolError],
    [state({ id: "call_number", name: "safe", args: { value: 9_007_199_254_740_992 }, type: "tool_call" }), LangChainProtocolError],
    [state(
      { id: "call_same", name: "safe", args: { value: 1 }, type: "tool_call" },
      { id: "call_same", name: "safe", args: { value: 2 }, type: "tool_call" },
    ), LangChainReplayError],
  ];
  for (const [input, ErrorType] of cases) {
    await t.test(ErrorType.name, async () => {
      const client = new FakeClient();
      const node = await createLatchToolNode([safe], client);
      await assert.rejects(graphFor(node).invoke(input), ErrorType);
      assert.equal(client.actions.length, 0);
      assert.deepEqual(executions, []);
    });
  }
});

test("failed graph tool remains consumed", async () => {
  let executions = 0;
  const fail = tool(async () => {
    executions++;
    throw new Error("tool failed");
  }, { name: "fail", description: "Fail", schema: z.object({}) });
  const client = new FakeClient();
  const node = await createLatchToolNode([fail], client, { handleToolErrors: false });
  const input = state({ id: "call_fail", name: "fail", args: {}, type: "tool_call" });
  await assert.rejects(graphFor(node).invoke(input), /tool failed/);
  await assert.rejects(graphFor(node).invoke(input), LangChainReplayError);
  assert.equal(executions, 1);
});

test("compiled graph streaming preserves the protected ToolNode boundary", async () => {
  const executions = [];
  const safe = tool(async ({ value }) => { executions.push(value); return `safe:${value}`; }, {
    name: "safe", description: "Safe", schema: z.object({ value: z.number() }),
  });
  const client = new FakeClient();
  const node = await createLatchToolNode([safe], client);
  const snapshots = [];
  const stream = await graphFor(node).stream(
    state({ id: "call_stream", name: "safe", args: { value: 4 }, type: "tool_call" }),
    { streamMode: "values" },
  );
  for await (const snapshot of stream) snapshots.push(snapshot);
  assert.deepEqual(executions, [4]);
  assert.equal(snapshots.at(-1).messages.at(-1).content, "safe:4");
});

import assert from "node:assert/strict";
import test from "node:test";

import {
  Decision,
  OpenAIToolAdapter,
  OpenAIToolExecutionError,
  OpenAIToolNotAllowedError,
  OpenAIToolProtocolError,
  OpenAIToolReplayError,
  UnknownOpenAIToolError,
} from "../dist/index.js";

function result(value = "ALLOW") {
  return new Decision(
    "req_test0000",
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

test("Responses executes an allowed function and returns provider-native output", async () => {
  const client = new FakeClient();
  const received = [];
  const adapter = new OpenAIToolAdapter(client, {
    weather: (arguments_) => {
      received.push(arguments_);
      return { temperature: 24 };
    },
  });
  const outputs = await adapter.executeResponses({
    status: "completed",
    output: [
      { type: "reasoning", id: "reasoning_1" },
      { type: "function_call", call_id: "call_123", name: "weather", arguments: '{"city":"Kigali"}', status: "completed" },
    ],
  });
  assert.deepEqual(outputs, [{ type: "function_call_output", call_id: "call_123", output: '{"temperature":24}' }]);
  assert.deepEqual(received, [{ city: "Kigali" }]);
  assert.deepEqual(client.actions[0], {
    tool: "weather",
    arguments: { city: "Kigali" },
    metadata: {
      protocol: "openai-compatible",
      surface: "responses",
      tool_call_id: "call_123",
      tool_call_kind: "function",
    },
  });
});

test("Chat Completions executes only the selected choice", async () => {
  const client = new FakeClient();
  const adapter = new OpenAIToolAdapter(client, { lookup: (arguments_) => arguments_.value });
  const messages = await adapter.executeChatCompletion({
    choices: [
      { index: 0, message: { tool_calls: [{ id: "call_zero", type: "function", function: { name: "missing", arguments: "{}" } }] } },
      { index: 1, message: { tool_calls: [{ id: "call_one", type: "function", function: { name: "lookup", arguments: '{"value":7}' } }] } },
    ],
  }, { choiceIndex: 1 });
  assert.deepEqual(messages, [{ role: "tool", tool_call_id: "call_one", content: "7" }]);
});

test("mixed allow and deny batch executes no handlers", async () => {
  const client = new FakeClient(["ALLOW", "BLOCK"]);
  let executions = 0;
  const handler = () => { executions++; return "ok"; };
  const adapter = new OpenAIToolAdapter(client, { first: handler, second: handler });
  await assert.rejects(
    adapter.executeResponses({ output: [
      { type: "function_call", call_id: "call_first", name: "first", arguments: "{}" },
      { type: "function_call", call_id: "call_second", name: "second", arguments: "{}" },
    ] }),
    OpenAIToolNotAllowedError,
  );
  assert.equal(executions, 0);
  assert.equal(client.actions.length, 2);
});

test("invalid calls fail before a decision or side effect", async (t) => {
  const cases = [
    [{ output: [{ type: "function_call", call_id: "call_dup", name: "safe", arguments: '{"x":1,"x":2}' }] }, OpenAIToolProtocolError],
    [{ output: [{ type: "function_call", call_id: "call_unknown", name: "unknown", arguments: "{}" }] }, UnknownOpenAIToolError],
    [{ output: [{ type: "function_call", call_id: "call_number", name: "safe", arguments: '{"value":9007199254740992}' }] }, OpenAIToolProtocolError],
    [{ output: [{ type: "custom_tool_call", call_id: "call_custom", name: "shell", input: "hi" }] }, OpenAIToolProtocolError],
  ];
  for (const [response, ErrorType] of cases) {
    await t.test(ErrorType.name, async () => {
      const client = new FakeClient();
      let executions = 0;
      const adapter = new OpenAIToolAdapter(client, { safe: () => { executions++; } });
      await assert.rejects(adapter.executeResponses(response), ErrorType);
      assert.equal(client.actions.length, 0);
      assert.equal(executions, 0);
    });
  }
});

test("failed execution consumes the call ID", async () => {
  const client = new FakeClient();
  let executions = 0;
  const adapter = new OpenAIToolAdapter(client, {
    write: () => {
      executions++;
      throw new Error("disk unavailable");
    },
  });
  const response = { output: [{ type: "function_call", call_id: "call_write", name: "write", arguments: "{}" }] };
  await assert.rejects(adapter.executeResponses(response), OpenAIToolExecutionError);
  await assert.rejects(adapter.executeResponses(response), OpenAIToolReplayError);
  assert.equal(executions, 1);
});

test("Latch failure executes nothing", async () => {
  const client = new FakeClient(["ALLOW"], new Error("offline"));
  let executions = 0;
  const adapter = new OpenAIToolAdapter(client, { safe: () => { executions++; } });
  await assert.rejects(
    adapter.executeResponses({ output: [{ type: "function_call", call_id: "call_safe", name: "safe", arguments: "{}" }] }),
    /offline/,
  );
  assert.equal(executions, 0);
});

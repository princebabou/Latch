import assert from "node:assert/strict";
import test from "node:test";

import {
  Decision,
  AnthropicToolAdapter,
  AnthropicToolNotAllowedError,
  AnthropicToolProtocolError,
  AnthropicToolReplayError,
  UnknownAnthropicToolError,
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

function message(blocks, role = "assistant", type = "message") {
  return { type, role, content: blocks };
}

test("executes an allowed tool_use and returns tool_result blocks", async () => {
  const client = new FakeClient();
  const received = [];
  const adapter = new AnthropicToolAdapter(client, {
    weather: (input) => {
      received.push(input);
      return { temperature: 24 };
    },
  });
  const outputs = await adapter.executeMessage(
    message([
      { type: "text", text: "Checking." },
      { type: "tool_use", id: "toolu_123", name: "weather", input: { city: "Kigali" } },
    ]),
  );
  assert.deepEqual(outputs, [{ type: "tool_result", tool_use_id: "toolu_123", content: '{"temperature":24}' }]);
  assert.deepEqual(received, [{ city: "Kigali" }]);
  assert.equal(client.actions[0].metadata.protocol, "anthropic-messages");
  assert.equal(client.actions[0].metadata.tool_use_id, "toolu_123");
});

test("does not run a handler on a BLOCK decision", async () => {
  const client = new FakeClient(["BLOCK"]);
  let executed = false;
  const adapter = new AnthropicToolAdapter(client, {
    deploy: () => {
      executed = true;
    },
  });
  await assert.rejects(
    adapter.executeMessage(message([{ type: "tool_use", id: "toolu_deny", name: "deploy", input: { env: "prod" } }])),
    AnthropicToolNotAllowedError,
  );
  assert.equal(executed, false);
});

test("rejects an unknown tool before any decision or execution", async () => {
  const client = new FakeClient();
  let ran = false;
  const adapter = new AnthropicToolAdapter(client, { known: () => (ran = true) });
  await assert.rejects(
    adapter.executeMessage(
      message([
        { type: "tool_use", id: "toolu_a", name: "known", input: {} },
        { type: "tool_use", id: "toolu_b", name: "unknown", input: {} },
      ]),
    ),
    UnknownAnthropicToolError,
  );
  assert.equal(ran, false);
  assert.equal(client.actions.length, 0);
});

test("rejects duplicate tool_use ids in one message", async () => {
  const client = new FakeClient();
  const adapter = new AnthropicToolAdapter(client, { echo: (input) => input });
  await assert.rejects(
    adapter.executeMessage(
      message([
        { type: "tool_use", id: "toolu_same", name: "echo", input: {} },
        { type: "tool_use", id: "toolu_same", name: "echo", input: {} },
      ]),
    ),
    AnthropicToolReplayError,
  );
});

test("refuses replay of the same tool_use across messages", async () => {
  const client = new FakeClient();
  const adapter = new AnthropicToolAdapter(client, { echo: (input) => input });
  const once = message([{ type: "tool_use", id: "toolu_once", name: "echo", input: {} }]);
  await adapter.executeMessage(once);
  await assert.rejects(adapter.executeMessage(once), AnthropicToolReplayError);
});

test("rejects a non-assistant message", async () => {
  const client = new FakeClient();
  const adapter = new AnthropicToolAdapter(client, { echo: (input) => input });
  await assert.rejects(adapter.executeMessage(message([], "user")), AnthropicToolProtocolError);
});

test("returns no results when there are no tool_use blocks", async () => {
  const client = new FakeClient();
  const adapter = new AnthropicToolAdapter(client, { echo: (input) => input });
  const outputs = await adapter.executeMessage(message([{ type: "text", text: "Hello" }]));
  assert.deepEqual(outputs, []);
  assert.equal(client.actions.length, 0);
});

test("rejects a non-object tool_use input", async () => {
  const client = new FakeClient();
  const adapter = new AnthropicToolAdapter(client, { echo: (input) => input });
  await assert.rejects(
    adapter.executeMessage(message([{ type: "tool_use", id: "toolu_x", name: "echo", input: "not-an-object" }])),
    AnthropicToolProtocolError,
  );
});

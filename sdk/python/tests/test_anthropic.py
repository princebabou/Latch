import unittest
from types import SimpleNamespace

from latch_sdk import (
    AnthropicToolAdapter,
    AnthropicToolNotAllowedError,
    AnthropicToolProtocolError,
    AnthropicToolReplayError,
    UnknownAnthropicToolError,
)


class FakeClient:
    def __init__(self, decisions=None, error=None):
        self.decisions = list(decisions or ["ALLOW"])
        self.error = error
        self.actions = []

    def decide(self, action):
        self.actions.append(action)
        if self.error is not None:
            raise self.error
        index = min(len(self.actions) - 1, len(self.decisions) - 1)
        value = self.decisions[index]
        return SimpleNamespace(decision=value, allowed=value == "ALLOW", fail_closed=False)


def _message(blocks, role="assistant", message_type="message"):
    return {"type": message_type, "role": role, "content": blocks}


class AnthropicToolAdapterTests(unittest.TestCase):
    def test_executes_allowed_tool_use(self):
        client = FakeClient()
        received = []
        adapter = AnthropicToolAdapter(
            client,
            {"weather": lambda input_: received.append(input_) or {"temperature": 24}},
        )
        outputs = adapter.execute_message(
            _message(
                [
                    {"type": "text", "text": "Checking."},
                    {"type": "tool_use", "id": "toolu_123", "name": "weather", "input": {"city": "Kigali"}},
                ]
            )
        )
        self.assertEqual(
            outputs,
            [{"type": "tool_result", "tool_use_id": "toolu_123", "content": '{"temperature":24}'}],
        )
        self.assertEqual(received, [{"city": "Kigali"}])
        metadata = client.actions[0].metadata
        self.assertEqual(metadata["protocol"], "anthropic-messages")
        self.assertEqual(metadata["surface"], "messages")
        self.assertEqual(metadata["tool_use_id"], "toolu_123")

    def test_blocks_held_tool_use(self):
        client = FakeClient(decisions=["BLOCK"])
        executed = []
        adapter = AnthropicToolAdapter(client, {"deploy": lambda input_: executed.append(input_)})
        with self.assertRaises(AnthropicToolNotAllowedError):
            adapter.execute_message(
                _message([{"type": "tool_use", "id": "toolu_deny", "name": "deploy", "input": {"env": "prod"}}])
            )
        self.assertEqual(executed, [])

    def test_unknown_tool_rejected_before_execution(self):
        client = FakeClient()
        ran = []
        adapter = AnthropicToolAdapter(client, {"known": lambda input_: ran.append(input_) or "ok"})
        with self.assertRaises(UnknownAnthropicToolError):
            adapter.execute_message(
                _message(
                    [
                        {"type": "tool_use", "id": "toolu_a", "name": "known", "input": {}},
                        {"type": "tool_use", "id": "toolu_b", "name": "unknown", "input": {}},
                    ]
                )
            )
        self.assertEqual(ran, [])
        self.assertEqual(client.actions, [])

    def test_duplicate_ids_rejected(self):
        client = FakeClient()
        adapter = AnthropicToolAdapter(client, {"echo": lambda input_: input_})
        with self.assertRaises(AnthropicToolReplayError):
            adapter.execute_message(
                _message(
                    [
                        {"type": "tool_use", "id": "toolu_same", "name": "echo", "input": {}},
                        {"type": "tool_use", "id": "toolu_same", "name": "echo", "input": {}},
                    ]
                )
            )

    def test_replay_across_messages(self):
        client = FakeClient()
        adapter = AnthropicToolAdapter(client, {"echo": lambda input_: input_})
        message = _message([{"type": "tool_use", "id": "toolu_once", "name": "echo", "input": {}}])
        adapter.execute_message(message)
        with self.assertRaises(AnthropicToolReplayError):
            adapter.execute_message(message)

    def test_non_assistant_message_rejected(self):
        client = FakeClient()
        adapter = AnthropicToolAdapter(client, {"echo": lambda input_: input_})
        with self.assertRaises(AnthropicToolProtocolError):
            adapter.execute_message(_message([], role="user"))

    def test_no_tool_use_returns_empty(self):
        client = FakeClient()
        adapter = AnthropicToolAdapter(client, {"echo": lambda input_: input_})
        outputs = adapter.execute_message(_message([{"type": "text", "text": "Hi"}]))
        self.assertEqual(outputs, [])
        self.assertEqual(client.actions, [])

    def test_non_object_input_rejected(self):
        client = FakeClient()
        adapter = AnthropicToolAdapter(client, {"echo": lambda input_: input_})
        with self.assertRaises(AnthropicToolProtocolError):
            adapter.execute_message(
                _message([{"type": "tool_use", "id": "toolu_x", "name": "echo", "input": "not-an-object"}])
            )


if __name__ == "__main__":
    unittest.main()

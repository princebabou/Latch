import unittest
from types import SimpleNamespace

from latch_sdk import (
    OpenAIToolAdapter,
    OpenAIToolExecutionError,
    OpenAIToolNotAllowedError,
    OpenAIToolProtocolError,
    OpenAIToolReplayError,
    UnknownOpenAIToolError,
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


class OpenAIToolAdapterTests(unittest.TestCase):
    def test_responses_executes_allowed_function(self):
        client = FakeClient()
        received = []
        adapter = OpenAIToolAdapter(
            client,
            {"weather": lambda arguments: received.append(arguments) or {"temperature": 24}},
        )
        outputs = adapter.execute_responses(
            {
                "status": "completed",
                "output": [
                    {"type": "reasoning", "id": "reasoning_1"},
                    {
                        "type": "function_call",
                        "call_id": "call_123",
                        "name": "weather",
                        "arguments": '{"city":"Kigali"}',
                        "status": "completed",
                    },
                ],
            }
        )
        self.assertEqual(
            outputs,
            [{"type": "function_call_output", "call_id": "call_123", "output": '{"temperature":24}'}],
        )
        self.assertEqual(received, [{"city": "Kigali"}])
        action = client.actions[0]
        self.assertEqual(action.tool, "weather")
        self.assertEqual(action.arguments, {"city": "Kigali"})
        self.assertEqual(
            action.metadata,
            {
                "protocol": "openai-compatible",
                "surface": "responses",
                "tool_call_id": "call_123",
                "tool_call_kind": "function",
            },
        )

    def test_chat_completion_uses_selected_choice(self):
        client = FakeClient()
        adapter = OpenAIToolAdapter(client, {"lookup": lambda arguments: arguments["value"]})
        messages = adapter.execute_chat_completion(
            {
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "call_zero",
                                    "type": "function",
                                    "function": {"name": "missing", "arguments": "{}"},
                                }
                            ]
                        },
                    },
                    {
                        "index": 1,
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "call_one",
                                    "type": "function",
                                    "function": {"name": "lookup", "arguments": '{"value":7}'},
                                }
                            ]
                        },
                    },
                ]
            },
            choice_index=1,
        )
        self.assertEqual(messages, [{"role": "tool", "tool_call_id": "call_one", "content": "7"}])

    def test_batch_denial_executes_nothing(self):
        client = FakeClient(["ALLOW", "BLOCK"])
        executions = []

        def handler(arguments):
            executions.append(arguments)
            return "ok"

        adapter = OpenAIToolAdapter(client, {"first": handler, "second": handler})
        with self.assertRaises(OpenAIToolNotAllowedError):
            adapter.execute_responses(
                {
                    "output": [
                        {"type": "function_call", "call_id": "call_first", "name": "first", "arguments": "{}"},
                        {"type": "function_call", "call_id": "call_second", "name": "second", "arguments": "{}"},
                    ]
                }
            )
        self.assertEqual(executions, [])
        self.assertEqual(len(client.actions), 2)

    def test_invalid_calls_fail_before_decision_or_execution(self):
        cases = [
            (
                {"output": [{"type": "function_call", "call_id": "call_dup", "name": "safe", "arguments": '{"x":1,"x":2}'}]},
                OpenAIToolProtocolError,
            ),
            (
                {"output": [{"type": "function_call", "call_id": "call_unknown", "name": "unknown", "arguments": "{}"}]},
                UnknownOpenAIToolError,
            ),
            (
                {"output": [{"type": "function_call", "call_id": "call_number", "name": "safe", "arguments": '{"value":9007199254740992}'}]},
                OpenAIToolProtocolError,
            ),
            (
                {"output": [{"type": "custom_tool_call", "call_id": "call_custom", "name": "shell", "input": "hi"}]},
                OpenAIToolProtocolError,
            ),
        ]
        for response, error_type in cases:
            with self.subTest(error_type=error_type):
                client = FakeClient()
                executions = []
                adapter = OpenAIToolAdapter(client, {"safe": lambda arguments: executions.append(arguments)})
                with self.assertRaises(error_type):
                    adapter.execute_responses(response)
                self.assertEqual(client.actions, [])
                self.assertEqual(executions, [])

    def test_execution_failure_consumes_call_id(self):
        client = FakeClient()
        executions = []

        def fail(arguments):
            executions.append(arguments)
            raise RuntimeError("disk unavailable")

        adapter = OpenAIToolAdapter(client, {"write": fail})
        response = {
            "output": [
                {"type": "function_call", "call_id": "call_write", "name": "write", "arguments": "{}"}
            ]
        }
        with self.assertRaises(OpenAIToolExecutionError):
            adapter.execute_responses(response)
        with self.assertRaises(OpenAIToolReplayError):
            adapter.execute_responses(response)
        self.assertEqual(len(executions), 1)

    def test_latch_failure_executes_nothing(self):
        client = FakeClient(error=OSError("offline"))
        executions = []
        adapter = OpenAIToolAdapter(client, {"safe": lambda arguments: executions.append(arguments)})
        response = {
            "output": [{"type": "function_call", "call_id": "call_safe", "name": "safe", "arguments": "{}"}]
        }
        with self.assertRaises(OSError):
            adapter.execute_responses(response)
        self.assertEqual(executions, [])


if __name__ == "__main__":
    unittest.main()

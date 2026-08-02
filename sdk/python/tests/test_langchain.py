import asyncio
from types import SimpleNamespace
import unittest

try:
    from langchain.tools import tool
    from langchain.messages import AIMessage
    from langgraph.graph import END, START, MessagesState, StateGraph
    from latch_sdk.langchain import (
        LangChainNotAllowedError,
        LangChainProtocolError,
        LangChainReplayError,
        LatchAgentMiddleware,
        LatchToolNode,
        UnknownLangChainToolError,
    )
except ImportError as error:  # Allow the dependency-free base SDK suite.
    raise unittest.SkipTest(f"optional LangChain dependencies are not installed: {error}")


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
        return SimpleNamespace(decision=value, allowed=value == "ALLOW")


def request(call):
    return SimpleNamespace(tool=object(), tool_call=call)


def graph_for(node):
    builder = StateGraph(MessagesState)
    builder.add_node("tools", node)
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    return builder.compile()


class LatchAgentMiddlewareTests(unittest.TestCase):
    def test_allowed_call_reaches_handler_with_normalized_action(self):
        client = FakeClient()
        middleware = LatchAgentMiddleware(client)
        calls = []
        result = middleware.wrap_tool_call(
            request({"id": "call_search", "name": "search", "args": {"query": "Kigali"}}),
            lambda received: calls.append(received) or "result",
        )
        self.assertEqual(result, "result")
        self.assertEqual(len(calls), 1)
        self.assertEqual(client.actions[0].tool, "search")
        self.assertEqual(client.actions[0].arguments, {"query": "Kigali"})
        self.assertEqual(client.actions[0].metadata["surface"], "langchain_agent")

    def test_denial_and_latch_failure_never_reach_handler(self):
        for client, error_type in (
            (FakeClient(["BLOCK"]), LangChainNotAllowedError),
            (FakeClient(["REQUIRE_APPROVAL"]), LangChainNotAllowedError),
            (FakeClient(error=OSError("offline")), OSError),
        ):
            with self.subTest(error_type=error_type):
                executions = []
                middleware = LatchAgentMiddleware(client)
                with self.assertRaises(error_type):
                    middleware.wrap_tool_call(
                        request({"id": "call_write", "name": "write", "args": {"path": "report.txt"}}),
                        lambda received: executions.append(received),
                    )
                self.assertEqual(executions, [])

    def test_cyclic_arguments_fail_before_latch(self):
        client = FakeClient()
        middleware = LatchAgentMiddleware(client)
        arguments = {}
        arguments["self"] = arguments
        with self.assertRaises(LangChainProtocolError):
            middleware.wrap_tool_call(
                request({"id": "call_cycle", "name": "write", "args": arguments}),
                lambda received: self.fail("cyclic arguments reached the handler"),
            )
        self.assertEqual(client.actions, [])

    def test_async_middleware_and_replay_protection(self):
        async def run():
            client = FakeClient()
            middleware = LatchAgentMiddleware(client)
            received = request({"id": "call_async", "name": "lookup", "args": {"id": 7}})

            async def handler(value):
                return value.tool_call["args"]["id"]

            self.assertEqual(await middleware.awrap_tool_call(received, handler), 7)
            with self.assertRaises(LangChainReplayError):
                await middleware.awrap_tool_call(received, handler)

        asyncio.run(run())


class LatchToolNodeTests(unittest.TestCase):
    def setUp(self):
        self.executions = []

        @tool
        def first(value: int) -> str:
            """Record the first value."""
            self.executions.append(("first", value))
            return f"first:{value}"

        @tool
        def second(value: int) -> str:
            """Record the second value."""
            self.executions.append(("second", value))
            return f"second:{value}"

        self.tools = [first, second]

    @staticmethod
    def state(*calls):
        return {"messages": [AIMessage(content="", tool_calls=list(calls))]}

    def test_real_tool_node_executes_fully_allowed_batch(self):
        client = FakeClient(["ALLOW", "ALLOW"])
        node = LatchToolNode(self.tools, client)
        output = graph_for(node).invoke(
            self.state(
                {"id": "call_first", "name": "first", "args": {"value": 1}, "type": "tool_call"},
                {"id": "call_second", "name": "second", "args": {"value": 2}, "type": "tool_call"},
            )
        )
        self.assertCountEqual(self.executions, [("first", 1), ("second", 2)])
        self.assertEqual(len(output["messages"]), 3)
        self.assertTrue(all(action.metadata["surface"] == "langgraph_tool_node" for action in client.actions))

    def test_mixed_batch_executes_nothing(self):
        client = FakeClient(["ALLOW", "BLOCK"])
        node = LatchToolNode(self.tools, client)
        with self.assertRaises(LangChainNotAllowedError):
            graph_for(node).invoke(
                self.state(
                    {"id": "call_first", "name": "first", "args": {"value": 1}, "type": "tool_call"},
                    {"id": "call_second", "name": "second", "args": {"value": 2}, "type": "tool_call"},
                )
            )
        self.assertEqual(self.executions, [])
        self.assertEqual(len(client.actions), 2)

    def test_unknown_malformed_and_duplicate_calls_fail_before_decision(self):
        cases = [
            (
                self.state({"id": "call_unknown", "name": "missing", "args": {}, "type": "tool_call"}),
                UnknownLangChainToolError,
            ),
            (
                self.state({"id": "call_number", "name": "first", "args": {"value": 9_007_199_254_740_992}, "type": "tool_call"}),
                LangChainProtocolError,
            ),
            (
                self.state(
                    {"id": "call_same", "name": "first", "args": {"value": 1}, "type": "tool_call"},
                    {"id": "call_same", "name": "second", "args": {"value": 2}, "type": "tool_call"},
                ),
                LangChainReplayError,
            ),
        ]
        for state, error_type in cases:
            with self.subTest(error_type=error_type):
                client = FakeClient()
                node = LatchToolNode(self.tools, client)
                with self.assertRaises(error_type):
                    graph_for(node).invoke(state)
                self.assertEqual(client.actions, [])
                self.assertEqual(self.executions, [])

    def test_failed_execution_remains_consumed(self):
        executions = []

        @tool
        def fail(value: int) -> str:
            """Fail after recording an execution attempt."""
            executions.append(value)
            raise RuntimeError("tool failed")

        client = FakeClient()
        node = LatchToolNode([fail], client, handle_tool_errors=False)
        state = self.state({"id": "call_fail", "name": "fail", "args": {"value": 1}, "type": "tool_call"})
        with self.assertRaises(RuntimeError):
            graph_for(node).invoke(state)
        with self.assertRaises(LangChainReplayError):
            graph_for(node).invoke(state)
        self.assertEqual(executions, [1])

    def test_async_tool_node_path(self):
        async def run():
            client = FakeClient()
            node = LatchToolNode(self.tools, client)
            output = await graph_for(node).ainvoke(
                self.state({"id": "call_async_node", "name": "first", "args": {"value": 9}, "type": "tool_call"})
            )
            self.assertEqual(output["messages"][-1].content, "first:9")

        asyncio.run(run())

    def test_compiled_graph_stream_uses_protected_boundary(self):
        client = FakeClient()
        node = LatchToolNode(self.tools, client)
        snapshots = list(
            graph_for(node).stream(
                self.state({"id": "call_stream", "name": "first", "args": {"value": 4}, "type": "tool_call"}),
                stream_mode="values",
            )
        )
        self.assertEqual(self.executions, [("first", 4)])
        self.assertEqual(snapshots[-1]["messages"][-1].content, "first:4")


if __name__ == "__main__":
    unittest.main()

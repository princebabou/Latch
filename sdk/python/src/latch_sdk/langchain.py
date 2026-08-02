"""Native fail-closed integration for LangChain agents and LangGraph ToolNode."""

import asyncio
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
import json
import math
from threading import Lock
from typing import Any, Dict, List, Optional, Set

try:
    from langchain.agents.middleware import AgentMiddleware
    from langgraph.prebuilt import ToolNode
except ImportError as error:  # pragma: no cover - exercised without the optional extra
    raise ImportError(
        'LangChain support requires: pip install "latch-sdk[langchain]"'
    ) from error

from .errors import LatchError
from .models import Action, Decision


class LangChainProtocolError(LatchError):
    """A framework tool call was unsafe or did not satisfy the adapter contract."""


class LangChainReplayError(LatchError):
    def __init__(self, call_id: str) -> None:
        self.call_id = call_id
        super().__init__(f"LangChain tool call {call_id!r} was duplicated or replayed; execution stopped")


class LangChainNotAllowedError(LatchError):
    def __init__(self, call_id: str, tool: str, decision: Decision) -> None:
        self.call_id = call_id
        self.tool = tool
        self.decision = decision
        super().__init__(
            f"Latch decision for LangChain tool {tool!r} call {call_id!r} is "
            f"{decision.decision}; execution stopped"
        )


class UnknownLangChainToolError(LatchError):
    def __init__(self, call_id: str, tool: str) -> None:
        self.call_id = call_id
        self.tool = tool
        super().__init__(f"LangChain tool {tool!r} for call {call_id!r} is not registered; batch not executed")


class _ToolCall:
    __slots__ = ("call_id", "name", "arguments")

    def __init__(self, call_id: str, name: str, arguments: Dict[str, Any]) -> None:
        self.call_id = call_id
        self.name = name
        self.arguments = arguments


class LangChainToolGuard:
    """Framework-neutral guard used by both middleware and protected ToolNode."""

    def __init__(
        self,
        client: Any,
        *,
        max_calls: int = 128,
        max_argument_bytes: int = 1 << 20,
        replay_capacity: int = 10_000,
    ) -> None:
        if client is None or not callable(getattr(client, "decide", None)):
            raise TypeError("client must provide decide(action)")
        self._max_calls = _bounded_integer(max_calls, 1, 1024, "max_calls")
        self._max_argument_bytes = _bounded_integer(
            max_argument_bytes, 1, 16 << 20, "max_argument_bytes"
        )
        self._replay_capacity = _bounded_integer(replay_capacity, 128, 1_000_000, "replay_capacity")
        if self._replay_capacity < self._max_calls:
            raise ValueError("replay_capacity cannot be smaller than max_calls")
        self._client = client
        self._replayed: "OrderedDict[str, None]" = OrderedDict()
        self._replay_lock = Lock()

    def protect(
        self,
        raw_calls: Sequence[Any],
        *,
        surface: str,
        allowed_tools: Optional[Set[str]] = None,
    ) -> List[_ToolCall]:
        """Validate, authorize, and atomically consume a complete call batch."""
        if isinstance(raw_calls, (str, bytes, bytearray)) or not isinstance(raw_calls, Sequence):
            raise LangChainProtocolError("tool calls must be an array")
        if len(raw_calls) > self._max_calls:
            raise LangChainProtocolError(f"tool call batch exceeds {self._max_calls} calls")
        calls = [self._normalize_call(raw) for raw in raw_calls]
        seen: Set[str] = set()
        for call in calls:
            if call.call_id in seen:
                raise LangChainReplayError(call.call_id)
            seen.add(call.call_id)
            if allowed_tools is not None and call.name not in allowed_tools:
                raise UnknownLangChainToolError(call.call_id, call.name)
        for call in calls:
            decision = self._client.decide(
                Action(
                    tool=call.name,
                    arguments=call.arguments,
                    metadata={
                        "protocol": "langchain",
                        "surface": surface,
                        "tool_call_id": call.call_id,
                        "tool_call_kind": "function",
                    },
                )
            )
            if not decision.allowed:
                raise LangChainNotAllowedError(call.call_id, call.name, decision)
        self._reserve(calls)
        return calls

    async def aprotect(
        self,
        raw_calls: Sequence[Any],
        *,
        surface: str,
        allowed_tools: Optional[Set[str]] = None,
    ) -> List[_ToolCall]:
        return await asyncio.to_thread(
            self.protect, raw_calls, surface=surface, allowed_tools=allowed_tools
        )

    def _normalize_call(self, value: Any) -> _ToolCall:
        call = _mapping(value, "tool call")
        call_id = _call_id(call.get("id"))
        name = _tool_name(call.get("name"))
        arguments = _normalize_arguments(call.get("args"), self._max_argument_bytes, call_id)
        return _ToolCall(call_id, name, arguments)

    def _reserve(self, calls: Sequence[_ToolCall]) -> None:
        with self._replay_lock:
            for call in calls:
                if call.call_id in self._replayed:
                    raise LangChainReplayError(call.call_id)
            for call in calls:
                self._replayed[call.call_id] = None
            while len(self._replayed) > self._replay_capacity:
                self._replayed.popitem(last=False)


class LatchAgentMiddleware(AgentMiddleware):
    """Drop-in middleware for ``create_agent(..., middleware=[...])``."""

    def __init__(self, client: Any, **guard_options: Any) -> None:
        super().__init__()
        self._latch_guard = LangChainToolGuard(client, **guard_options)

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        if getattr(request, "tool", None) is None:
            raise LangChainProtocolError("tool call has no resolved LangChain tool")
        self._latch_guard.protect(
            [getattr(request, "tool_call", None)], surface="langchain_agent"
        )
        return handler(request)

    async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        if getattr(request, "tool", None) is None:
            raise LangChainProtocolError("tool call has no resolved LangChain tool")
        await self._latch_guard.aprotect(
            [getattr(request, "tool_call", None)], surface="langchain_agent"
        )
        return await handler(request)


class LatchToolNode(ToolNode):
    """LangGraph ToolNode that authorizes the full parallel batch first."""

    def __init__(
        self,
        tools: Sequence[Any],
        client: Any,
        *,
        latch_max_calls: int = 128,
        latch_max_argument_bytes: int = 1 << 20,
        latch_replay_capacity: int = 10_000,
        **kwargs: Any,
    ) -> None:
        super().__init__(tools, **kwargs)
        self._latch_guard = LangChainToolGuard(
            client,
            max_calls=latch_max_calls,
            max_argument_bytes=latch_max_argument_bytes,
            replay_capacity=latch_replay_capacity,
        )
        self._latch_messages_key = kwargs.get("messages_key", "messages")
        self._latch_allowed_tools = set(self.tools_by_name)

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        calls = _extract_tool_calls(input, self._latch_messages_key)
        self._latch_guard.protect(
            calls,
            surface="langgraph_tool_node",
            allowed_tools=self._latch_allowed_tools,
        )
        return super().invoke(input, config, **kwargs)

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        calls = _extract_tool_calls(input, self._latch_messages_key)
        await self._latch_guard.aprotect(
            calls,
            surface="langgraph_tool_node",
            allowed_tools=self._latch_allowed_tools,
        )
        return await super().ainvoke(input, config, **kwargs)


def _extract_tool_calls(value: Any, messages_key: str) -> Sequence[Any]:
    if isinstance(value, list):
        if not value:
            return []
        if all(isinstance(item, Mapping) and {"id", "name", "args"}.issubset(item) for item in value):
            return value
        message = value[-1]
    elif isinstance(value, Mapping):
        messages = value.get(messages_key)
        if not isinstance(messages, list) or not messages:
            raise LangChainProtocolError(f"LangGraph state must contain a non-empty {messages_key!r} list")
        message = messages[-1]
    else:
        messages = getattr(value, messages_key, None)
        if not isinstance(messages, list) or not messages:
            raise LangChainProtocolError(f"LangGraph state must contain a non-empty {messages_key!r} list")
        message = messages[-1]
    calls = message.get("tool_calls") if isinstance(message, Mapping) else getattr(message, "tool_calls", None)
    if calls is None:
        return []
    if isinstance(calls, (str, bytes, bytearray)) or not isinstance(calls, Sequence):
        raise LangChainProtocolError("the last message tool_calls value must be an array")
    return calls


def _normalize_arguments(value: Any, limit: int, call_id: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise LangChainProtocolError(f"arguments for call {call_id!r} must be an object")
    normalized = _normalize_json(value, set())
    try:
        payload = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise LangChainProtocolError(f"arguments for call {call_id!r} are not interoperable JSON: {error}") from error
    if len(payload) > limit:
        raise LangChainProtocolError(f"arguments for call {call_id!r} exceed {limit} bytes")
    return normalized


def _normalize_json(value: Any, ancestors: Set[int]) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        _validate_unicode(value, "JSON string")
        return value
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise LangChainProtocolError("JSON integer is outside the interoperable safe range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise LangChainProtocolError("JSON number is outside the finite range")
        if value.is_integer() and abs(value) > 9_007_199_254_740_991:
            raise LangChainProtocolError("JSON integer-valued number is outside the interoperable safe range")
        return value
    if isinstance(value, (list, dict)):
        identity = id(value)
        if identity in ancestors:
            raise LangChainProtocolError("JSON arguments cannot contain cycles")
        ancestors.add(identity)
        try:
            if isinstance(value, list):
                return [_normalize_json(item, ancestors) for item in value]
            result: Dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise LangChainProtocolError("JSON object keys must be strings")
                _validate_unicode(key, "JSON object key")
                result[key] = _normalize_json(item, ancestors)
            return result
        finally:
            ancestors.remove(identity)
    raise LangChainProtocolError(f"unsupported JSON argument type {type(value).__name__}")


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise LangChainProtocolError(f"{name} must be an object")
    return value


def _call_id(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise LangChainProtocolError("tool call id must be 1-256 visible ASCII characters")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise LangChainProtocolError("tool call id must be 1-256 visible ASCII characters")
    return value


def _tool_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LangChainProtocolError("tool name must be a non-empty string")
    _validate_unicode(value, "tool name")
    if len(value.encode("utf-8")) > 256:
        raise LangChainProtocolError("tool name cannot exceed 256 UTF-8 bytes")
    return value


def _validate_unicode(value: str, name: str) -> None:
    if any(ord(character) == 0xFFFD or 0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise LangChainProtocolError(f"{name} cannot contain replacement or unpaired-surrogate characters")


def _bounded_integer(value: Any, minimum: int, maximum: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


__all__ = [
    "LangChainNotAllowedError",
    "LangChainProtocolError",
    "LangChainReplayError",
    "LangChainToolGuard",
    "LatchAgentMiddleware",
    "LatchToolNode",
    "UnknownLangChainToolError",
]

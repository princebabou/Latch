"""Fail-closed adapter for completed Anthropic Messages API tool_use blocks."""

from collections import OrderedDict
from dataclasses import dataclass
import json
from threading import Lock
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from .errors import LatchError
from .models import Action, Decision
from .openai import _validate_json, _validate_unicode

AnthropicToolHandler = Callable[[Mapping[str, Any]], Any]


class AnthropicToolProtocolError(LatchError):
    """A completed message did not satisfy the protected tool_use contract."""


class UnknownAnthropicToolError(LatchError):
    def __init__(self, tool_use_id: str, tool: str) -> None:
        self.tool_use_id = tool_use_id
        self.tool = tool
        super().__init__(
            f"Anthropic tool {tool!r} for tool_use {tool_use_id!r} has no registered handler; batch not executed"
        )


class AnthropicToolReplayError(LatchError):
    def __init__(self, tool_use_id: str) -> None:
        self.tool_use_id = tool_use_id
        super().__init__(f"Anthropic tool_use {tool_use_id!r} was duplicated or replayed; batch not executed")


class AnthropicToolNotAllowedError(LatchError):
    def __init__(self, tool_use_id: str, tool: str, decision: Decision) -> None:
        self.tool_use_id = tool_use_id
        self.tool = tool
        self.decision = decision
        super().__init__(
            f"Latch decision for Anthropic tool {tool!r} tool_use {tool_use_id!r} is {decision.decision}; batch not executed"
        )


class AnthropicToolExecutionError(LatchError):
    def __init__(self, tool_use_id: str, tool: str, cause: Exception) -> None:
        self.tool_use_id = tool_use_id
        self.tool = tool
        self.cause = cause
        super().__init__(f"execute Anthropic tool {tool!r} tool_use {tool_use_id!r}: {cause}")


@dataclass(frozen=True)
class _ToolUse:
    tool_use_id: str
    name: str
    input: Mapping[str, Any]


class AnthropicToolAdapter:
    """Protect Anthropic Messages API tool_use blocks with Latch.

    Every tool_use block is parsed, resolved to a handler, and allowed before
    any handler starts. Block IDs are then atomically consumed, so redelivery
    of the same assistant message cannot repeat a side effect.
    """

    def __init__(
        self,
        client: Any,
        handlers: Mapping[str, AnthropicToolHandler],
        *,
        max_calls: int = 128,
        max_input_bytes: int = 1 << 20,
        max_output_bytes: int = 4 << 20,
        replay_capacity: int = 10_000,
    ) -> None:
        if client is None or not callable(getattr(client, "decide", None)):
            raise TypeError("client must provide decide(action)")
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or not 1 <= max_calls <= 1024:
            raise ValueError("max_calls must be between 1 and 1024")
        if not 1 <= max_input_bytes <= 16 << 20:
            raise ValueError("max_input_bytes must be between 1 and 16777216")
        if not 1 <= max_output_bytes <= 64 << 20:
            raise ValueError("max_output_bytes must be between 1 and 67108864")
        if not 128 <= replay_capacity <= 1_000_000 or replay_capacity < max_calls:
            raise ValueError("replay_capacity must be between 128 and 1000000 and at least max_calls")
        copied: Dict[str, AnthropicToolHandler] = {}
        for name, handler in handlers.items():
            _validate_name(name)
            if not callable(handler):
                raise TypeError(f"handler {name!r} must be callable")
            copied[name] = handler
        self._client = client
        self._handlers = copied
        self._max_calls = max_calls
        self._max_input_bytes = max_input_bytes
        self._max_output_bytes = max_output_bytes
        self._replay_capacity = replay_capacity
        self._replayed: "OrderedDict[str, None]" = OrderedDict()
        self._replay_lock = Lock()

    def execute_message(self, message: Any) -> List[Mapping[str, str]]:
        """Execute tool_use blocks from one completed assistant message.

        Returns tool_result content blocks to append to a new user message.
        """
        message_type = _field(message, "type", required=False)
        if message_type is not None and message_type != "message":
            raise AnthropicToolProtocolError("payload is not a Messages API message")
        role = _field(message, "role", required=False)
        if role is not None and role != "assistant":
            raise AnthropicToolProtocolError("only assistant messages carry tool_use blocks")
        calls: List[_ToolUse] = []
        for block in _array(_field(message, "content"), "message.content"):
            if _field(block, "type") != "tool_use":
                continue
            calls.append(
                self._parse_tool_use(
                    _field(block, "id"), _field(block, "name"), _field(block, "input")
                )
            )
        results = self._execute(calls)
        return [
            {"type": "tool_result", "tool_use_id": call.tool_use_id, "content": results[index]}
            for index, call in enumerate(calls)
        ]

    def _parse_tool_use(self, tool_use_id: Any, name: Any, raw_input: Any) -> _ToolUse:
        _validate_tool_use_id(tool_use_id)
        _validate_name(name)
        if not isinstance(raw_input, Mapping):
            raise AnthropicToolProtocolError(f"input for tool_use {tool_use_id!r} must be an object")
        try:
            serialized = json.dumps(raw_input, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise AnthropicToolProtocolError(f"input for tool_use {tool_use_id!r} is invalid: {error}") from error
        if len(serialized.encode("utf-8")) > self._max_input_bytes:
            raise AnthropicToolProtocolError(
                f"input for tool_use {tool_use_id!r} exceeds {self._max_input_bytes} bytes"
            )
        input_object = dict(raw_input)
        try:
            _validate_json(input_object)
        except ValueError as error:
            raise AnthropicToolProtocolError(f"input for tool_use {tool_use_id!r} is invalid: {error}") from error
        return _ToolUse(tool_use_id, name, input_object)

    def _execute(self, calls: Sequence[_ToolUse]) -> List[str]:
        if len(calls) > self._max_calls:
            raise AnthropicToolProtocolError(f"tool_use batch exceeds {self._max_calls} blocks")
        seen = set()
        for call in calls:
            if call.tool_use_id in seen:
                raise AnthropicToolReplayError(call.tool_use_id)
            seen.add(call.tool_use_id)
            if call.name not in self._handlers:
                raise UnknownAnthropicToolError(call.tool_use_id, call.name)
        for call in calls:
            decision = self._client.decide(
                Action(
                    tool=call.name,
                    arguments=call.input,
                    metadata={
                        "protocol": "anthropic-messages",
                        "surface": "messages",
                        "tool_use_id": call.tool_use_id,
                        "tool_call_kind": "tool_use",
                    },
                )
            )
            if not decision.allowed:
                raise AnthropicToolNotAllowedError(call.tool_use_id, call.name, decision)
        self._reserve(calls)
        outputs: List[str] = []
        for call in calls:
            try:
                value = self._handlers[call.name](call.input)
                outputs.append(self._encode_output(value))
            except AnthropicToolExecutionError:
                raise
            except Exception as error:
                raise AnthropicToolExecutionError(call.tool_use_id, call.name, error) from error
        return outputs

    def _reserve(self, calls: Sequence[_ToolUse]) -> None:
        with self._replay_lock:
            for call in calls:
                if call.tool_use_id in self._replayed:
                    raise AnthropicToolReplayError(call.tool_use_id)
            for call in calls:
                self._replayed[call.tool_use_id] = None
            while len(self._replayed) > self._replay_capacity:
                self._replayed.popitem(last=False)

    def _encode_output(self, value: Any) -> str:
        if isinstance(value, str):
            encoded = value
        else:
            encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > self._max_output_bytes:
            raise ValueError(f"tool output exceeds {self._max_output_bytes} bytes")
        return encoded


def _field(value: Any, name: str, *, required: bool = True) -> Any:
    if isinstance(value, Mapping):
        if name in value:
            return value[name]
    elif hasattr(value, name):
        return getattr(value, name)
    if required:
        raise AnthropicToolProtocolError(f"required field {name!r} is missing")
    return None


def _array(value: Any, name: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise AnthropicToolProtocolError(f"{name} must be an array")
    return value


def _validate_tool_use_id(value: Any) -> None:
    if not isinstance(value, str):
        raise AnthropicToolProtocolError("tool_use id must be 1-256 UTF-8 bytes")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise AnthropicToolProtocolError("tool_use id must contain visible ASCII only")
    if not 1 <= len(value) <= 256:
        raise AnthropicToolProtocolError("tool_use id must be 1-256 UTF-8 bytes")


def _validate_name(value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AnthropicToolProtocolError("tool name must be 1-256 UTF-8 bytes")
    try:
        _validate_unicode(value, "tool name")
    except ValueError as error:
        raise AnthropicToolProtocolError("tool name must contain valid interoperable Unicode") from error
    if len(value.encode("utf-8")) > 256:
        raise AnthropicToolProtocolError("tool name must be 1-256 UTF-8 bytes")

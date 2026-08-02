"""Fail-closed adapters for completed OpenAI-compatible function calls."""

from collections import OrderedDict
from dataclasses import dataclass
import json
import math
from threading import Lock
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from .errors import LatchError
from .models import Action, Decision

OpenAIToolHandler = Callable[[Mapping[str, Any]], Any]


class OpenAIToolProtocolError(LatchError):
    """A completed provider response did not satisfy the protected contract."""


class UnknownOpenAIToolError(LatchError):
    def __init__(self, call_id: str, tool: str) -> None:
        self.call_id = call_id
        self.tool = tool
        super().__init__(f"OpenAI tool {tool!r} for call {call_id!r} has no registered handler; batch not executed")


class OpenAIToolReplayError(LatchError):
    def __init__(self, call_id: str) -> None:
        self.call_id = call_id
        super().__init__(f"OpenAI tool call {call_id!r} was duplicated or replayed; batch not executed")


class OpenAIToolNotAllowedError(LatchError):
    def __init__(self, call_id: str, tool: str, decision: Decision) -> None:
        self.call_id = call_id
        self.tool = tool
        self.decision = decision
        super().__init__(
            f"Latch decision for OpenAI tool {tool!r} call {call_id!r} is {decision.decision}; batch not executed"
        )


class OpenAIToolExecutionError(LatchError):
    def __init__(self, call_id: str, tool: str, cause: Exception) -> None:
        self.call_id = call_id
        self.tool = tool
        self.cause = cause
        super().__init__(f"execute OpenAI tool {tool!r} call {call_id!r}: {cause}")


@dataclass(frozen=True)
class _ToolCall:
    call_id: str
    name: str
    arguments: Mapping[str, Any]
    surface: str


class OpenAIToolAdapter:
    """Protect Responses API and Chat Completions function calls with Latch.

    Every call is parsed, resolved, and allowed before any handler starts. Call
    IDs are then atomically consumed, so duplicate delivery cannot repeat a
    side effect accidentally.
    """

    def __init__(
        self,
        client: Any,
        handlers: Mapping[str, OpenAIToolHandler],
        *,
        max_calls: int = 128,
        max_argument_bytes: int = 1 << 20,
        max_output_bytes: int = 4 << 20,
        replay_capacity: int = 10_000,
    ) -> None:
        if client is None or not callable(getattr(client, "decide", None)):
            raise TypeError("client must provide decide(action)")
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or not 1 <= max_calls <= 1024:
            raise ValueError("max_calls must be between 1 and 1024")
        if not 1 <= max_argument_bytes <= 16 << 20:
            raise ValueError("max_argument_bytes must be between 1 and 16777216")
        if not 1 <= max_output_bytes <= 64 << 20:
            raise ValueError("max_output_bytes must be between 1 and 67108864")
        if not 128 <= replay_capacity <= 1_000_000 or replay_capacity < max_calls:
            raise ValueError("replay_capacity must be between 128 and 1000000 and at least max_calls")
        copied: Dict[str, OpenAIToolHandler] = {}
        for name, handler in handlers.items():
            _validate_name(name)
            if not callable(handler):
                raise TypeError(f"handler {name!r} must be callable")
            copied[name] = handler
        self._client = client
        self._handlers = copied
        self._max_calls = max_calls
        self._max_argument_bytes = max_argument_bytes
        self._max_output_bytes = max_output_bytes
        self._replay_capacity = replay_capacity
        self._replayed: "OrderedDict[str, None]" = OrderedDict()
        self._replay_lock = Lock()

    def execute_responses(self, response: Any) -> List[Mapping[str, str]]:
        """Execute function calls from one assembled, completed Responses result."""
        status = _field(response, "status", required=False)
        if status is not None and status != "completed":
            raise OpenAIToolProtocolError("Responses payload must be completed before execution")
        calls: List[_ToolCall] = []
        for item in _array(_field(response, "output"), "response.output"):
            kind = _field(item, "type")
            if kind == "custom_tool_call":
                raise OpenAIToolProtocolError("custom tools are not supported by this function-tool adapter")
            if kind != "function_call":
                continue
            item_status = _field(item, "status", required=False)
            if item_status is not None and item_status != "completed":
                raise OpenAIToolProtocolError("function call must be completed before execution")
            calls.append(
                self._parse_call(
                    _field(item, "call_id"), _field(item, "name"), _field(item, "arguments"), "responses"
                )
            )
        results = self._execute(calls)
        return [
            {"type": "function_call_output", "call_id": call.call_id, "output": results[index]}
            for index, call in enumerate(calls)
        ]

    def execute_chat_completion(self, completion: Any, *, choice_index: int = 0) -> List[Mapping[str, str]]:
        """Execute function calls from one selected completed Chat choice."""
        if isinstance(choice_index, bool) or not isinstance(choice_index, int) or choice_index < 0:
            raise ValueError("choice_index must be a non-negative integer")
        selected: Optional[Any] = None
        for choice in _array(_field(completion, "choices"), "completion.choices"):
            if _field(choice, "index") == choice_index:
                selected = choice
                break
        if selected is None:
            raise OpenAIToolProtocolError(f"Chat Completions choice {choice_index} was not found")
        message = _field(selected, "message")
        raw_calls = _field(message, "tool_calls", required=False)
        calls: List[_ToolCall] = []
        if raw_calls is not None:
            for item in _array(raw_calls, "choice.message.tool_calls"):
                kind = _field(item, "type")
                if kind != "function":
                    raise OpenAIToolProtocolError(f"unsupported Chat Completions tool call type {kind!r}")
                function = _field(item, "function")
                calls.append(
                    self._parse_call(
                        _field(item, "id"),
                        _field(function, "name"),
                        _field(function, "arguments"),
                        "chat_completions",
                    )
                )
        results = self._execute(calls)
        return [
            {"role": "tool", "tool_call_id": call.call_id, "content": results[index]}
            for index, call in enumerate(calls)
        ]

    def _parse_call(self, call_id: Any, name: Any, raw_arguments: Any, surface: str) -> _ToolCall:
        _validate_call_id(call_id)
        _validate_name(name)
        if not isinstance(raw_arguments, str):
            raise OpenAIToolProtocolError(f"arguments for call {call_id!r} must be a JSON string")
        try:
            _validate_unicode(raw_arguments, "arguments JSON")
        except ValueError as error:
            raise OpenAIToolProtocolError(f"arguments for call {call_id!r} are invalid: {error}") from error
        if len(raw_arguments.encode("utf-8")) > self._max_argument_bytes:
            raise OpenAIToolProtocolError(
                f"arguments for call {call_id!r} exceed {self._max_argument_bytes} bytes"
            )
        try:
            arguments = json.loads(
                raw_arguments,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
                parse_float=_finite_float,
                parse_int=_safe_integer,
            )
        except (json.JSONDecodeError, UnicodeError, ValueError) as error:
            raise OpenAIToolProtocolError(f"arguments for call {call_id!r} are invalid: {error}") from error
        if not isinstance(arguments, dict):
            raise OpenAIToolProtocolError(f"arguments for call {call_id!r} must decode to an object")
        try:
            _validate_json(arguments)
        except ValueError as error:
            raise OpenAIToolProtocolError(f"arguments for call {call_id!r} are invalid: {error}") from error
        return _ToolCall(call_id, name, arguments, surface)

    def _execute(self, calls: Sequence[_ToolCall]) -> List[str]:
        if len(calls) > self._max_calls:
            raise OpenAIToolProtocolError(f"tool call batch exceeds {self._max_calls} calls")
        seen = set()
        for call in calls:
            if call.call_id in seen:
                raise OpenAIToolReplayError(call.call_id)
            seen.add(call.call_id)
            if call.name not in self._handlers:
                raise UnknownOpenAIToolError(call.call_id, call.name)
        for call in calls:
            decision = self._client.decide(
                Action(
                    tool=call.name,
                    arguments=call.arguments,
                    metadata={
                        "protocol": "openai-compatible",
                        "surface": call.surface,
                        "tool_call_id": call.call_id,
                        "tool_call_kind": "function",
                    },
                )
            )
            if not decision.allowed:
                raise OpenAIToolNotAllowedError(call.call_id, call.name, decision)
        self._reserve(calls)
        outputs: List[str] = []
        for call in calls:
            try:
                value = self._handlers[call.name](call.arguments)
                outputs.append(self._encode_output(value))
            except OpenAIToolExecutionError:
                raise
            except Exception as error:
                raise OpenAIToolExecutionError(call.call_id, call.name, error) from error
        return outputs

    def _reserve(self, calls: Sequence[_ToolCall]) -> None:
        with self._replay_lock:
            for call in calls:
                if call.call_id in self._replayed:
                    raise OpenAIToolReplayError(call.call_id)
            for call in calls:
                self._replayed[call.call_id] = None
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
        raise OpenAIToolProtocolError(f"required field {name!r} is missing")
    return None


def _array(value: Any, name: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise OpenAIToolProtocolError(f"{name} must be an array")
    return value


def _validate_call_id(value: Any) -> None:
    if not isinstance(value, str):
        raise OpenAIToolProtocolError("tool call id must be 1-256 UTF-8 bytes")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise OpenAIToolProtocolError("tool call id must contain visible ASCII only")
    if not 1 <= len(value) <= 256:
        raise OpenAIToolProtocolError("tool call id must be 1-256 UTF-8 bytes")


def _validate_name(value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise OpenAIToolProtocolError("function name must be 1-256 UTF-8 bytes")
    try:
        _validate_unicode(value, "function name")
    except ValueError as error:
        raise OpenAIToolProtocolError("function name must contain valid interoperable Unicode") from error
    if len(value.encode("utf-8")) > 256:
        raise OpenAIToolProtocolError("function name must be 1-256 UTF-8 bytes")


def _unique_object(pairs: Sequence[Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        _validate_unicode(key, "JSON object key")
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON constant {value!r}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON number is outside the finite range")
    if parsed.is_integer() and abs(parsed) > 9_007_199_254_740_991:
        raise ValueError("JSON integer-valued number is outside the interoperable safe range")
    return parsed


def _safe_integer(value: str) -> int:
    parsed = int(value)
    if abs(parsed) > 9_007_199_254_740_991:
        raise ValueError("JSON integer is outside the interoperable safe range")
    return parsed


def _validate_unicode(value: str, name: str) -> None:
    if any(ord(character) == 0xFFFD or 0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError(f"{name} cannot contain replacement or unpaired-surrogate characters")


def _validate_json(value: Any) -> None:
    if isinstance(value, str):
        _validate_unicode(value, "JSON string")
    elif isinstance(value, list):
        for item in value:
            _validate_json(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_unicode(key, "JSON object key")
            _validate_json(item)

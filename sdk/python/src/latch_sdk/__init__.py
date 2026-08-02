"""Official fail-closed Python client for Latch."""

from .client import LatchClient
from .errors import APIError, LatchError, LatchUnavailable, NotAllowedError, ProtocolError
from .models import (
    API_VERSION,
    MEDIA_TYPE,
    Action,
    Decision,
    Identity,
    PolicyResult,
    Risk,
)
from .openai import (
    OpenAIToolAdapter,
    OpenAIToolExecutionError,
    OpenAIToolNotAllowedError,
    OpenAIToolProtocolError,
    OpenAIToolReplayError,
    UnknownOpenAIToolError,
)
from .shell import (
    ShellExecutionError,
    ShellExecutor,
    ShellNotAllowedError,
    ShellProtocolError,
    ShellReplayError,
    ShellResult,
)

__all__ = [
    "APIError",
    "API_VERSION",
    "Action",
    "Decision",
    "Identity",
    "LatchClient",
    "LatchError",
    "LatchUnavailable",
    "MEDIA_TYPE",
    "NotAllowedError",
    "OpenAIToolAdapter",
    "OpenAIToolExecutionError",
    "OpenAIToolNotAllowedError",
    "OpenAIToolProtocolError",
    "OpenAIToolReplayError",
    "PolicyResult",
    "ProtocolError",
    "Risk",
    "ShellExecutionError",
    "ShellExecutor",
    "ShellNotAllowedError",
    "ShellProtocolError",
    "ShellReplayError",
    "ShellResult",
    "UnknownOpenAIToolError",
]

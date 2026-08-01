"""Latch SDK error types."""

from typing import Optional


class LatchError(Exception):
    """Base class for errors that must stop action execution."""


class LatchUnavailable(LatchError):
    """The enforcement service could not be reached safely."""


class ProtocolError(LatchError):
    """The server response did not satisfy the stable v1 contract."""


class APIError(LatchError):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        super().__init__(f"Latch API rejected the request ({status_code} {code}): {message}")


class NotAllowedError(LatchError):
    def __init__(self, decision: "Optional[object]" = None) -> None:
        self.decision = decision
        value = getattr(decision, "decision", "UNKNOWN")
        super().__init__(f"Latch decision is {value}; action not executed")

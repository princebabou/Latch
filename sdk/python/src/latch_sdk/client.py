"""Synchronous, dependency-free Latch API client."""

import json
import secrets
import socket
from typing import Any, Callable, Mapping, Optional, TypeVar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .errors import APIError, LatchUnavailable, ProtocolError
from .models import API_VERSION, MEDIA_TYPE, Action, Decision, parse_decision

T = TypeVar("T")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class LatchClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:7070",
        *,
        token: Optional[str] = None,
        timeout: float = 2.0,
        max_response_bytes: int = 1 << 20,
    ) -> None:
        self._endpoint = _decision_endpoint(base_url)
        if token is not None and not token.strip():
            raise ValueError("token cannot be empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_response_bytes < 1024 or max_response_bytes > 16 << 20:
            raise ValueError("response limit must be between 1024 and 16777216 bytes")
        self._token = token
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        self._opener = build_opener(_NoRedirect())

    def decide(self, action: Action) -> Decision:
        request_id = "req_" + secrets.token_hex(16)
        body = json.dumps(
            {"api_version": API_VERSION, "request_id": request_id, "action": action.as_dict()},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        headers = {
            "Accept": MEDIA_TYPE,
            "Content-Type": MEDIA_TYPE,
            "User-Agent": "latch-python/0.2",
        }
        if self._token is not None:
            headers["Authorization"] = "Bearer " + self._token
        request = Request(self._endpoint, data=body, headers=headers, method="POST")
        try:
            response = self._opener.open(request, timeout=self._timeout)
            with response:
                payload = self._read_bounded(response)
                if response.status != 200:
                    raise _decode_api_error(response.status, payload)
                content_type = response.headers.get_content_type()
                if content_type not in (MEDIA_TYPE, "application/json"):
                    raise ProtocolError("invalid Latch response; action not executed: unexpected content type")
        except HTTPError as error:
            payload = self._read_bounded(error)
            raise _decode_api_error(error.code, payload) from None
        except (URLError, TimeoutError, socket.timeout, OSError) as error:
            raise LatchUnavailable(f"Latch is unavailable; action not executed: {error}") from error
        try:
            decoded = json.loads(payload.decode("utf-8"))
            return parse_decision(decoded, request_id)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ProtocolError(f"invalid Latch response; action not executed: {error}") from error

    def guard(self, action: Action, execute: Callable[[], T]) -> T:
        if not callable(execute):
            raise TypeError("execute must be callable")
        self.decide(action).require_allow()
        return execute()

    def _read_bounded(self, response: Any) -> bytes:
        payload = response.read(self._max_response_bytes + 1)
        if len(payload) > self._max_response_bytes:
            raise ProtocolError(
                f"invalid Latch response; action not executed: response exceeds {self._max_response_bytes} bytes"
            )
        return payload


def _decision_endpoint(raw: str) -> str:
    parsed = urlsplit(raw.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("base_url must be an absolute HTTP or HTTPS URL")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("base_url cannot contain credentials, a query, or a fragment")
    path = parsed.path.rstrip("/")
    if not path:
        path = "/v1/decisions"
    elif path != "/v1/decisions":
        raise ValueError("base_url path must be empty or /v1/decisions")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _decode_api_error(status: int, payload: bytes) -> APIError:
    try:
        decoded: Mapping[str, Any] = json.loads(payload.decode("utf-8"))
        if decoded.get("api_version") == API_VERSION and isinstance(decoded.get("error"), dict):
            error = decoded["error"]
            code = error.get("code")
            message = error.get("message")
            if isinstance(code, str) and isinstance(message, str):
                return APIError(status, code, message)
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        pass
    return APIError(status, "http_error", "request failed")

import json
import os
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Iterator

from latch_sdk import (
    APIError,
    API_VERSION,
    MEDIA_TYPE,
    Action,
    LatchClient,
    LatchUnavailable,
    NotAllowedError,
    ProtocolError,
)


def decision_payload(request_id: str, decision: str = "ALLOW") -> dict[str, Any]:
    return {
        "api_version": API_VERSION,
        "request_id": request_id,
        "decision": decision,
        "risk": {"score": 0, "level": "LOW"},
        "identity": {"verified": True},
        "policy": {"decision_source": "test", "hard_deny": False},
    }


@contextmanager
def test_server(callback: Callable[[BaseHTTPRequestHandler], None]) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            callback(self)

        def log_message(self, _format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def send_json(handler: BaseHTTPRequestHandler, value: Any, status: int = 200, content_type: str = MEDIA_TYPE) -> None:
    body = json.dumps(value).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class LatchClientTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("LATCH_TEST_URL"), "LATCH_TEST_URL is not set")
    def test_client_against_live_api(self) -> None:
        decision = LatchClient(
            os.environ["LATCH_TEST_URL"], token=os.environ.get("LATCH_API_TOKEN")
        ).decide(Action("filesystem.read", {"path": "./README.md"}))
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.identity.verified)

    def test_decide_sends_contract_and_authentication(self) -> None:
        def callback(handler: BaseHTTPRequestHandler) -> None:
            self.assertEqual(handler.path, "/v1/decisions")
            self.assertEqual(handler.headers["Authorization"], "Bearer secret")
            self.assertEqual(handler.headers["Content-Type"], MEDIA_TYPE)
            size = int(handler.headers["Content-Length"])
            request = json.loads(handler.rfile.read(size))
            send_json(handler, decision_payload(request["request_id"]))

        with test_server(callback) as url:
            decision = LatchClient(url, token="secret").decide(Action("filesystem.read", {"path": "./README.md"}))
        self.assertTrue(decision.allowed)

    def test_guard_executes_only_allow(self) -> None:
        for outcome in ("ALLOW", "BLOCK", "REQUIRE_APPROVAL"):
            with self.subTest(outcome=outcome):
                def callback(handler: BaseHTTPRequestHandler, selected: str = outcome) -> None:
                    size = int(handler.headers["Content-Length"])
                    request = json.loads(handler.rfile.read(size))
                    send_json(handler, decision_payload(request["request_id"], selected))

                executed = []
                with test_server(callback) as url:
                    client = LatchClient(url)
                    if outcome == "ALLOW":
                        result = client.guard(Action("safe.tool"), lambda: executed.append(True) or "done")
                        self.assertEqual(result, "done")
                    else:
                        with self.assertRaises(NotAllowedError):
                            client.guard(Action("unsafe.tool"), lambda: executed.append(True))
                self.assertEqual(bool(executed), outcome == "ALLOW")

    def test_http_error_and_unavailable_fail_closed(self) -> None:
        def callback(handler: BaseHTTPRequestHandler) -> None:
            send_json(handler, {"api_version": API_VERSION, "error": {"code": "unauthorized", "message": "denied"}}, 401)

        with test_server(callback) as url:
            with self.assertRaises(APIError):
                LatchClient(url).decide(Action("safe.tool"))
        with self.assertRaises(LatchUnavailable):
            LatchClient("http://127.0.0.1:1", timeout=0.1).decide(Action("safe.tool"))

    def test_malformed_mismatched_and_oversized_responses_fail_closed(self) -> None:
        callbacks = (
            lambda handler: send_json(handler, "not a decision"),
            lambda handler: send_json(handler, decision_payload("req_wrong000")),
            lambda handler: send_json(handler, {"padding": "x" * 2048}),
        )
        for index, callback in enumerate(callbacks):
            with self.subTest(index=index), test_server(callback) as url:
                client = LatchClient(url, max_response_bytes=1024)
                with self.assertRaises(ProtocolError):
                    client.decide(Action("safe.tool"))

    def test_redirect_is_not_followed(self) -> None:
        def callback(handler: BaseHTTPRequestHandler) -> None:
            handler.send_response(307)
            handler.send_header("Location", "https://example.invalid")
            handler.end_headers()

        with test_server(callback) as url:
            with self.assertRaises(APIError):
                LatchClient(url).decide(Action("safe.tool"))


if __name__ == "__main__":
    unittest.main()

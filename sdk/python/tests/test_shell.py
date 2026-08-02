import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from latch_sdk import (
    Action,
    ShellExecutionError,
    ShellExecutor,
    ShellNotAllowedError,
    ShellProtocolError,
    ShellReplayError,
)
from latch_sdk.models import Decision, Identity, PolicyResult, Risk


def decision(value="ALLOW", fail_closed=False):
    return Decision(
        "req_test",
        value,
        Risk(0, "low"),
        Identity(True),
        PolicyResult("test", False),
        fail_closed,
    )


class FakeClient:
    def __init__(self, verdict="ALLOW", error=None, after=None):
        self.verdict = verdict
        self.error = error
        self.after = after
        self.actions = []

    def decide(self, action: Action):
        self.actions.append(action)
        if self.after is not None:
            self.after()
        if self.error is not None:
            raise self.error
        return decision(self.verdict)


class ShellExecutorTests(unittest.TestCase):
    def test_structured_command_allowed_and_normalized(self):
        client = FakeClient()
        executor = ShellExecutor(client)
        code = "import os,sys; print(','.join(sys.argv[1:])+'|'+os.environ['LATCH_VALUE']+'|'+sys.stdin.read(), end='')"
        result = executor.run(
            "exec_python_001",
            sys.executable,
            ("-c", code, "one", "two"),
            env={"LATCH_VALUE": "secret-value"},
            stdin="payload",
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout_text, "one,two|secret-value|payload")
        action = client.actions[0]
        self.assertEqual((action.tool, action.operation), ("shell.exec", "execute"))
        self.assertEqual(action.metadata["surface"], "argv")
        self.assertTrue(Path(action.resource).is_absolute())
        encoded = json.dumps(action.as_dict())
        self.assertNotIn("secret-value", encoded)
        self.assertNotIn("payload", encoded)
        self.assertTrue(action.arguments["environment_sha256"])
        self.assertTrue(action.arguments["stdin_sha256"])

    def test_block_approval_and_outage_start_nothing(self):
        cases = (
            (FakeClient("BLOCK"), ShellNotAllowedError),
            (FakeClient("REQUIRE_APPROVAL"), ShellNotAllowedError),
            (FakeClient(error=RuntimeError("offline")), RuntimeError),
        )
        for client, expected in cases:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as directory:
                    marker = Path(directory, "started")
                    code = "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('started')"
                    executor = ShellExecutor(client)
                    with self.assertRaises(expected):
                        executor.run("exec_denied_001", sys.executable, ("-c", code, str(marker)))
                    self.assertFalse(marker.exists())

    def test_replay_and_failed_process_stay_consumed(self):
        client = FakeClient()
        executor = ShellExecutor(client)
        command = ("exec_replay_001", sys.executable, ("-c", "raise SystemExit(7)"))
        with self.assertRaises(ShellExecutionError):
            executor.run(*command)
        with self.assertRaises(ShellReplayError):
            executor.run(*command)
        self.assertEqual(len(client.actions), 1)

    def test_timeout_and_output_limit(self):
        timeout_executor = ShellExecutor(FakeClient(), timeout=0.05)
        with self.assertRaises(ShellExecutionError) as timeout:
            timeout_executor.run("exec_timeout_001", sys.executable, ("-c", "import time; time.sleep(2)"))
        self.assertIsInstance(timeout.exception.cause, TimeoutError)

        output_executor = ShellExecutor(FakeClient(), max_output_bytes=1024)
        with self.assertRaises(ShellExecutionError) as output:
            output_executor.run("exec_output_001", sys.executable, ("-c", "print('x'*4096, end='')"))
        self.assertEqual(len(output.exception.result.stdout), 1024)

    def test_changed_executable_and_environment_conflict_fail_before_start(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory, Path(sys.executable).name)
            shutil.copy2(sys.executable, copied)
            copied.chmod(0o700)

            def mutate():
                with copied.open("ab") as executable:
                    executable.write(b"changed")

            executor = ShellExecutor(FakeClient(after=mutate))
            with self.assertRaises(ShellProtocolError):
                executor.run("exec_changed_001", str(copied))

        conflict_client = FakeClient()
        conflict_executor = ShellExecutor(conflict_client)
        with self.assertRaises(ShellProtocolError):
            conflict_executor.run(
                "exec_env_conflict",
                sys.executable,
                env={"LATCH_VALUE": "one"},
                unset_env=("LATCH_VALUE",),
            )
        self.assertEqual(conflict_client.actions, [])

    def test_explicit_shell_command(self):
        client = FakeClient()
        result = ShellExecutor(client).run_shell("exec_script_001", "echo shell-ok")
        self.assertIn("shell-ok", result.stdout_text)
        self.assertEqual(client.actions[0].arguments["command"], "echo shell-ok")
        self.assertEqual(client.actions[0].metadata["surface"], "shell")


if __name__ == "__main__":
    unittest.main()

"""Fail-closed local process execution with an explicit Latch boundary."""

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from threading import Event, Lock, Thread
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .errors import LatchError
from .models import Action, Decision

_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class ShellProtocolError(LatchError):
    """The requested process could not be represented safely."""


class ShellReplayError(LatchError):
    def __init__(self, execution_id: str) -> None:
        self.execution_id = execution_id
        super().__init__(f"shell execution {execution_id!r} was duplicated or replayed; process not executed")


class ShellNotAllowedError(LatchError):
    def __init__(self, execution_id: str, decision: Decision) -> None:
        self.execution_id = execution_id
        self.decision = decision
        super().__init__(
            f"Latch decision for shell execution {execution_id!r} is {decision.decision}; process not executed"
        )


class ShellExecutionError(LatchError):
    def __init__(self, execution_id: str, cause: BaseException, result: Optional["ShellResult"] = None) -> None:
        self.execution_id = execution_id
        self.cause = cause
        self.result = result
        super().__init__(f"execute allowed shell action {execution_id!r}: {cause}")


@dataclass(frozen=True)
class ShellResult:
    decision: Decision
    exit_code: int
    stdout: bytes
    stderr: bytes

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", errors="strict")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="strict")


@dataclass(frozen=True)
class _PreparedCommand:
    execution_id: str
    mode: str
    executable: str
    executable_sha256: str
    args: Tuple[str, ...]
    cwd: str
    environment: Mapping[str, str]
    stdin: bytes
    action: Action


class ShellExecutor:
    """Starts local processes only after an explicit, valid Latch ALLOW."""

    def __init__(
        self,
        client: Any,
        *,
        timeout: float = 30.0,
        max_input_bytes: int = 1 << 20,
        max_output_bytes: int = 4 << 20,
        replay_capacity: int = 10_000,
    ) -> None:
        if client is None or not callable(getattr(client, "decide", None)):
            raise TypeError("client must provide decide(action)")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 86_400:
            raise ValueError("timeout must be between 0 and 86400 seconds")
        if isinstance(max_input_bytes, bool) or not isinstance(max_input_bytes, int) or not 0 <= max_input_bytes <= 16 << 20:
            raise ValueError("max_input_bytes must be between 0 and 16777216")
        if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int) or not 1024 <= max_output_bytes <= 64 << 20:
            raise ValueError("max_output_bytes must be between 1024 and 67108864")
        if isinstance(replay_capacity, bool) or not isinstance(replay_capacity, int) or not 128 <= replay_capacity <= 1_000_000:
            raise ValueError("replay_capacity must be between 128 and 1000000")
        self._client = client
        self._timeout = float(timeout)
        self._max_input_bytes = max_input_bytes
        self._max_output_bytes = max_output_bytes
        self._replay_capacity = replay_capacity
        self._replayed: "OrderedDict[str, None]" = OrderedDict()
        self._replay_lock = Lock()

    def run(
        self,
        execution_id: str,
        executable: str,
        args: Sequence[str] = (),
        *,
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        unset_env: Sequence[str] = (),
        clear_env: bool = False,
        stdin: str = "",
    ) -> ShellResult:
        """Execute a structured argv command without invoking a command shell."""
        prepared = self._prepare(
            execution_id,
            "argv",
            executable,
            args,
            None,
            cwd,
            env,
            unset_env,
            clear_env,
            stdin,
        )
        return self._execute(prepared)

    def run_shell(
        self,
        execution_id: str,
        command: str,
        *,
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        unset_env: Sequence[str] = (),
        clear_env: bool = False,
        stdin: str = "",
    ) -> ShellResult:
        """Execute explicit shell text through the platform system shell."""
        _validate_text(command, "shell command", 1 << 20, allow_empty=False)
        if os.name == "nt":
            shell_name = "cmd.exe"
            args = ("/d", "/s", "/c", command)
        else:
            shell_name = "sh"
            args = ("-c", command)
        prepared = self._prepare(
            execution_id,
            "shell",
            shell_name,
            args,
            command,
            cwd,
            env,
            unset_env,
            clear_env,
            stdin,
        )
        return self._execute(prepared)

    def _prepare(
        self,
        execution_id: str,
        mode: str,
        executable: str,
        args: Sequence[str],
        shell_command: Optional[str],
        cwd: Optional[str],
        env: Optional[Mapping[str, str]],
        unset_env: Sequence[str],
        clear_env: bool,
        stdin: str,
    ) -> _PreparedCommand:
        if not isinstance(execution_id, str) or _EXECUTION_ID.fullmatch(execution_id) is None:
            raise ShellProtocolError("execution ID must be 8-128 safe ASCII characters")
        with self._replay_lock:
            if execution_id in self._replayed:
                raise ShellReplayError(execution_id)
        resolved_executable = _resolve_executable(executable)
        executable_sha256 = _file_sha256(resolved_executable)
        resolved_cwd = _resolve_directory(cwd)
        validated_args = _validate_args(args)
        stdin_bytes = _utf8(stdin, "stdin", self._max_input_bytes, allow_empty=True)
        environment, environment_sha256, changes = _prepare_environment(env, unset_env, clear_env)
        arguments: Dict[str, Any] = {
            "execution_id": execution_id,
            "mode": mode,
            "executable": resolved_executable,
            "executable_sha256": executable_sha256,
            "args": list(validated_args),
            "cwd": resolved_cwd,
            "clear_environment": bool(clear_env),
            "environment_sha256": environment_sha256,
            "environment_changes": changes,
            "stdin_sha256": hashlib.sha256(stdin_bytes).hexdigest(),
            "stdin_bytes": len(stdin_bytes),
            "timeout_ms": int(self._timeout * 1000),
        }
        if mode == "shell":
            arguments["command"] = shell_command
        else:
            arguments["command"] = [resolved_executable, *validated_args]
        action = Action(
            tool="shell.exec",
            operation="execute",
            resource=resolved_executable,
            arguments=arguments,
            metadata={"protocol": "local-process", "surface": mode, "platform": sys.platform},
        )
        return _PreparedCommand(
            execution_id,
            mode,
            resolved_executable,
            executable_sha256,
            validated_args,
            resolved_cwd,
            environment,
            stdin_bytes,
            action,
        )

    def _execute(self, prepared: _PreparedCommand) -> ShellResult:
        decision = self._client.decide(prepared.action)
        if not decision.allowed:
            raise ShellNotAllowedError(prepared.execution_id, decision)
        if _file_sha256(prepared.executable) != prepared.executable_sha256:
            raise ShellProtocolError("executable changed after approval; process not executed")
        if _resolve_directory(prepared.cwd) != prepared.cwd:
            raise ShellProtocolError("working directory changed after approval; process not executed")
        self._reserve(prepared.execution_id)
        try:
            process = subprocess.Popen(
                [prepared.executable, *prepared.args],
                cwd=prepared.cwd,
                env=dict(prepared.environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except BaseException as error:
            raise ShellExecutionError(prepared.execution_id, error) from error

        stdout = bytearray()
        stderr = bytearray()
        overflow = Event()

        def drain(stream: Any, output: bytearray) -> None:
            try:
                while True:
                    chunk = stream.read(64 << 10)
                    if not chunk:
                        return
                    remaining = self._max_output_bytes - len(output)
                    if remaining > 0:
                        output.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow.set()
                        try:
                            process.kill()
                        except OSError:
                            pass
                        return
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

        def write_input() -> None:
            if process.stdin is None:
                return
            try:
                if prepared.stdin:
                    process.stdin.write(prepared.stdin)
                    process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass

        readers = (
            Thread(target=drain, args=(process.stdout, stdout), daemon=True),
            Thread(target=drain, args=(process.stderr, stderr), daemon=True),
        )
        writer = Thread(target=write_input, daemon=True)
        for thread in readers:
            thread.start()
        writer.start()
        timed_out = False
        try:
            exit_code = process.wait(timeout=self._timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            exit_code = process.wait()
        writer.join(timeout=1)
        for thread in readers:
            thread.join(timeout=1)
        result = ShellResult(decision, exit_code, bytes(stdout), bytes(stderr))
        if timed_out:
            raise ShellExecutionError(prepared.execution_id, TimeoutError("process timed out"), result)
        if overflow.is_set():
            raise ShellExecutionError(
                prepared.execution_id,
                ValueError(f"process output exceeds {self._max_output_bytes} bytes per stream"),
                result,
            )
        if exit_code != 0:
            raise ShellExecutionError(
                prepared.execution_id,
                subprocess.CalledProcessError(exit_code, [prepared.executable, *prepared.args]),
                result,
            )
        return result

    def _reserve(self, execution_id: str) -> None:
        with self._replay_lock:
            if execution_id in self._replayed:
                raise ShellReplayError(execution_id)
            self._replayed[execution_id] = None
            while len(self._replayed) > self._replay_capacity:
                self._replayed.popitem(last=False)


def _resolve_executable(value: str) -> str:
    _validate_text(value, "executable", 16 << 10, allow_empty=False)
    found = shutil.which(value)
    if found is None:
        raise ShellProtocolError(f"executable {value!r} could not be resolved")
    try:
        resolved = Path(found).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ShellProtocolError(f"executable path could not be resolved: {error}") from error
    if not resolved.is_file():
        raise ShellProtocolError("executable must be a regular file")
    return str(resolved)


def _resolve_directory(value: Optional[str]) -> str:
    raw = os.getcwd() if value is None or value == "" else value
    _validate_text(raw, "working directory", 16 << 10, allow_empty=False)
    try:
        resolved = Path(raw).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ShellProtocolError(f"working directory could not be resolved: {error}") from error
    if not resolved.is_dir():
        raise ShellProtocolError("working directory must be an existing directory")
    return str(resolved)


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as executable:
            for chunk in iter(lambda: executable.read(1 << 20), b""):
                digest.update(chunk)
    except OSError as error:
        raise ShellProtocolError(f"executable could not be fingerprinted: {error}") from error
    return digest.hexdigest()


def _validate_args(args: Sequence[str]) -> Tuple[str, ...]:
    if type(args) not in (list, tuple):
        raise ShellProtocolError("args must be a plain list or tuple of strings")
    if len(args) > 4096:
        raise ShellProtocolError("argv cannot exceed 4096 arguments")
    result = []
    total = 0
    for index, argument in enumerate(args):
        if not isinstance(argument, str):
            raise ShellProtocolError(f"argv[{index}] must be a string")
        encoded = _utf8(argument, f"argv[{index}]", 1 << 20, allow_empty=True)
        total += len(encoded)
        if total > 4 << 20:
            raise ShellProtocolError("argv exceeds 4194304 bytes")
        result.append(argument)
    return tuple(result)


def _prepare_environment(
    overrides: Optional[Mapping[str, str]], unset: Sequence[str], clear: bool
) -> Tuple[Mapping[str, str], str, Sequence[Mapping[str, Any]]]:
    if not isinstance(clear, bool):
        raise ShellProtocolError("clear_env must be a boolean")
    if overrides is None:
        overrides = {}
    if type(overrides) is not dict:
        raise ShellProtocolError("env must be a plain dictionary")
    if type(unset) not in (list, tuple):
        raise ShellProtocolError("unset_env must be a plain list or tuple")
    values: Dict[str, str] = {} if clear else dict(os.environ)
    canonical = {_environment_key(name): name for name in values}
    changed = set()
    changes = []
    for name, value in overrides.items():
        _validate_environment_name(name)
        if not isinstance(value, str):
            raise ShellProtocolError(f"environment value for {name!r} must be a string")
        encoded = _utf8(value, f"environment value for {name!r}", 1 << 20, allow_empty=True)
        key = _environment_key(name)
        if key in changed:
            raise ShellProtocolError(f"environment variable {name!r} is changed more than once")
        changed.add(key)
        old = canonical.get(key)
        if old is not None:
            values.pop(old, None)
        values[name] = value
        canonical[key] = name
        changes.append({"name": name, "value_sha256": hashlib.sha256(encoded).hexdigest(), "value_bytes": len(encoded)})
    for name in unset:
        _validate_environment_name(name)
        key = _environment_key(name)
        if key in changed:
            raise ShellProtocolError(f"environment variable {name!r} is changed more than once")
        changed.add(key)
        old = canonical.pop(key, None)
        if old is not None:
            values.pop(old, None)
        changes.append({"name": name, "unset": True})
    if len(values) > 16_384:
        raise ShellProtocolError("environment snapshot exceeds 16384 variables")
    entries = [f"{name}={values[name]}" for name in sorted(values)]
    try:
        encoded_snapshot = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except UnicodeError as error:
        raise ShellProtocolError("environment snapshot contains invalid Unicode") from error
    changes.sort(key=lambda item: item["name"])
    return dict(values), hashlib.sha256(encoded_snapshot).hexdigest(), tuple(changes)


def _environment_key(name: str) -> str:
    return name.upper() if os.name == "nt" else name


def _validate_environment_name(name: Any) -> None:
    if not isinstance(name, str) or not name or len(name.encode("utf-8", errors="ignore")) > 1024:
        raise ShellProtocolError(f"environment variable name {name!r} is invalid")
    if "=" in name or "\x00" in name:
        raise ShellProtocolError(f"environment variable name {name!r} is invalid")
    _utf8(name, "environment variable name", 1024, allow_empty=False)


def _validate_text(value: Any, name: str, limit: int, *, allow_empty: bool) -> None:
    _utf8(value, name, limit, allow_empty=allow_empty)


def _utf8(value: Any, name: str, limit: int, *, allow_empty: bool) -> bytes:
    if not isinstance(value, str):
        raise ShellProtocolError(f"{name} must be a string")
    if not allow_empty and not value.strip():
        raise ShellProtocolError(f"{name} cannot be empty")
    if "\x00" in value or "\ufffd" in value or any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ShellProtocolError(f"{name} must contain valid interoperable UTF-8 without NUL bytes")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ShellProtocolError(f"{name} must contain valid interoperable UTF-8") from error
    if len(encoded) > limit:
        raise ShellProtocolError(f"{name} exceeds {limit} bytes")
    return encoded

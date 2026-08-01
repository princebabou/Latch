"""Stable latch.security/v1 data types."""

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .errors import NotAllowedError

API_VERSION = "latch.security/v1"
MEDIA_TYPE = "application/vnd.latch.decision.v1+json"
ALLOW = "ALLOW"
BLOCK = "BLOCK"
REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True)
class Action:
    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    agent_id: Optional[str] = None
    operation: Optional[str] = None
    resource: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        if not isinstance(self.tool, str) or not self.tool.strip():
            raise ValueError("tool is required")
        result: Dict[str, Any] = {"tool": self.tool, "arguments": dict(self.arguments)}
        if self.agent_id:
            result["agent_id"] = self.agent_id
        if self.operation:
            result["operation"] = self.operation
        if self.resource:
            result["resource"] = self.resource
        if self.metadata:
            result["metadata"] = dict(self.metadata)
        return result


@dataclass(frozen=True)
class Risk:
    score: int
    level: str
    signals: Tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class Identity:
    verified: bool
    source: Optional[str] = None
    canonical_agent_id: Optional[str] = None
    matched_capabilities: Tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyResult:
    decision_source: str
    hard_deny: bool
    unsafe_override: bool = False
    triggered_rules: Tuple[str, ...] = ()
    reasons: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    request_id: str
    decision: str
    risk: Risk
    identity: Identity
    policy: PolicyResult
    fail_closed: bool = False
    budgets: Tuple[Mapping[str, Any], ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW and not self.fail_closed

    def require_allow(self) -> "Decision":
        if not self.allowed:
            raise NotAllowedError(self)
        return self


def parse_decision(payload: Any, request_id: str) -> Decision:
    root = _mapping(payload, "response")
    _required(root, "api_version", "request_id", "decision", "risk", "identity", "policy")
    if root["api_version"] != API_VERSION:
        raise ValueError(f"unsupported api_version {root['api_version']!r}")
    if root["request_id"] != request_id:
        raise ValueError("response request_id does not match the request")
    decision = _string(root["decision"], "decision")
    if decision not in (ALLOW, BLOCK, REQUIRE_APPROVAL):
        raise ValueError(f"unknown decision {decision!r}")
    fail_closed = root.get("fail_closed", False)
    if not isinstance(fail_closed, bool):
        raise ValueError("fail_closed must be a boolean")

    risk_data = _mapping(root["risk"], "risk")
    _required(risk_data, "score", "level")
    score = _integer(risk_data["score"], "risk.score")
    level = _string(risk_data["level"], "risk.level")
    if score < 0 or score > 100 or not level.strip():
        raise ValueError("risk evidence is invalid")

    identity_data = _mapping(root["identity"], "identity")
    _required(identity_data, "verified")
    verified = identity_data["verified"]
    if not isinstance(verified, bool):
        raise ValueError("identity.verified must be a boolean")

    policy_data = _mapping(root["policy"], "policy")
    _required(policy_data, "decision_source", "hard_deny")
    source = _string(policy_data["decision_source"], "policy.decision_source")
    hard_deny = policy_data["hard_deny"]
    if not isinstance(hard_deny, bool) or not source.strip():
        raise ValueError("policy evidence is invalid")
    unsafe_override = policy_data.get("unsafe_override", False)
    if not isinstance(unsafe_override, bool):
        raise ValueError("policy.unsafe_override must be a boolean")
    if decision == ALLOW and fail_closed:
        raise ValueError("fail_closed response cannot allow execution")

    return Decision(
        request_id=request_id,
        decision=decision,
        fail_closed=fail_closed,
        risk=Risk(score, level, _mapping_sequence(risk_data.get("signals", ()), "risk.signals")),
        identity=Identity(
            verified,
            _optional_string(identity_data.get("source"), "identity.source"),
            _optional_string(identity_data.get("canonical_agent_id"), "identity.canonical_agent_id"),
            _string_sequence(identity_data.get("matched_capabilities", ()), "identity.matched_capabilities"),
        ),
        policy=PolicyResult(
            source,
            hard_deny,
            unsafe_override,
            _string_sequence(policy_data.get("triggered_rules", ()), "policy.triggered_rules"),
            _string_sequence(policy_data.get("reasons", ()), "policy.reasons"),
        ),
        budgets=_mapping_sequence(root.get("budgets", ()), "budgets"),
    )


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _required(value: Mapping[str, Any], *fields: str) -> None:
    for field_name in fields:
        if field_name not in value:
            raise ValueError(f"required response field {field_name!r} is missing")


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _optional_string(value: Any, name: str) -> Optional[str]:
    if value is None:
        return None
    return _string(value, name)


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    return value


def _sequence(value: Any, name: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be an array")
    return value


def _string_sequence(value: Any, name: str) -> Tuple[str, ...]:
    return tuple(_string(item, name) for item in _sequence(value, name))


def _mapping_sequence(value: Any, name: str) -> Tuple[Mapping[str, Any], ...]:
    return tuple(_mapping(item, name) for item in _sequence(value, name))

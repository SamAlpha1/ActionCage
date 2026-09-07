"""Deterministic, dependency-free policy evaluation for tool calls."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from hashlib import sha256
import json
from pathlib import Path
import re
import tomllib
from typing import Any, Mapping


VALID_EFFECTS = {"allow", "review", "deny"}
EFFECT_WEIGHT = {"allow": 0, "review": 1, "deny": 2}


class PolicyError(ValueError):
    """Raised when policy input is invalid or ambiguous."""


@dataclass(frozen=True, slots=True)
class Decision:
    decision: str
    rule_id: str | None
    reason: str
    call_sha256: str
    policy_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_policy(path: str | Path) -> dict[str, Any]:
    with Path(path).open("rb") as handle:
        policy = tomllib.load(handle)
    validate_policy(policy)
    return policy


def validate_policy(policy: Mapping[str, Any]) -> None:
    defaults = policy.get("defaults", {})
    default = defaults.get("decision", "review")
    if default not in VALID_EFFECTS:
        raise PolicyError(f"invalid default decision: {default!r}")

    seen: set[str] = set()
    for index, rule in enumerate(policy.get("rules", [])):
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise PolicyError(f"rules[{index}] requires a non-empty id")
        if rule_id in seen:
            raise PolicyError(f"duplicate rule id: {rule_id}")
        seen.add(rule_id)
        if rule.get("effect") not in VALID_EFFECTS:
            raise PolicyError(f"rule {rule_id!r} has invalid effect")
        for path, pattern in rule.get("argument_regex", {}).items():
            try:
                re.compile(pattern)
            except re.error as exc:
                raise PolicyError(f"rule {rule_id!r}, {path!r}: {exc}") from exc


def _canonical_hash(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _get_path(value: Any, dotted_path: str) -> Any:
    current = value
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _matches(rule: Mapping[str, Any], call: Mapping[str, Any]) -> bool:
    tool = str(call.get("tool", ""))
    patterns = rule.get("tools", ["*"])
    if not any(fnmatchcase(tool, pattern) for pattern in patterns):
        return False

    for path, expected in rule.get("argument_equals", {}).items():
        if _get_path(call.get("arguments", {}), path) != expected:
            return False

    for path, pattern in rule.get("argument_regex", {}).items():
        actual = _get_path(call.get("arguments", {}), path)
        if actual is None or re.search(pattern, str(actual)) is None:
            return False
    return True


def evaluate(policy: Mapping[str, Any], call: Mapping[str, Any]) -> Decision:
    """Evaluate a call. Highest priority wins; deny wins equal-priority ties."""
    validate_policy(policy)
    if not isinstance(call.get("tool"), str) or not call["tool"].strip():
        raise PolicyError("call requires a non-empty string field: tool")
    arguments = call.get("arguments", {})
    if not isinstance(arguments, Mapping):
        raise PolicyError("call.arguments must be an object")

    matches = [rule for rule in policy.get("rules", []) if _matches(rule, call)]
    if matches:
        rule = max(
            matches,
            key=lambda item: (
                int(item.get("priority", 0)),
                EFFECT_WEIGHT[item["effect"]],
            ),
        )
        effect = rule["effect"]
        return Decision(
            decision=effect,
            rule_id=rule["id"],
            reason=rule.get("reason", f"matched rule {rule['id']}"),
            call_sha256=_canonical_hash(call),
            policy_version=str(policy.get("policy", {}).get("version", "unversioned")),
        )

    default = policy.get("defaults", {}).get("decision", "review")
    return Decision(
        decision=default,
        rule_id=None,
        reason="no rule matched",
        call_sha256=_canonical_hash(call),
        policy_version=str(policy.get("policy", {}).get("version", "unversioned")),
    )


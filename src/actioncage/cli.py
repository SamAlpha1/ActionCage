"""Command-line interface for ActionCage."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

from .engine import PolicyError, evaluate, load_policy


EXIT_CODES = {"allow": 0, "review": 3, "deny": 4}


def _read_call(path: str) -> dict[str, Any]:
    raw = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise PolicyError("tool call JSON must be an object")
    return value


def _append_audit(path: str, result: dict[str, Any]) -> None:
    record = {"evaluated_at": datetime.now(timezone.utc).isoformat(), **result}
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="actioncage", description="Evaluate an agent tool call before execution."
    )
    parser.add_argument("--version", action="version", version="actioncage 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="evaluate a JSON tool call")
    check.add_argument("call", help="path to call JSON, or - for stdin")
    check.add_argument("--policy", required=True, help="TOML policy path")
    check.add_argument("--audit-log", help="append the decision as JSONL")
    check.add_argument("--compact", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        decision = evaluate(load_policy(args.policy), _read_call(args.call))
        output = decision.to_dict()
        if args.audit_log:
            _append_audit(args.audit_log, output)
        print(json.dumps(output, indent=None if args.compact else 2, sort_keys=True))
        return EXIT_CODES[decision.decision]
    except (OSError, json.JSONDecodeError, PolicyError) as exc:
        print(json.dumps({"error": str(exc), "decision": "error"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


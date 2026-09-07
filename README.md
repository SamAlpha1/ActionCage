# ActionCage

**A deterministic policy firewall for agent tool calls.**

ActionCage answers one question before a tool runs: **allow, review, or deny?** It is local, dependency-free at runtime, fail-closed by default, and produces an auditable hash without storing the original arguments.

```text
tool call JSON -> matching rules -> priority + deny-on-tie -> hashed decision record
```

## 30-second demo

```bash
python -m pip install -e .
actioncage check examples/call.json --policy examples/policy.toml
```

Output:

```json
{
  "decision": "deny",
  "rule_id": "deny-recursive-delete",
  "reason": "Recursive deletion requires an explicit, separate approval path.",
  "policy_version": "2026-09-07",
  "call_sha256": "..."
}
```

Exit codes are designed for automation: `0` allow, `3` review, `4` deny, `2` invalid input.

## Why it is different

- Evaluates the **intended action**, not model prose.
- Exact, deterministic outcomes: no model call inside the security boundary.
- Glob matching for tool names and exact/regex matching for nested arguments.
- Highest priority wins; a deny rule wins equal-priority ties.
- Audit logs store hashes and decisions, not raw secrets.
- TOML policies work in a repository, container, pre-tool hook, or CI job.

## Call format

```json
{"tool":"http_post","arguments":{"url":"https://api.example.com","body":"hello"}}
```

Rules match tool names plus fields below `arguments`:

```toml
[[rules]]
id = "block-production-post"
effect = "deny"
priority = 90
tools = ["http_*"]

[rules.argument_regex]
url = '''^https://api\.example\.com/production'''
```

Use `--audit-log decisions.jsonl` to append tamper-evident call hashes to an operational log.

## Security model

ActionCage is a policy decision point, not a sandbox. The caller must refuse to execute denied actions and must route review decisions to a trusted approval mechanism. Keep the policy file read-only for the agent being governed.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Project origin

Created and maintained by [SamAlpha1](https://github.com/SamAlpha1). The canonical origin is `SamAlpha1/ActionCage`; see `.provenance/origin.json`, `NOTICE`, and the immutable Git history.

MIT licensed. Copies must preserve the copyright and license notice.

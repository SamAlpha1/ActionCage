import unittest

from actioncage.engine import PolicyError, evaluate, validate_policy


POLICY = {
    "policy": {"version": "test-v1"},
    "defaults": {"decision": "review"},
    "rules": [
        {"id": "deny-recursive-delete", "effect": "deny", "priority": 100,
         "tools": ["shell", "exec_*"],
         "argument_regex": {"command": r"(^|\s)(rm\s+-rf|Remove-Item\s+.*-Recurse)"},
         "reason": "destructive recursive deletion"},
        {"id": "allow-tests", "effect": "allow", "priority": 10,
         "tools": ["shell"], "argument_regex": {"command": r"^pytest(?:\s|$)"}},
    ],
}


class EngineTests(unittest.TestCase):
    def test_deny_dangerous_command(self):
        result = evaluate(POLICY, {"tool": "shell", "arguments": {"command": "rm -rf build"}})
        self.assertEqual(result.decision, "deny")
        self.assertEqual(result.rule_id, "deny-recursive-delete")

    def test_allow_known_test_command(self):
        result = evaluate(POLICY, {"tool": "shell", "arguments": {"command": "pytest -q"}})
        self.assertEqual(result.decision, "allow")

    def test_unmatched_call_requires_review_and_hash_is_stable(self):
        call = {"tool": "http", "arguments": {"url": "https://example.com"}}
        one = evaluate(POLICY, call)
        two = evaluate(POLICY, {"arguments": call["arguments"], "tool": "http"})
        self.assertEqual(one.decision, "review")
        self.assertEqual(one.call_sha256, two.call_sha256)

    def test_deny_wins_priority_tie(self):
        policy = {"rules": [
            {"id": "a", "effect": "allow", "priority": 5, "tools": ["*"]},
            {"id": "d", "effect": "deny", "priority": 5, "tools": ["*"]},
        ]}
        self.assertEqual(evaluate(policy, {"tool": "x", "arguments": {}}).rule_id, "d")

    def test_duplicate_rule_ids_rejected(self):
        policy = {"rules": [{"id": "x", "effect": "allow"}, {"id": "x", "effect": "deny"}]}
        with self.assertRaisesRegex(PolicyError, "duplicate"):
            validate_policy(policy)


if __name__ == "__main__":
    unittest.main()


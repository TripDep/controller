"""C07 real-work intake tests: fixtures are not production authorization."""
import copy
import json
import unittest
from real_work_intake import IntakeBlocked, canonical, inspect, sha


class RealWorkIntakeTests(unittest.TestCase):
    def setUp(self):
        self.master = b"Golden Controller enforcement\nPersistent observable audit trail\n"
        self.master_sha = sha(self.master)
        row = {"asset": "WORK_A", "event": "WORK_INIT", "prev_hash": "GENESIS"}
        row["record_hash"] = sha(canonical(row))
        self.rows = [row]
        self.st = {
            "last_audit_hash": row["record_hash"],
            "next_step": 2,
            "active_step": None,
            "unresolved": {},
            "d_authorized": True,
            "d_authorization_evidence": "unit fixture; not a real user decision",
            "last_master": {"sha256": self.master_sha},
        }
        self.state = {"assets": {"WORK_A": self.st}}

    def examine(self, asset="WORK_A"):
        audit = b"\n".join(canonical(row) for row in self.rows) + b"\n"
        return inspect(self.master, canonical(self.state), audit, asset, self.master_sha)

    def test_valid_chain_allows_only_enrollment_preflight_not_advance(self):
        report = self.examine()
        self.assertTrue(report["audit_chain_valid"])
        self.assertEqual(report["state_audit_alignment"], "EXACT")
        self.assertTrue(report["controller_preflight_ready"])
        self.assertFalse(report["advancement_authorized"])
        self.assertFalse(report["semantic_rules_and_mg0_verified"])
        self.assertFalse(report["operation_enrolled"])

    def test_real_stop_blocks_only_changed_asset_not_independent_one(self):
        old = self.rows[-1]
        newer = {"asset": "WORK_A", "event": "STEP_CLOSE", "result": "FAIL",
                 "prev_hash": old["record_hash"], "step": "0002"}
        newer["record_hash"] = sha(canonical(newer))
        self.rows.append(newer)
        report = self.examine()
        self.assertEqual(report["state_audit_alignment"], "STATE_BEHIND_AUDIT")
        self.assertEqual(report["state_lag_events"], 1)
        self.assertIn("CURRENT_WORK_STATE_AUDIT_RECONCILIATION_REQUIRED", report["blockers"])
        self.assertFalse(report["controller_preflight_ready"])

    def test_unresolved_controller_failure_never_authorized(self):
        self.st["unresolved"] = {"0012": {"result": "FAIL"}}
        report = self.examine()
        self.assertEqual(report["next_required_action"], "RESOLVE_THIS_ASSET_CONTROLLER_BLOCKERS")
        self.assertFalse(report["controller_preflight_ready"])

    def test_tampered_hash_chain_fails_without_silent_unknown(self):
        self.rows[0]["event"] = "FORGED_PASS"
        with self.assertRaisesRegex(IntakeBlocked, "INTAKE_AUDIT_RECORD"):
            self.examine()

    def test_changed_master_not_accepted_on_old_pin(self):
        self.master += b"not identical"
        with self.assertRaisesRegex(IntakeBlocked, "INTAKE_MASTER_LIBRARY_DRIFT"):
            self.examine()

    def test_duplicate_keys_rejected(self):
        from real_work_intake import strict_json
        with self.assertRaisesRegex(IntakeBlocked, "INTAKE_DUPLICATE_JSON_KEY"):
            strict_json(b'{"status": "PASS", "status": "UNKNOWN"}')

    def test_foreign_asset_audit_rejected(self):
        self.rows[0]["asset"] = "OTHER"
        self.rows[0]["record_hash"] = sha(canonical({k: v for k, v in self.rows[0].items()
                                                     if k != "record_hash"}))
        with self.assertRaisesRegex(IntakeBlocked, "INTAKE_AUDIT_ASSET"):
            self.examine()

    def test_state_tail_unrelated_to_audit_blocked(self):
        self.st["last_audit_hash"] = "f" * 64
        report = self.examine()
        self.assertEqual(report["state_audit_alignment"], "STATE_AUDIT_DISCONNECTED")
        self.assertFalse(report["controller_preflight_ready"])


if __name__ == "__main__":
    unittest.main()

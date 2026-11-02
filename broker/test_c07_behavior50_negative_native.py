"""C07 BEHAVIOR-001..050: standard-library-only regression tests."""
import hashlib
import unittest
from unittest.mock import patch
from c07_behavior50_negative_native import TRIGGERS, SOURCE_SHA256, inspect, Behavior50Blocked

ATTEMPT = "a" * 64
OPERATION = "b" * 64

def inventory():
    rules = {}
    for rid in TRIGGERS:
        requirement = "Errore: canonical behavior " + rid
        rules[rid] = {
            "family": "BEHAVIOR_110", "source_sha256": SOURCE_SHA256,
            "requirement": requirement,
            "requirement_sha256": hashlib.sha256(requirement.encode()).hexdigest(),
        }
    return {
        "schema": "gg-effective-family-inventory-v1", "rule_count": 763,
        "source_digests": {"error_registry": SOURCE_SHA256},
        "rules": rules,
    }

def run(inv, records):
    with patch("c07_behavior50_negative_native.audit_check", return_value=(records, "tail")):
        return inspect(inv, b"audited original bytes", "GOLDEN_GARDEN", ATTEMPT, OPERATION)

class Behavior50Tests(unittest.TestCase):
    def test_all_50_absence_never_passes(self):
        result = run(inventory(), [])
        self.assertEqual(result["rule_count"], 50)
        self.assertEqual(result["certified_count"], 0)
        self.assertEqual(result["individual_mg0_passes"], 0)
        self.assertTrue(all(v["verdict"] == "UNKNOWN" and not v["full_rule_pass"]
                            for v in result["rules"].values()))

    def test_each_of_50_rule_violations_is_negative_only(self):
        for rid in TRIGGERS:
            with self.subTest(rule=rid):
                inv = inventory()
                event = {
                    "event": "INDEPENDENT_BEHAVIOR_VIOLATION", "rule_id": rid,
                    "violation_kind": TRIGGERS[rid][0],
                    "attempt_id": ATTEMPT, "operation_sha256": OPERATION,
                    "source_requirement_sha256": inv["rules"][rid]["requirement_sha256"],
                    "record_hash": "c" * 64,
                }
                result = run(inv, [event])
                self.assertEqual(result["negative_findings"], 1)
                self.assertEqual(result["rules"][rid]["verdict"], "FAIL")
                self.assertEqual(result["rules"][rid]["individual_mg0"], "UNKNOWN")
                self.assertEqual(result["certified_count"], 0)

    def test_wrong_attempt_cannot_replay_fail(self):
        inv = inventory()
        rid = "BEHAVIOR-001"
        event = {
            "event": "INDEPENDENT_BEHAVIOR_VIOLATION", "rule_id": rid,
            "violation_kind": TRIGGERS[rid][0], "attempt_id": "f" * 64,
            "operation_sha256": OPERATION,
            "source_requirement_sha256": inv["rules"][rid]["requirement_sha256"],
            "record_hash": "c" * 64,
        }
        self.assertEqual(run(inv, [event])["negative_findings"], 0)

    def test_canonical_source_change_blocks_everything(self):
        inv = inventory()
        inv["rules"]["BEHAVIOR-050"]["requirement"] = "modified"
        with self.assertRaises(Behavior50Blocked):
            run(inv, [])

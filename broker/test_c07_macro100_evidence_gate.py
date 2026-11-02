"""Regression tests for the C07 frozen macro100 negative gate."""
import hashlib
import unittest
from unittest.mock import patch
import c07_macro100_evidence_gate as gate

def fixture():
    rules = {}
    for i, rid in enumerate(gate.BATCH_IDS):
        clause = "original source obligation " + rid
        rules[rid] = {
            "requirement": clause,
            "requirement_sha256": hashlib.sha256(clause.encode()).hexdigest(),
            "source_sha256": "a" * 64,
        }
    for i in range(663):
        rules["SYNTHETIC-" + str(i)] = {}
    return {"schema": "gg-effective-family-inventory-v1",
            "rule_count": 763, "rules": rules}

class Macro100GateTests(unittest.TestCase):
    def test_all_100_enumerated_without_false_pass(self):
        r = gate.inspect(fixture(), {}, {})
        self.assertEqual((r["rule_count"], len(r["rules"]),
                          r["unknown_count"], r["certified_full_count"]),
                         (100, 100, 100, 0))
        self.assertFalse(r["advancement_authorized"])

    def test_untrusted_positive_assertions_never_grant_pass(self):
        x = fixture()
        fake = {rid: {"verdict": "PASS", "independent_review": True,
                      "mg0_independent": True}
                for rid in gate.BATCH_IDS}
        r = gate.inspect(x, {}, fake)
        self.assertEqual(r["certified_full_count"], 0)
        self.assertEqual(r["unknown_count"], 100)

    def test_100_claims_cannot_be_self_certified(self):
        x = fixture()
        r = gate.inspect(x, {}, {})
        for rid in gate.BATCH_IDS:
            r["rules"][rid]["full_rule_pass"] = True
            r["rules"][rid]["individual_mg0_pass"] = True
            r["rules"][rid]["verdict"] = "PASS"
        r["certified_full_count"] = 100
        r["individual_mg0_passes"] = 100
        r["advancement_authorized"] = True
        with self.assertRaisesRegex(gate.Macro100Blocked, "INDEPENDENT_FULL_AND_MG0_MISSING"):
            gate.require_complete(r, x)

    def test_truncated_certificate_is_rejected(self):
        x = fixture()
        r = gate.inspect(x, {}, {})
        del r["rules"][gate.BATCH_IDS[0]]
        with self.assertRaisesRegex(gate.Macro100Blocked, "NOT_ALL_ONE_HUNDRED"):
            gate.require_complete(r, x)

    def test_source_tampering_is_hard_blocked(self):
        x = fixture()
        rid = gate.BATCH_IDS[0]
        x["rules"][rid]["requirement"] = "altered text"
        with self.assertRaisesRegex(gate.Macro100Blocked, "SOURCE_CLAUSE_INVALID"):
            gate.inspect(x, {}, {})

    def test_missing_canonical_rule_blocks(self):
        x = fixture()
        del x["rules"][gate.BATCH_IDS[0]]
        with self.assertRaises(gate.Macro100Blocked):
            gate.inspect(x, {}, {})

    def test_reviewer_spoof_without_registry_blocks_positive(self):
        rid = gate.BATCH_IDS[0]
        x = fixture()
        fake_enrolled = {rid: {"validator_id": "fake",
                               "requirement_sha256": x["rules"][rid]["requirement_sha256"]}}
        with patch.dict(gate.REVIEWED, {}, clear=True):
            r = gate.inspect(x, fake_enrolled, {rid: {"verdict": "PASS"}})
        self.assertEqual(r["rules"][rid]["verdict"], "UNKNOWN")
        self.assertFalse(r["rules"][rid]["full_rule_pass"])

if __name__ == "__main__":
    unittest.main()

"""C07 eighth 25 A001-C025: adversarial TEST-ONLY source fixtures.

The 25 canonical rule mutations, tampered audit/master and fake MG0
must be rejected. Fixture PASS here never certifies a live asset.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import c07_a001_c025_25_semantic_replay as gate
from c07_a10_c10_original_evidence import TEXT as AC_TEXT
from c07_bf50_canonical import CLAUSES
from c07_bf50_predicates import SPEC

MASTER = b"TEST_ONLY_MASTER_A001_C025"
AUDIT = b"TEST_ONLY_AUDIT_A001_C025"
MASTER_SHA = hashlib.sha256(MASTER).hexdigest()
AUDIT_SHA = hashlib.sha256(AUDIT).hexdigest()
ATTEMPT = "b" * 64
OPERATION = "c" * 64
TAIL = "a" * 64


class A001C025Test(unittest.TestCase):
    def setUp(self):
        ctrl = Mock()
        ctrl.master.read_bytes.return_value = MASTER
        ctrl.audit_path.return_value.read_bytes.return_value = AUDIT
        self.ctrl = ctrl
        self.inv = {
            "schema": "gg-effective-family-inventory-v1",
            "rule_count": 763,
            "canonical_master_sha256": MASTER_SHA,
            "source_digests": {"aaa_catalog": gate.CATALOG_SHA},
            "rules": {},
        }
        self.work = {
            "phase": "P0", "attempt_id": ATTEMPT,
            "operation_sha256": OPERATION, "master_sha256": MASTER_SHA,
        }
        self.plan = {"phase": "P0", "master_sha256": MASTER_SHA}
        self.context = {
            "inventory": self.inv, "plan": self.plan,
            "controller": ctrl, "asset": "TEST_ONLY_ASSET",
            "step": "TEST_ONLY_STEP", "work": self.work,
            "source_loader": lambda path: b"TEST_ONLY_SOURCE",
        }
        self.ac = {
            "schema": gate.AC_SCHEMA, "source_rules_examined": 20,
            "native_conditions_evaluated": 60,
            "original_audit_sha256": AUDIT_SHA,
            "original_audit_tail": TAIL,
            "attempt_id": ATTEMPT, "operation_sha256": OPERATION,
            "full_rule_passes": 0, "individual_mg0_passes": 0,
            "advancement_authorized": False, "rules": {},
        }
        self.bf = {
            "schema": gate.BF_SCHEMA, "source_rules_examined": 50,
            "native_conditions_evaluated": 200,
            "original_audit_sha256": AUDIT_SHA,
            "original_audit_tail": TAIL,
            "attempt_id": ATTEMPT, "operation_sha256": OPERATION,
            "full_rule_passes": 0, "individual_mg0_passes": 0,
            "advancement_authorized": False, "rules": {},
        }
        self.mg = {
            "rule_count": 25, "counts": {"PASS": 0, "UNKNOWN": 25, "FAIL": 0},
            "audit_sha256": AUDIT_SHA, "audit_tail_sha256": TAIL,
            "attempt_id": ATTEMPT, "individual_mg0_passes": 0,
            "advancement_authorized": False, "rules": {},
        }
        for n, rid in enumerate(gate.IDS, 1):
            sec = "A" if n <= 10 else "B" if n <= 20 else "C"
            requirement = AC_TEXT[n] if n <= 10 or n >= 21 else CLAUSES[n][1]
            digest = hashlib.sha256(requirement.encode("utf-8")).hexdigest()
            self.inv["rules"][rid] = {
                "family": "AAA-200", "catalog_number": n,
                "catalog_section": sec, "catalog_phase": "P0",
                "asset_type": "all", "requirement": requirement,
                "requirement_sha256": digest,
                "source_sha256": gate.CATALOG_SHA,
            }
            if n <= 10 or n >= 21:
                checks = {
                    "original_photo_bound": True,
                    "original_document_bound": True,
                    "independent_license_or_artistic_review": False,
                }
                self.ac["rules"][rid] = {
                    "requirement_sha256": digest, "full_rule_pass": False,
                    "individual_mg0": "UNKNOWN", "owner_approval": "UNKNOWN",
                    "advancement_authorized": False,
                    "native_original_file_criteria": checks,
                }
            if n >= 11:
                bf_checks = {k: (i == 0) for i, k in enumerate(SPEC[n])}
                if n >= 21:
                    bf_checks = dict(zip(SPEC[n], [True, True, False, False]))
                self.bf["rules"][rid] = {
                    "rule_id": rid, "source_sha256": gate.CATALOG_SHA,
                    "requirement_sha256": digest,
                    "canonical_requirement": requirement,
                    "applicability": "DUE",
                    "full_rule_semantics": "UNKNOWN",
                    "individual_mg0": "UNKNOWN", "owner_approval": "UNKNOWN",
                    "advancement_authorized": False,
                    "original_native_predicates": bf_checks,
                }
            self.mg["rules"][rid] = {
                "verdict": "UNKNOWN", "uncorrected_failure_count": 0,
                "observation_sha256": hashlib.sha256(rid.encode()).hexdigest(),
            }

    def run_gate(self):
        with patch.object(gate, "inspect_ac", return_value=self.ac), \
             patch.object(gate, "inspect_bf", return_value=self.bf), \
             patch.object(gate, "inspect_mg0", return_value=self.mg):
            return gate.inspect(self.context)

    def assert_blocked(self, reason):
        with self.assertRaisesRegex(gate.A001C025Blocked, reason):
            self.run_gate()

    def test_25_exact_unique_canonical_id_sources(self):
        gate.canonical(self.inv)
        self.assertEqual(len(gate.IDS), 25)
        self.assertEqual(len(set(gate.IDS)), 25)

    def test_each_original_canonical_clause_mutation_is_rejected(self):
        for rid in gate.IDS:
            row = self.inv["rules"][rid]
            old = row["requirement"]
            row["requirement"] = old + " MODIFIED"
            with self.subTest(rule=rid):
                self.assert_blocked("ORIGINAL_REQUIREMENT_CHANGED")
            row["requirement"] = old

    def test_disjoint_from_previous_175_software_ids(self):
        seen = {"EXEC-%03d" % i for i in range(1, 26)}
        for n in list(range(36, 111)) + list(range(121, 171)) + list(range(176, 201)):
            sec = ("D" if n <= 40 else "E" if n <= 50 else
                   "F" if n <= 60 else "G" if n <= 70 else
                   "H" if n <= 80 else "I" if n <= 90 else
                   "J" if n <= 100 else "K" if n <= 110 else
                   "M" if n <= 130 else "N" if n <= 140 else
                   "O" if n <= 150 else "P" if n <= 160 else
                   "Q" if n <= 170 else "R" if n <= 180 else
                   "S" if n <= 190 else "T")
            seen.add("AAA-200-%s-%03d" % (sec, n))
        self.assertFalse(set(gate.IDS) & seen)

    def test_25_rule_source_checks_and_mg0_without_fake_pass(self):
        out = self.run_gate()
        self.assertEqual(out["rule_count"], 25)
        self.assertEqual(out["canonical_source_clauses"], 25)
        self.assertEqual(out["actual_machine_subchecks_checked"], 85)
        self.assertEqual(out["mg0_individual_negative_checks"], 25)
        self.assertEqual(out["full_rule_semantic_passes"], 0)
        self.assertEqual(out["individual_mg0_passes"], 0)
        self.assertFalse(out["advancement_authorized"])
        self.assertEqual({v["semantic_verdict"] for v in out["rules"].values()},
                         {"UNKNOWN"})

    def test_reused_c21_c25_research_not_double_counted(self):
        out = self.run_gate()
        for rid in gate.IDS[20:]:
            self.assertEqual(len(out["rules"][rid]["original_machine_subchecks"]), 3)

    def test_mg0_failure_retained_and_never_approved(self):
        rid = gate.IDS[18]
        self.mg["rules"][rid]["verdict"] = "FAIL"
        self.mg["rules"][rid]["uncorrected_failure_count"] = 1
        out = self.run_gate()
        self.assertEqual(out["negative_mg0_failures"], 1)
        self.assertEqual(out["rules"][rid]["semantic_verdict"], "FAIL")
        self.assertFalse(out["rules"][rid]["advancement_authorized"])

    def test_fake_mg0_pass_blocks(self):
        self.mg["counts"]["PASS"] = 1
        self.assert_blocked("SOURCE_AND_MG0_REPLAY_DIVERGED")

    def test_mg0_missing_one_id_blocks(self):
        self.mg["rules"].pop(gate.IDS[5])
        self.assert_blocked("SOURCE_AND_MG0_REPLAY_DIVERGED")

    def test_mg0_fake_individual_observation_blocks(self):
        self.mg["rules"][gate.IDS[6]]["verdict"] = "PASS"
        self.assert_blocked("INDEPENDENT_MG0_NEGATIVE_MISSING")

    def test_fake_full_source_pass_blocks(self):
        self.bf["rules"][gate.IDS[14]]["full_rule_semantics"] = "PASS"
        self.assert_blocked("BF_SOURCE_SCOPE_CHANGED")

    def test_reused_reference_contradiction_blocks(self):
        self.bf["rules"][gate.IDS[21]]["original_native_predicates"][
            SPEC[22][0]] = False
        self.assert_blocked("REUSED_C_REFERENCE_CONTRADICTED")

    def test_missing_original_source_predicate_blocks(self):
        self.ac["rules"][gate.IDS[0]]["native_original_file_criteria"].pop(
            "original_photo_bound")
        self.assert_blocked("THREE_ORIGINAL_REFERENCE_CHECKS")

    def test_master_changed_blocks(self):
        self.ctrl.master.read_bytes.return_value = b"CHANGED"
        self.assert_blocked("MASTER_READBACK_CHANGED")

    def test_audit_changed_blocks(self):
        self.ctrl.audit_path.return_value.read_bytes.return_value = b"ALTERED"
        self.assert_blocked("SOURCE_AND_MG0_REPLAY_DIVERGED")

    def test_foreign_attempt_blocks(self):
        self.bf["attempt_id"] = "d" * 64
        self.assert_blocked("SOURCE_AND_MG0_REPLAY_DIVERGED")

    def test_phase_drift_blocks(self):
        self.work["phase"] = "P1"
        self.assert_blocked("ACTIVE_OPERATION_PHASE_REQUIRED")

    def test_extra_context_key_blocks(self):
        self.context["injected_source"] = "PASS"
        self.assert_blocked("ORIGINAL_SOURCE_CONTEXT_REQUIRED")
        self.context.pop("injected_source")

    def test_controlled_close_hook_present(self):
        source = Path(__file__).with_name("controlled_judgment.py").read_text("utf-8")
        for marker in (
            "from c07_a001_c025_25_semantic_replay import inspect as inspect_ac25",
            "SUPERVISOR_C07_A001_C025_ORIGINAL_SEMANTIC_25",
            "C07_A001_C025_25_ORIGINAL_SOURCE_REPLAY_REQUIRED",
            "source_original=ac25['rules']",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()

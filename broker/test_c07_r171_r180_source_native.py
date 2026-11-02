"""Adversarial functional checks for ten native C07 R171..R180 predicates."""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from c07_r171_r180_source_native import (
    CLAUSES, CATALOG_SHA, IDS, Process10Blocked, evidence_checks, exact_canon,
    inspect, SCHEMA,
)

ATTEMPT = "a" * 64
OPERATION = "b" * 64
MASTER = "d" * 64
WORK = {
    "attempt_id": ATTEMPT, "operation_sha256": OPERATION,
    "master_sha256": MASTER, "work_dependencies": {"e" * 64: "f" * 64},
    "previous_attempt_id": None,
}
PLAN = {"dependency_files": {"e" * 64: "source.blend"}}
STATE = {"last_audit_hash": "tail", "active_step": {"step": "STEP005"}}
ARTIFACTS = [
    ("SOURCE_EDITABLE", "/vault/work/source.blend", "1" * 64, b"blend-original"),
    ("NATIVE_EXPORT", "/vault/output/model.glb", "2" * 64, b"glb-original"),
    ("DELIVERY_PACKAGE", "/vault/delivery/package.zip", "3" * 64, b"zip-original"),
    ("BASELINE_SNAPSHOT", "/vault/approved/original.glb", "4" * 64, b"glb-baseline"),
    ("NATIVE_REIMPORT", "/vault/qa/reimport.glb", "5" * 64, b"glb-reimport"),
]

def inventory():
    rules = {}
    for n, clause in CLAUSES.items():
        rid = "AAA-200-R-%03d" % n
        rules[rid] = {
            "family": "AAA-200", "catalog_number": n,
            "catalog_section": "R", "catalog_phase": "P0",
            "requirement": clause,
            "requirement_sha256": hashlib.sha256(clause.encode()).hexdigest(),
            "source_sha256": CATALOG_SHA,
        }
    return {
        "schema": "gg-effective-family-inventory-v1", "rule_count": 763,
        "canonical_master_sha256": MASTER,
        "source_digests": {"aaa_catalog": CATALOG_SHA},
        "rules": rules,
    }

def native():
    names = ("AAA-200-R-172", "AAA-200-R-178")
    return {
        "rule_count": 2,
        "individual_mg0_passes": 0, "advancement_authorized": False,
        "rules": {
            rid: {
                "semantic_result": "SEMANTIC_OBSERVED",
                "criteria": {
                    "authenticated_original": True,
                    "all_native_bytes_verified": True,
                },
            } for rid in names
        },
    }

class Process10Tests(unittest.TestCase):
    def test_10_exact_canonical_clauses(self):
        exact_canon(inventory())
        self.assertEqual(len(CLAUSES), 10)
        self.assertEqual(len(IDS), 10)

    def test_changing_any_canonical_requirement_blocks(self):
        for rid in IDS:
            with self.subTest(rule=rid):
                inv = inventory()
                inv["rules"][rid]["requirement"] += " fake"
                with self.assertRaises(Process10Blocked):
                    exact_canon(inv)

    def test_10_distinct_source_specific_criteria(self):
        checks = evidence_checks(inventory(), PLAN, [], STATE, ARTIFACTS,
                                 WORK, "STEP005", native())
        self.assertEqual(len(checks), 10)
        self.assertEqual(sum(len(cs) for cs in checks.values()), 40)
        for n, cs in checks.items():
            with self.subTest(rule=n):
                self.assertEqual(len(cs), 4)
                self.assertTrue(all(type(v) is bool for v in cs.values()))

    def test_real_native_binary_changes_count_not_reports(self):
        c = evidence_checks(inventory(), PLAN, [], STATE, ARTIFACTS,
                            WORK, "STEP005", native())
        self.assertTrue(all(c[180].values()))
        no_export = [x for x in ARTIFACTS if x[0] != "NATIVE_EXPORT"]
        d = evidence_checks(inventory(), PLAN, [], STATE, no_export,
                            WORK, "STEP005", native())
        self.assertFalse(d[180]["current_original_model_export_exists"])
        self.assertFalse(d[180]["progress_not_derived_from_document_event_count"])

    def test_no_event_pretends_owner_or_git_independence(self):
        records = []
        for event in ("SOURCE_VERSION_INDEPENDENTLY_VERIFIED",
                      "OWNER_APPROVED_ASSET_COPY_VERIFIED",
                      "AUTOMATED_ORIGINAL_OUTPUT_CHECK"):
            records.append({
                "event": event, "step": "STEP005", "attempt_id": ATTEMPT,
                "operation_sha256": OPERATION, "record_hash": event
            })
        checks = evidence_checks(inventory(), PLAN, records, STATE, ARTIFACTS,
                                 WORK, "STEP005", native())
        self.assertFalse(checks[173]["independent_version_storage_readback"])
        self.assertFalse(checks[174]["independent_owner_identity_verified"])
        self.assertFalse(checks[175]["measured_net_benefit_independently_proven"])

    def test_other_attempt_evidence_cannot_replay(self):
        row = {"event": "CHECKPOINT_RESTORED_AND_VERIFIED", "step": "STEP005",
               "attempt_id": "0" * 64, "operation_sha256": OPERATION}
        checks = evidence_checks(inventory(), PLAN, [row], STATE,
                                 ARTIFACTS, WORK, "STEP005", native())
        self.assertFalse(checks[179]["recovery_event_matches_exact_current_attempt"])

    def test_duplicate_role_paths_rejected(self):
        forged = ARTIFACTS + [("REFERENCE_IMAGE", ARTIFACTS[0][1], "9" * 64,
                                  b"replayed")]
        with self.assertRaises(Process10Blocked):
            evidence_checks(inventory(), PLAN, [], STATE, forged,
                            WORK, "STEP005", native())

    def test_untrusted_existing_native_verdict_rejected(self):
        forged = native()
        forged["individual_mg0_passes"] = 2
        with self.assertRaises(Process10Blocked):
            evidence_checks(inventory(), PLAN, [], STATE, ARTIFACTS,
                            WORK, "STEP005", forged)

    def test_operational_entrypoint_replays_10_against_original_readback(self):
        ctrl = Mock()
        ctrl.master.read_bytes.return_value = b"authentic-master"
        inv = inventory()
        inv["canonical_master_sha256"] = hashlib.sha256(b"authentic-master").hexdigest()
        work = dict(WORK, master_sha256=inv["canonical_master_sha256"])
        with patch("c07_r171_r180_source_native._original_attempt",
                   return_value=([], "tail", STATE, "auditsha")), \
             patch("c07_r171_r180_source_native._registered_artifacts",
                   return_value=ARTIFACTS), \
             patch("c07_r171_r180_source_native.native_process",
                   return_value=native()):
            report = inspect(inv, PLAN, ctrl, "GOLDEN_GARDEN", "STEP005",
                             work, source_loader=lambda _: b"original")
        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual(report["source_rules_examined"], 10)
        self.assertEqual(report["native_conditions_evaluated"], 40)
        self.assertEqual(report["full_rule_passes"], 0)
        self.assertEqual(report["individual_mg0_passes"], 0)
        self.assertTrue(all(not x["full_rule_pass"] and
                            x["independent_mg0"] == "UNKNOWN"
                            for x in report["rules"].values()))

if __name__ == "__main__":
    unittest.main()

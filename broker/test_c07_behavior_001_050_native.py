"""C07 BEHAVIOR first 50: adversarial original-source machine readbacks.

These controlled fixtures are implementation tests, not production prevention,
user approval, model quality or independent MG0 certifications.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from c07_behavior_001_050_canonical import CLAUSES, IDS, SOURCE_SHA
from c07_behavior_001_050_spec import SPEC
from c07_behavior_001_050_native import (
    Behavior50Blocked, exact_source, scoped_original_features, inspect, SCHEMA,
)

MASTER=b"current original master"
MASTER_SHA=hashlib.sha256(MASTER).hexdigest()
WORK={"attempt_id":"a"*64,"operation_sha256":"b"*64,
      "master_sha256":MASTER_SHA,"work_item_sha256":"c"*64,
      "work_dependencies":{},"phase":"P0","asset_type":"terrain"}
STEP="STEP055"
ASSET="GOLDEN_GARDEN"
PLAN={"operation":{"action":"MODEL","locks":["Approved tree line"]},
      "cost_policy":{"max_extra_cost":0},
      "dependency_files":{},
      "master_sha256":MASTER_SHA}
STATE={"last_audit_hash":"tail","active_step":{"step":STEP},
       "delivery_status":"NOT_DELIVERABLE"}
EXPORT=b"original native export data"
ARTIFACTS=[("NATIVE_EXPORT","/vault/asset.glb",
            hashlib.sha256(EXPORT).hexdigest(),EXPORT)]

def inventory():
    rules={}
    for n,clause in CLAUSES.items():
        rid=IDS[n-1]
        rules[rid]={"family":"BEHAVIOR_110","source":"error_registry",
                    "source_path":"governance/sources/REGISTRO_110_ERRORI_E_PREVENZIONE.md",
                    "source_sha256":SOURCE_SHA,"required_mg0":True,
                    "requirement":clause,
                    "requirement_sha256":hashlib.sha256(clause.encode()).hexdigest()}
    return {"schema":"gg-effective-family-inventory-v1","rule_count":763,
            "canonical_master_sha256":MASTER_SHA,
            "source_digests":{"error_registry":SOURCE_SHA},"rules":rules}

class BehaviorFiftyNativeTests(unittest.TestCase):
    def test_fifty_exact_original_clauses_present(self):
        exact_source(inventory())
        self.assertEqual(len(IDS),50)
        self.assertEqual(len(set(IDS)),50)

    def test_all_fifty_mutated_error_to_prevention_source_fail(self):
        for rid in IDS:
            with self.subTest(rid=rid):
                copy=inventory()
                copy["rules"][rid]["requirement"]+=" [fake]"
                with self.assertRaises(Behavior50Blocked):
                    exact_source(copy)

    def test_distinct_per_rule_specific_three_observations(self):
        self.assertEqual(len(SPEC),50)
        for n,scope in SPEC.items():
            with self.subTest(n=n):
                self.assertEqual(len(scope),3)
                self.assertEqual(len(set(scope)),3)

    def test_registered_original_bytes_verify_before_observing(self):
        ctrl=Mock()
        ctrl.root=Path("/cloud")
        ctrl.master.read_bytes.return_value=MASTER
        out=scoped_original_features([],ARTIFACTS,STATE,PLAN,WORK,
                                     ASSET,STEP,ctrl,lambda _:b"original")
        self.assertTrue(out["real_output_original_bytes"])
        self.assertTrue(out["output_sha_readback_verified"])
        self.assertFalse(out["actual_provider_run_verified"])
        self.assertFalse(out["true_checkpoint_completion_observed"])

    def test_fake_source_digest_rejected(self):
        ctrl=Mock()
        forged=[("NATIVE_EXPORT","/vault/asset.glb","0"*64,EXPORT)]
        with self.assertRaisesRegex(Behavior50Blocked,"ORIGINAL_BYTES_REPLAY"):
            scoped_original_features([],forged,STATE,PLAN,WORK,
                                     ASSET,STEP,ctrl,lambda _:b"fake")

    def test_duplicate_source_path_rejected(self):
        ctrl=Mock()
        with self.assertRaises(Behavior50Blocked):
            scoped_original_features([],ARTIFACTS+ARTIFACTS,STATE,PLAN,WORK,
                                     ASSET,STEP,ctrl,lambda _:b"original")

    def test_fake_guardian_event_of_different_attempt_is_not_current(self):
        ctrl=Mock()
        ctrl.master.read_bytes.return_value=MASTER
        row={"event":"GUARDIAN_CHECK","step":STEP,
             "attempt_id":"0"*64,"operation_sha256":WORK["operation_sha256"]}
        out=scoped_original_features([row],ARTIFACTS,STATE,PLAN,WORK,
                                     ASSET,STEP,ctrl,lambda _:b"original")
        self.assertFalse(out["guardian_cycle_record_original"])

    def test_malformed_untrusted_timestamps_not_counted(self):
        ctrl=Mock()
        ctrl.master.read_bytes.return_value=MASTER
        rows=[
            {"event":"RUN_STARTED","step":STEP,"attempt_id":WORK["attempt_id"],
             "operation_sha256":WORK["operation_sha256"],"timestamp_utc":"not-time"},
            {"event":"RUN_FINISHED","step":STEP,"attempt_id":WORK["attempt_id"],
             "operation_sha256":WORK["operation_sha256"],"timestamp_utc":"not-time"}]
        out=scoped_original_features(rows,[],STATE,PLAN,WORK,
                                     ASSET,STEP,ctrl,lambda _:b"original")
        self.assertFalse(out["run_start_finish_pairs_measured"])
        self.assertFalse(out["actual_distinct_run_samples"])

    def test_current_original_audit_and_fifty_no_mg0_passes(self):
        ctrl=Mock()
        ctrl.root=Path("/cloud")
        ctrl.master.read_bytes.return_value=MASTER
        with patch("c07_behavior_001_050_native._original_attempt",
                   return_value=([],"tail",STATE,"audit-source-digest")), \
             patch("c07_behavior_001_050_native._registered_artifacts",
                   return_value=ARTIFACTS):
            report=inspect(inventory(),PLAN,ctrl,ASSET,STEP,WORK,
                           source_loader=lambda _:b"original")
        self.assertEqual(report["schema"],SCHEMA)
        self.assertEqual(report["source_rules_examined"],50)
        self.assertEqual(report["native_conditions_evaluated"],150)
        self.assertEqual(report["full_rule_passes"],0)
        self.assertEqual(report["individual_mg0_passes"],0)
        self.assertEqual(set(report["rules"]),set(IDS))
        for row in report["rules"].values():
            self.assertEqual(len(row["original_machine_checks"]),3)
            self.assertEqual(row["individual_mg0"],"UNKNOWN")
            self.assertEqual(row["full_prevention_semantics"],"UNKNOWN")
            self.assertFalse(row["advancement_authorized"])

    def test_real_controller_close_integration(self):
        code=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_behavior_001_050_native import inspect as inspect_beh50",code)
        self.assertIn("SUPERVISOR_C07_BEHAVIOR001_050_ORIGINAL_NATIVE",code)

if __name__=="__main__":
    unittest.main()

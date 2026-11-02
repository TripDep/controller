"""Adversarial tests: 50 real canonical B11-F60 sources, no false MG0.

Fixtures prove implementation behavior, never user/project runtime quality.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

from test_glb_machine_qa import synthetic_glb
from c07_bf50_canonical import CLAUSES,IDS,CATALOG_SHA
from c07_bf50_predicates import SPEC
from c07_b011_f060_fifty_native import (
    SCHEMA,BF50Blocked,original_sources,observed_originals,inspect
)
MASTER=b"immutable canonical original master"
MASTER_SHA=hashlib.sha256(MASTER).hexdigest()
STEP="STEP050"
WORK={"attempt_id":"a"*64,"operation_sha256":"b"*64,
      "master_sha256":MASTER_SHA,"phase":"P1","asset_type":"terrain",
      "work_dependencies":{}}
STATE={"last_audit_hash":"original-tail","active_step":{"step":STEP}}
PLAN={"pre_d_control":{"target_engine":"FiveM","criteria":["original GLB verified"],
                      "piece_id":"original_terrain",
                      "time_budget_seconds":1800,"locks":["approved baseline"]},
      "operation":{"action":"MODEL","locks":["approved baseline"]},
      "dependency_files":{}}
GLB=synthetic_glb()
ROW=("NATIVE_EXPORT","/vault/current.glb",hashlib.sha256(GLB).hexdigest(),GLB)
BASELINE=("BASELINE_SNAPSHOT","/vault/approved.glb",
          hashlib.sha256(b"distinct approved original").hexdigest(),
          b"distinct approved original")
def inventory():
    return {"schema":"gg-effective-family-inventory-v1","rule_count":763,
            "canonical_master_sha256":MASTER_SHA,
            "source_digests":{"aaa_catalog":CATALOG_SHA},
            "rules":{
                rid:{"family":"AAA-200","catalog_number":n,
                     "catalog_section":section,"catalog_phase":phase,
                     "asset_type":kind,"source_sha256":CATALOG_SHA,
                     "requirement":wording,
                     "requirement_sha256":hashlib.sha256(wording.encode()).hexdigest()}
                for n,(section,wording,phase,kind) in CLAUSES.items()
                for rid in (IDS[n-11],)
            }}
def prior_r140():
    return {"source_rules_examined":20,"full_rule_passes":0,
            "individual_mg0_passes":0,"advancement_authorized":False,
            "rules":{
                "AAA-200-C-%03d"%n:{
                    "native_original_file_criteria":{
                        "original_source_evidence_one":False,
                        "original_source_evidence_two":False,
                        "original_source_evidence_three":False}
                } for n in range(21,31)}}

class FiftyBFTests(unittest.TestCase):
    def test_fifty_exact_original_clauses_and_distinct_ids(self):
        self.assertEqual(len(CLAUSES),50)
        self.assertEqual(len(set(IDS)),50)
        self.assertEqual(set(SPEC),set(range(11,61)))
        original_sources(inventory())
    def test_every_source_requirement_mutation_rejected(self):
        for rid in IDS:
            with self.subTest(rule_id=rid):
                data=inventory()
                data["rules"][rid]["requirement"]+=" fake"
                with self.assertRaises(BF50Blocked):
                    original_sources(data)
    def test_all_fifty_source_specific_scopes_have_four_unique_criteria(self):
        all_names=set()
        for i,keys in SPEC.items():
            with self.subTest(rule=i):
                self.assertEqual(len(keys),4)
                self.assertEqual(len(set(keys)),4)
                self.assertNotIn(keys[-1],all_names)
                all_names.add(keys[-1])
        self.assertEqual(len(all_names),50)
    def test_actual_original_glb_not_fake_name_controls_geometry(self):
        features,machine=observed_originals([], [ROW,BASELINE], PLAN,WORK,STEP,
                                             "GOLDEN_GARDEN",Mock(),lambda _:b"")
        self.assertEqual(machine["source_sha256"],ROW[2])
        self.assertTrue(features["original_glb_geometry_present"])
        self.assertTrue(features["new_native_output_differs_from_baseline"])
        self.assertTrue(features["planned_target_engine_is_explicit"])
        self.assertFalse(features["terrain_meshes_present"])
        self.assertFalse(features["original_front_view_png_valid"])
    def test_missing_original_glb_does_not_prove_progress(self):
        features,machine=observed_originals([], [BASELINE], PLAN,WORK,STEP,
                                             "GOLDEN_GARDEN",Mock(),lambda _:b"")
        self.assertIsNone(machine)
        self.assertFalse(features["scene_world_bounds_measured"])
        self.assertFalse(features["new_native_output_differs_from_baseline"])
    def test_corrupt_source_binary_is_blocked(self):
        fake=b"not a real glb"
        row=("NATIVE_EXPORT","/vault/current.glb",hashlib.sha256(fake).hexdigest(),fake)
        with self.assertRaisesRegex(BF50Blocked,"CORRUPT_REGISTERED_GLB"):
            observed_originals([], [row], PLAN,WORK,STEP,"GOLDEN_GARDEN",
                               Mock(),lambda _:b"")
    def test_wrong_original_sha_is_blocked(self):
        with self.assertRaisesRegex(BF50Blocked,"DUPLICATE_OR_UNVERIFIED"):
            observed_originals([], [("NATIVE_EXPORT","/vault/current.glb",
                                     "0"*64,GLB)],PLAN,WORK,STEP,"GOLDEN_GARDEN",
                               Mock(),lambda _:b"")
    def test_other_attempt_cannot_replay_quality_qa(self):
        row={"event":"QUALITY_FINDING","step":STEP,
             "attempt_id":"z"*64,"operation_sha256":WORK["operation_sha256"]}
        features,_=observed_originals([row],[ROW],PLAN,WORK,STEP,
                                      "GOLDEN_GARDEN",Mock(),lambda _:b"")
        self.assertFalse(features["original_quality_findings_scanned"])
    def test_authenticated_fifty_rule_output_without_fake_mg0(self):
        ctl=Mock()
        ctl.master.read_bytes.return_value=MASTER
        with patch("c07_b011_f060_fifty_native._original_attempt",
                   return_value=([],"original-tail",STATE,"original-audit-sha")), \
             patch("c07_b011_f060_fifty_native._registered_artifacts",
                   return_value=[ROW,BASELINE]), \
             patch("c07_b011_f060_fifty_native.inspect_existing_reference",
                   return_value=prior_r140()):
            result=inspect(inventory(),PLAN,ctl,"GOLDEN_GARDEN",STEP,WORK,
                           source_loader=lambda _:b"")
        self.assertEqual(result["schema"],SCHEMA)
        self.assertEqual(result["source_rules_examined"],50)
        self.assertEqual(result["native_conditions_evaluated"],200)
        self.assertEqual(result["full_rule_passes"],0)
        self.assertEqual(result["individual_mg0_passes"],0)
        self.assertEqual(set(result["rules"]),set(IDS))
        self.assertEqual(result["rules"]["AAA-200-B-011"]["applicability"],"DUE")
        for row in result["rules"].values():
            self.assertEqual(row["full_rule_semantics"],"UNKNOWN")
            self.assertEqual(row["individual_mg0"],"UNKNOWN")
            self.assertFalse(row["advancement_authorized"])
    def test_phase_p0_keeps_p1_future_not_pass(self):
        ctl=Mock()
        ctl.master.read_bytes.return_value=MASTER
        context=dict(WORK,phase="P0")
        with patch("c07_b011_f060_fifty_native._original_attempt",
                   return_value=([],"original-tail",STATE,"original-audit-sha")), \
             patch("c07_b011_f060_fifty_native._registered_artifacts",
                   return_value=[ROW]), \
             patch("c07_b011_f060_fifty_native.inspect_existing_reference",
                   return_value=prior_r140()):
            report=inspect(inventory(),PLAN,ctl,"GOLDEN_GARDEN",STEP,context,
                           source_loader=lambda _:b"")
        self.assertEqual(report["rules"]["AAA-200-F-060"]["applicability"],
                         "FUTURE_PHASE")
        self.assertEqual(report["rules"]["AAA-200-B-011"]["applicability"],"DUE")
    def test_controller_has_real_readback_and_durable_audit_call(self):
        text=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_b011_f060_fifty_native import inspect as inspect_bf50",text)
        self.assertIn("SUPERVISOR_C07_B011_F060_FIFTY_ORIGINAL_NATIVE",text)
        self.assertIn("bf50['native_conditions_evaluated'] == 200",text)

if __name__=="__main__":
    unittest.main()

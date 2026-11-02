"""C07 M121-Q170: 50 source-specific rules; real GLB bytes, hostile input.

Synthetic fixtures prove scanner behavior only. They do NOT certify a real
production asset, artistic design, FiveM runtime or any individual MG0.
"""
import hashlib
import unittest
from unittest.mock import Mock, patch
from test_glb_machine_qa import synthetic_glb
from c07_m121_q170_fifty_native import (
    CATALOG_SHA, CLAUSES, IDS, RULE_PREDICATES, SCHEMA,
    Native50Blocked, literal_sources, original_features, inspect,
)
from pathlib import Path

WORK = {"attempt_id":"a"*64, "operation_sha256":"b"*64,
        "master_sha256":"d"*64}
STEP = "STEP050"
STATE = {"active_step":{"step":STEP}, "last_audit_hash":"tail"}
PLAN = {"pre_d_control":{"performance_budget":{"triangles":1000}}}
GLB = synthetic_glb()
GLB_ROW = ("NATIVE_EXPORT","/safe/asset.glb",hashlib.sha256(GLB).hexdigest(),GLB)
SOURCE_ROW = ("SOURCE_EDITABLE","/safe/source.blend",
              hashlib.sha256(b"original-source").hexdigest(),b"original-source")
PNG_ROW = ("VISUAL_VIEW_FRONT","/safe/front.png",
           hashlib.sha256(b"\x89PNG\r\n\x1a\nfixture").hexdigest(),
           b"\x89PNG\r\n\x1a\nfixture")
ROWS = [GLB_ROW,SOURCE_ROW,PNG_ROW]

def inv():
    rules={}
    for i,text in CLAUSES.items():
        s="MNOPQ"[(i-121)//10]
        rid="AAA-200-"+s+"-%03d"%i
        rules[rid]={"family":"AAA-200","catalog_section":s,
                    "catalog_number":i,"catalog_phase":"P0",
                    "requirement":text,
                    "source_sha256":CATALOG_SHA,
                    "requirement_sha256":hashlib.sha256(text.encode()).hexdigest()}
    return {"schema":"gg-effective-family-inventory-v1",
            "rule_count":763,"canonical_master_sha256":"d"*64,
            "source_digests":{"aaa_catalog":CATALOG_SHA},"rules":rules}

class OriginalNativeFifty(unittest.TestCase):
    def test_all_50_real_original_source_clauses_are_pinned(self):
        self.assertEqual(len(CLAUSES),50)
        self.assertEqual(len(IDS),50)
        self.assertEqual(len(set(IDS)),50)
        literal_sources(inv())

    def test_each_of_50_literal_requirements_rejects_mutation(self):
        for rid in IDS:
            with self.subTest(rule_id=rid):
                copy=inv()
                copy["rules"][rid]["requirement"] += " substituted"
                with self.assertRaises(Native50Blocked):
                    literal_sources(copy)

    def test_each_of_50_distinct_evidence_scopes_exists(self):
        self.assertEqual(set(RULE_PREDICATES),set(CLAUSES))
        for n,scope in RULE_PREDICATES.items():
            with self.subTest(rule=n):
                self.assertGreaterEqual(len(scope),3)
                self.assertEqual(len(set(scope)),len(scope))

    def test_real_glb_buffer_parsed_not_inferred_from_file_name(self):
        features,report,shots=original_features([],ROWS,PLAN,STATE,STEP,WORK)
        self.assertEqual(report["triangles_examined"],1)
        self.assertEqual(report["source_sha256"],hashlib.sha256(GLB).hexdigest())
        self.assertTrue(features["triangle_count_from_original_indices"])
        self.assertTrue(features["neutral_view_source_png"])
        self.assertFalse(features["true_fivem_runtime_playback_verified"])
        self.assertFalse(features["original_artistic_quality_independently_approved"])
        self.assertFalse(features["native_drawable_header_validated"])

    def test_missing_registered_original_glb_cannot_prove_geometry(self):
        features,report,shots=original_features([], [SOURCE_ROW], PLAN,STATE,STEP,WORK)
        self.assertIsNone(report)
        for name in ("registered_glb_original","glb_geometry_nonempty",
                     "triangle_count_from_original_indices","texture_image_dimensions_reopened",
                     "registered_native_ybn","original_runtime_frame_measurement_verified"):
            with self.subTest(feature=name):self.assertFalse(features[name])

    def test_corrupted_glb_original_bytes_are_hard_stop(self):
        corrupt=b"NOT A GLB"
        row=("NATIVE_EXPORT","/safe/asset.glb",hashlib.sha256(corrupt).hexdigest(),corrupt)
        with self.assertRaisesRegex(Native50Blocked,"INVALID_REGISTERED_NATIVE_GLB"):
            original_features([], [row], PLAN,STATE,STEP,WORK)

    def test_registered_original_sha_cannot_be_substituted(self):
        forged=("NATIVE_EXPORT","/safe/asset.glb","0"*64,GLB)
        with self.assertRaisesRegex(Native50Blocked,"DUPLICATE_OR_UNTRUSTED"):
            original_features([], [forged], PLAN,STATE,STEP,WORK)

    def test_cross_attempt_qa_event_does_not_count(self):
        unrelated=[{"event":"FIVEM_RUNTIME_EVIDENCE","step":STEP,
                    "attempt_id":"9"*64,"operation_sha256":WORK["operation_sha256"]}]
        features,_,_=original_features(unrelated, ROWS,PLAN,STATE,STEP,WORK)
        self.assertFalse(features["original_runtime_evidence_event_present"])

    def test_50_reported_and_none_claimed_full_certification(self):
        control=Mock()
        control.master.read_bytes.return_value=b"original master bytes"
        inventory=inv()
        digest=hashlib.sha256(b"original master bytes").hexdigest()
        inventory["canonical_master_sha256"]=digest
        current=dict(WORK,master_sha256=digest)
        with patch("c07_m121_q170_fifty_native._original_attempt",
                   return_value=([], "tail", STATE, "real-audit-sha")), \
             patch("c07_m121_q170_fifty_native._registered_artifacts",
                   return_value=ROWS):
            result=inspect(inventory, PLAN, control, "GOLDEN_GARDEN", STEP,
                           current,source_loader=lambda _: b"original")
        self.assertEqual(result["schema"],SCHEMA)
        self.assertEqual(result["source_rules_examined"],50)
        self.assertGreaterEqual(result["native_predicates_evaluated"],150)
        self.assertEqual(result["full_rule_passes"],0)
        self.assertEqual(result["individual_mg0_passes"],0)
        self.assertEqual(set(result["rules"]),set(IDS))
        self.assertTrue(all(r["individual_mg0"]=="UNKNOWN" and
                            r["full_rule_semantics"]=="UNKNOWN" and
                            not r["advancement_authorized"]
                            for r in result["rules"].values()))

    def test_materials_light_collision_and_fivem_remain_truthful(self):
        features,_,_=original_features([],ROWS,PLAN,STATE,STEP,WORK)
        for required_false in ("material_authenticity_independently_proven",
                               "lighting_quality_independently_proven",
                               "collision_stability_independently_proven",
                               "original_runtime_collision_proven",
                               "optimization_benefit_independently_measured",
                               "true_fivem_runtime_playback_verified"):
            with self.subTest(name=required_false):
                self.assertFalse(features[required_false])

    def test_controller_close_includes_50_native_readback(self):
        p=Path(__file__).with_name("controlled_judgment.py")
        s=p.read_text()
        self.assertIn("from c07_m121_q170_fifty_native import inspect as inspect_mq50",s)
        self.assertIn("SUPERVISOR_C07_M121_Q170_FIFTY_ORIGINAL_NATIVE",s)
        self.assertIn("mq50['source_rules_examined'] == 50",s)

if __name__=="__main__":
    unittest.main()

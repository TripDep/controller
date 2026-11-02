"""G061-K110 native source tests. Synthetic tests cannot certify real models."""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

from test_glb_machine_qa import synthetic_glb
from c07_gk50_canonical import CLAUSES,IDS,CATALOG_SHA
from c07_gk50_predicates import SPEC
from c07_g061_k110_fifty_native import (
    GKBlocked,SCHEMA,exact_catalog,machine_features,inspect,
)
MASTER=b"original immutable master"
MASTER_SHA=hashlib.sha256(MASTER).hexdigest()
WORK={"attempt_id":"a"*64,"operation_sha256":"b"*64,
      "master_sha256":MASTER_SHA,"phase":"P2","asset_type":"architecture"}
STATE={"active_step":{"step":"STEP050"},"last_audit_hash":"tail"}
PLAN={"pre_d_control":{"expected_measurements":{"height":10.0}}}
GLB=synthetic_glb()
ROW=("NATIVE_EXPORT","/vault/current.glb",hashlib.sha256(GLB).hexdigest(),GLB)
def inventory():
    return {"schema":"gg-effective-family-inventory-v1","rule_count":763,
            "canonical_master_sha256":MASTER_SHA,
            "source_digests":{"aaa_catalog":CATALOG_SHA},
            "rules":{
              rid:{"family":"AAA-200","catalog_number":n,
                   "catalog_section":section,"catalog_phase":phase,
                   "asset_type":kind,"source_sha256":CATALOG_SHA,
                   "requirement":literal,
                   "requirement_sha256":hashlib.sha256(literal.encode()).hexdigest()}
              for n,(section,literal,phase,kind) in CLAUSES.items()
              for rid in [IDS[n-61]]
            }}

class NativeGK50Tests(unittest.TestCase):
    def test_all_fifty_actual_original_catalog_requirements(self):
        self.assertEqual(len(IDS),50)
        self.assertEqual(len(set(IDS)),50)
        exact_catalog(inventory())
    def test_every_source_rule_mutation_rejected(self):
        for rid in IDS:
            with self.subTest(rule=rid):
                inv=inventory();inv["rules"][rid]["requirement"]+=" forged"
                with self.assertRaises(GKBlocked):exact_catalog(inv)
    def test_each_of_50_individual_scopes_implemented(self):
        self.assertEqual(set(SPEC),set(range(61,111)))
        for number,checks in SPEC.items():
            with self.subTest(number=number):
                self.assertGreaterEqual(len(checks),3)
                self.assertEqual(len(checks),len(set(checks)))
    def test_real_registered_glb_is_scanned_not_treated_as_a_name(self):
        features,technical=machine_features([], [ROW], PLAN,"STEP050",WORK)
        self.assertEqual(technical["source_sha256"],ROW[2])
        self.assertTrue(features["source_geometry"])
        self.assertTrue(features["bounded_world_bounds"])
        self.assertFalse(features["architecture_named"])
        self.assertFalse(features["water_runtime_proven"])
        self.assertFalse(features["wind_runtime_proven"])
        self.assertFalse(features["construction_logic_proven"])
        self.assertFalse(features["shape_before_detail_proven"])
    def test_missing_glb_is_not_native_pass(self):
        features,report=machine_features([],[],PLAN,"STEP050",WORK)
        self.assertIsNone(report)
        self.assertFalse(features["source_geometry"])
        self.assertFalse(features["bounded_world_bounds"])
    def test_forged_digest_rejected(self):
        forged=("NATIVE_EXPORT","/vault/current.glb","0"*64,GLB)
        with self.assertRaises(GKBlocked):
            machine_features([],[forged],PLAN,"STEP050",WORK)
    def test_corrupt_original_binary_hard_stop(self):
        bad=b"NOT GLB"
        row=("NATIVE_EXPORT","/vault/current.glb",
             hashlib.sha256(bad).hexdigest(),bad)
        with self.assertRaisesRegex(GKBlocked,"REGISTERED_ORIGINAL_GLB_INVALID"):
            machine_features([],[row],PLAN,"STEP050",WORK)
    def test_wrong_attempt_runtime_record_never_replays(self):
        event={"event":"FIVEM_RUNTIME_EVIDENCE","step":"STEP050",
               "attempt_id":"9"*64,"operation_sha256":WORK["operation_sha256"]}
        f,_=machine_features([event],[ROW],PLAN,"STEP050",WORK)
        self.assertFalse(f["runtime_evidence_recorded"])
    def test_all_fifty_evaluated_but_not_falsely_mg0_certified(self):
        ctrl=Mock();ctrl.master.read_bytes.return_value=MASTER
        with patch("c07_g061_k110_fifty_native._original_attempt",
                   return_value=([],"tail",STATE,"original-audit-sha")), \
             patch("c07_g061_k110_fifty_native._registered_artifacts",
                   return_value=[ROW]):
            x=inspect(inventory(),PLAN,ctrl,"GOLDEN_GARDEN","STEP050",WORK,
                      source_loader=lambda p:GLB)
        self.assertEqual(x["schema"],SCHEMA)
        self.assertEqual(x["source_rules_examined"],50)
        self.assertGreaterEqual(x["native_conditions_evaluated"],150)
        self.assertEqual(x["individual_mg0_passes"],0)
        self.assertEqual(x["full_rule_passes"],0)
        self.assertEqual(set(x["rules"]),set(IDS))
        self.assertEqual(x["rules"]["AAA-200-G-061"]["applicability"],"DUE")
        self.assertEqual(x["rules"]["AAA-200-K-110"]["applicability"],"N_A_ASSET_TYPE")
        for row in x["rules"].values():
            self.assertEqual(row["individual_mg0"],"UNKNOWN")
            self.assertEqual(row["full_rule_semantics"],"UNKNOWN")
            self.assertFalse(row["advancement_authorized"])
    def test_not_due_before_p2_never_becomes_pass(self):
        ctrl=Mock();ctrl.master.read_bytes.return_value=MASTER
        previous=dict(WORK,phase="P0",asset_type="terrain")
        with patch("c07_g061_k110_fifty_native._original_attempt",
                   return_value=([],"tail",STATE,"original-audit-sha")), \
             patch("c07_g061_k110_fifty_native._registered_artifacts",
                   return_value=[ROW]):
            x=inspect(inventory(),PLAN,ctrl,"GOLDEN_GARDEN","STEP050",previous,
                      source_loader=lambda p:GLB)
        self.assertTrue(all(v["applicability"]=="FUTURE_PHASE"
                            for v in x["rules"].values()))
    def test_controller_close_wires_real_native_readback(self):
        s=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_g061_k110_fifty_native import inspect as inspect_gk50",s)
        self.assertIn("SUPERVISOR_C07_G061_K110_FIFTY_ORIGINAL_NATIVE",s)
        self.assertIn("gk50['source_rules_examined'] == 50",s)
    def test_two_different_original_world_scale_rock_instances_are_measured(self):
        import json,struct
        from glb_machine_qa import parse,audit_bytes
        from c07_gk50_size_scan import readback
        def raw_named(name,second_scale):
            g,binary=parse(GLB)
            g["meshes"][0]["name"]=name
            g["nodes"]=[
                {"mesh":0,"name":name+"_first","scale":[1,1,1]},
                {"mesh":0,"name":name+"_second","scale":[second_scale]*3}]
            g["scenes"][0]["nodes"]=[0,1]
            payload=json.dumps(g,separators=(",",":")).encode()
            payload+=b" "*(-len(payload)%4)
            return (struct.pack("<4sII",b"glTF",2,
                        12+8+len(payload)+8+len(binary))+
                    struct.pack("<I4s",len(payload),b"JSON")+payload+
                    struct.pack("<I4s",len(binary),b"BIN\x00")+binary)
        for name,key in (("taihu_rock","rock"),("bamboo_tree","vegetation")):
            with self.subTest(group=key):
                model=raw_named(name,2)
                observation=readback(model,audit_bytes(model))
                self.assertTrue(observation[key])
                same=raw_named(name,1)
                self.assertFalse(readback(same,audit_bytes(same))[key])
    def test_original_world_scan_budget_does_not_fake_positive(self):
        from c07_gk50_size_scan import readback,POINT_BUDGET
        self.assertEqual(readback(GLB,{"vertices_examined":POINT_BUDGET+1}),
                         {"rock":False,"vegetation":False})
if __name__=="__main__":unittest.main()

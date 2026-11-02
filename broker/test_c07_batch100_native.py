"""C07 100 additional canonical rules: adversarial source/model/audit tests.

Test outcomes only verify these source readers and constraints; no MG0 PASS,
owner consent, behavioral compliance or real FiveM acceptance is inferred.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

from test_glb_machine_qa import synthetic_glb
from c07_batch100_canonical import AAA,BEHAVIOR,IDS,CATALOG_SHA,REGISTRY_SHA
from c07_batch100_predicates import AAA_SPEC,BEHAVIOR_SPEC
from c07_batch100_probes import AAA_PROBES,BEHAVIOR_PROBES
from c07_batch100_native import (
    pin_sources,actual_originals,inspect,Batch100Blocked,SCHEMA,
)

GLB=synthetic_glb()
MASTER=b"immutable-original-master"
MASTER_SHA=hashlib.sha256(MASTER).hexdigest()
STEP="STEP057"
WORK={"master_sha256":MASTER_SHA,"operation_sha256":"b"*64,
      "attempt_id":"a"*64,"phase":"P8","asset_type":"architecture",
      "work_dependencies":{}}
PLAN={"operation":{"action":"MODEL","locks":["original-locked-mesh"],
                    "deliverables":["NATIVE_EXPORT","DELIVERY_PACKAGE"],
                    "method":"approved-original-workflow"},
      "pre_d_control":{"criteria":["original-native-checks"],
                       "expected_measurements":{"height":5}},
      "dependency_files":{},"asset_id":"GOLDEN_GARDEN"}
STATE={"last_audit_hash":"tail","active_step":{"step":STEP},
       "delivery_status":"PENDING"}
GLB_FILE=("NATIVE_EXPORT","/vault/original.glb",hashlib.sha256(GLB).hexdigest(),GLB)
BASELINE=("BASELINE_SNAPSHOT","/vault/approved.glb",
          hashlib.sha256(b"original approved baseline").hexdigest(),
          b"original approved baseline")
def inventory():
    rules={}
    for n,(letter,wording,phase,kind) in AAA.items():
        rid="AAA-200-"+letter+"-%03d"%n
        rules[rid]={
          "family":"AAA-200","catalog_number":n,"catalog_section":letter,
          "catalog_phase":phase,"asset_type":kind,
          "source_sha256":CATALOG_SHA,"requirement":wording,
          "requirement_sha256":hashlib.sha256(wording.encode()).hexdigest(),
        }
    for n,clause in BEHAVIOR.items():
        rid="BEHAVIOR-%03d"%n
        rules[rid]={
          "family":"BEHAVIOR_110","source":"error_registry",
          "source_path":"governance/sources/REGISTRO_110_ERRORI_E_PREVENZIONE.md",
          "source_sha256":REGISTRY_SHA,
          "requirement_sha256":hashlib.sha256(clause.encode()).hexdigest(),
          "requirement":clause,"required_mg0":True,
        }
    return {"schema":"gg-effective-family-inventory-v1","rule_count":763,
            "canonical_master_sha256":MASTER_SHA,
            "source_digests":{"aaa_catalog":CATALOG_SHA,
                              "error_registry":REGISTRY_SHA},
            "rules":rules}
def controller():
    c=Mock()
    c.root=Path("/original-project")
    c.master.read_bytes.return_value=MASTER
    return c

class NativeBatch100Tests(unittest.TestCase):
    def test_100_original_rules_and_no_duplicate_from_prior_lots(self):
        self.assertEqual(len(AAA),40)
        self.assertEqual(len(BEHAVIOR),60)
        self.assertEqual(len(IDS),100)
        self.assertEqual(len(set(IDS)),100)
        pin_sources(inventory())

    def test_all_one_hundred_mutated_original_requirements_rejected(self):
        for rid in IDS:
            with self.subTest(rule=rid):
                inv=inventory()
                inv["rules"][rid]["requirement"]+=" tampered"
                with self.assertRaises(Batch100Blocked):
                    pin_sources(inv)

    def test_100_different_domain_scopes_with_340_predicates(self):
        self.assertEqual(set(AAA),set(AAA_SPEC))
        self.assertEqual(set(AAA),set(AAA_PROBES))
        self.assertEqual(set(BEHAVIOR),set(BEHAVIOR_SPEC))
        self.assertEqual(set(BEHAVIOR),set(BEHAVIOR_PROBES))
        self.assertEqual(sum(map(len,AAA_SPEC.values()))+
                         sum(map(len,BEHAVIOR_SPEC.values())),340)
        for family,scope,probes in (
            ("AAA",AAA_SPEC,AAA_PROBES),
            ("BEHAVIOR",BEHAVIOR_SPEC,BEHAVIOR_PROBES)):
            for n,fields in scope.items():
                with self.subTest(family=family,rule=n):
                    self.assertEqual(len(set(fields)),len(fields))
                    self.assertEqual(len(fields),len(probes[n])+1)
                    self.assertEqual(len(probes[n]),3 if family=="AAA" else 2)

    def test_real_binary_and_baseline_checks_are_observations_only(self):
        read, report=actual_originals([], [GLB_FILE,BASELINE],PLAN,STATE,WORK,
                                     "GOLDEN_GARDEN",STEP,controller(),
                                     lambda _:b"original")
        self.assertEqual(report["source_sha256"],GLB_FILE[1] if False else GLB_FILE[2])
        self.assertTrue(read("R:NATIVE_EXPORT"))
        self.assertTrue(read("X:master"))
        self.assertTrue(read("X:export_changed"))
        self.assertTrue(read("M:triangles"))
        self.assertTrue(read("M:valid_glb"))
        self.assertFalse(read("E:OWNER_APPROVAL"))
        self.assertFalse(read("X:registry"))

    def test_corrupt_native_glb_cannot_be_processed(self):
        raw=b"corrupt native GLB"
        forged=("NATIVE_EXPORT","/vault/asset.glb",
                hashlib.sha256(raw).hexdigest(),raw)
        with self.assertRaisesRegex(Batch100Blocked,"CORRUPT_ORIGINAL_GLB"):
            actual_originals([], [forged],PLAN,STATE,WORK,
                             "GOLDEN_GARDEN",STEP,controller(),lambda _:b"")

    def test_forged_registered_source_digest_blocks(self):
        forged=("NATIVE_EXPORT","/vault/asset.glb","0"*64,GLB)
        with self.assertRaisesRegex(Batch100Blocked,"UNAUTHENTICATED_OR_DUPLICATED"):
            actual_originals([],[forged],PLAN,STATE,WORK,
                             "GOLDEN_GARDEN",STEP,controller(),lambda _:b"")

    def test_cross_attempt_owner_approval_never_counts(self):
        other=[{"event":"OWNER_APPROVAL","attempt_id":"0"*64,
                "operation_sha256":WORK["operation_sha256"],"step":STEP}]
        read,_=actual_originals(other,[],PLAN,STATE,WORK,
                                "GOLDEN_GARDEN",STEP,controller(),lambda _:b"")
        self.assertFalse(read("E:OWNER_APPROVAL"))

    def test_real_current_event_is_not_owner_signature(self):
        rows=[{"event":"OWNER_APPROVAL","attempt_id":WORK["attempt_id"],
               "operation_sha256":WORK["operation_sha256"],"step":STEP}]
        read,_=actual_originals(rows,[],PLAN,STATE,WORK,
                                "GOLDEN_GARDEN",STEP,controller(),lambda _:b"")
        self.assertTrue(read("E:OWNER_APPROVAL"))

    def test_missing_native_bytes_do_not_prove_geometry(self):
        read,report=actual_originals([],[],PLAN,STATE,WORK,
                                     "GOLDEN_GARDEN",STEP,controller(),lambda _:b"")
        self.assertIsNone(report)
        self.assertFalse(read("M:triangles"))
        self.assertFalse(read("X:winding"))
        self.assertFalse(read("R:DELIVERY_PACKAGE"))

    def test_full_source_original_report_is_100_and_no_faked_mg0(self):
        c=controller()
        with patch("c07_batch100_native._original_attempt",
                   return_value=([],"tail",STATE,"original-audit-digest")), \
             patch("c07_batch100_native._registered_artifacts",
                   return_value=[GLB_FILE,BASELINE]):
            r=inspect(inventory(),PLAN,c,"GOLDEN_GARDEN",STEP,WORK,
                      source_loader=lambda _:b"original")
        self.assertEqual(r["schema"],SCHEMA)
        self.assertEqual(r["source_rules_examined"],100)
        self.assertEqual(r["aaa_rules_examined"],40)
        self.assertEqual(r["behavior_rules_examined"],60)
        self.assertEqual(r["native_conditions_evaluated"],340)
        self.assertEqual(r["full_rule_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertEqual(set(r["rules"]),set(IDS))
        for rid,rule in r["rules"].items():
            with self.subTest(rid=rid):
                self.assertEqual(rule["individual_mg0"],"UNKNOWN")
                self.assertEqual(rule["full_rule_semantics"],"UNKNOWN")
                self.assertFalse(rule["advancement_authorized"])
                self.assertEqual(rule["owner_approval"],"UNKNOWN")
                self.assertIn(False,rule["original_native_criteria"].values())

    def test_p0_does_not_certify_p8_qa_or_delivery(self):
        c=controller()
        w=dict(WORK,phase="P0")
        with patch("c07_batch100_native._original_attempt",
                   return_value=([],"tail",STATE,"original-audit-digest")), \
             patch("c07_batch100_native._registered_artifacts",
                   return_value=[GLB_FILE]):
            r=inspect(inventory(),PLAN,c,"GOLDEN_GARDEN",STEP,w,
                      source_loader=lambda _:b"original")
        self.assertEqual(r["rules"]["AAA-200-S-181"]["applicability"],"FUTURE_PHASE")
        self.assertEqual(r["rules"]["AAA-200-T-200"]["applicability"],"FUTURE_PHASE")
        self.assertEqual(r["rules"]["AAA-200-A-001"]["applicability"],"DUE")
        self.assertEqual(r["full_rule_passes"],0)

    def test_live_controller_close_calls_batch100(self):
        s=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_batch100_native import inspect as inspect_batch100",s)
        self.assertIn("SUPERVISOR_C07_BATCH100_ORIGINAL_NATIVE",s)
        self.assertIn("batch100['native_conditions_evaluated'] == 340",s)

if __name__=="__main__":
    unittest.main()

"""Synthetic fixture regression only: NEVER a real asset/owner/MG0 certification."""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import c07_behavior001_025_semantic_replay as gate
from c07_behavior_001_050_canonical import CLAUSES, SOURCE_SHA
from c07_behavior_001_050_spec import SPEC

MASTER=b"TEST_ONLY_MASTER";AUDIT=b"TEST_ONLY_AUDIT"
MSHA=hashlib.sha256(MASTER).hexdigest()
ASHA=hashlib.sha256(AUDIT).hexdigest()
ATTEMPT="a"*64;OP="b"*64;TAIL="c"*64
class Behavior25Tests(unittest.TestCase):
    def setUp(self):
        self.ctrl=Mock()
        self.ctrl.master.read_bytes.return_value=MASTER
        self.ctrl.audit_path.return_value.read_bytes.return_value=AUDIT
        self.inv={"schema":"gg-effective-family-inventory-v1","rule_count":763,
            "canonical_master_sha256":MSHA,
            "source_digests":{"error_registry":SOURCE_SHA},"rules":{}}
        self.rows=[]
        self.native={"schema":gate.NATIVE_SCHEMA,"source_rules_examined":50,
            "native_conditions_evaluated":150,"original_audit_sha256":ASHA,
            "original_audit_tail":TAIL,"attempt_id":ATTEMPT,"operation_sha256":OP,
            "full_rule_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        self.mg={"audit_sha256":ASHA,"audit_tail_sha256":TAIL,
            "attempt_id":ATTEMPT,"rule_count":25,"counts":{"PASS":0},
            "individual_mg0_passes":0,"advancement_authorized":False,"rules":{}}
        for n,rid in enumerate(gate.IDS,1):
            req=CLAUSES[n]
            digest=hashlib.sha256(req.encode("utf-8")).hexdigest()
            self.inv["rules"][rid]={"family":"BEHAVIOR_110",
                "source":"error_registry","source_sha256":SOURCE_SHA,
                "requirement":req,"requirement_sha256":digest,"required_mg0":True}
            names=SPEC[n]
            self.native["rules"][rid]={"rule_id":rid,"canonical_clause":req,
                "source_sha256":SOURCE_SHA,"requirement_sha256":digest,
                "original_machine_checks":{names[0]:True,names[1]:False,names[2]:False},
                "full_prevention_semantics":"UNKNOWN",
                "individual_mg0":"UNKNOWN","owner_approval":"UNKNOWN",
                "advancement_authorized":False}
            self.mg["rules"][rid]={"verdict":"UNKNOWN",
                "uncorrected_failure_count":0,"observation_sha256":TAIL}
        self.ctx={"inventory":self.inv,"plan":{"phase":"P0","master_sha256":MSHA},
            "work":{"phase":"P0","master_sha256":MSHA,"attempt_id":ATTEMPT,
                    "operation_sha256":OP},
            "controller":self.ctrl,"asset":"TEST_ONLY","step":"STEP_ONLY",
            "source_loader":lambda _:b"TEST_ONLY"}
    def run_gate(self):
        with patch.object(gate,"native50",return_value=self.native),\
             patch.object(gate,"mg0_batch",return_value=self.mg),\
             patch.object(gate,"audit_check",return_value=(self.rows,TAIL)):
            return gate.inspect(self.ctx)
    def test_all_25_original_rule_bindings_and_unknowns(self):
        out=self.run_gate()
        self.assertEqual(set(out["rules"]),set(gate.IDS))
        self.assertEqual((out["rule_count"],out["native_facts_checked"]),(25,50))
        self.assertEqual(out["full_rule_semantic_passes"],0)
        self.assertEqual(out["individual_mg0_passes"],0)
        self.assertFalse(out["advancement_authorized"])
        self.assertTrue(all(row["semantic_verdict"]=="UNKNOWN" for row in out["rules"].values()))
    def test_all_25_source_mutations_fail_closed(self):
        for rid in gate.IDS:
            with self.subTest(rid=rid):
                old=self.inv["rules"][rid]["requirement"]
                self.inv["rules"][rid]["requirement"]="ALTERED"
                with self.assertRaisesRegex(gate.Blocked,"ORIGINAL_REQUIREMENT_CHANGED"):
                    self.run_gate()
                self.inv["rules"][rid]["requirement"]=old
    def test_forged_positive_machine_third_clause_rejected(self):
        self.native["rules"][gate.IDS[0]]["original_machine_checks"][SPEC[1][2]]=True
        with self.assertRaisesRegex(gate.Blocked,"MACHINE_OR_ORIGINAL_CLAUSE_DRIFT"):
            self.run_gate()
    def test_forged_full_rule_rejected(self):
        self.native["rules"][gate.IDS[8]]["full_prevention_semantics"]="PASS"
        with self.assertRaisesRegex(gate.Blocked,"MACHINE_OR_ORIGINAL_CLAUSE_DRIFT"):
            self.run_gate()
    def test_forged_mg0_pass_rejected(self):
        self.mg["rules"][gate.IDS[3]]["verdict"]="PASS"
        with self.assertRaisesRegex(gate.Blocked,"INDIVIDUAL_MG0_NEGATIVE_REQUIRED"):
            self.run_gate()
    def test_lost_native_audit_identity_rejected(self):
        self.native["original_audit_sha256"]="0"*64
        with self.assertRaisesRegex(gate.Blocked,"NATIVE_AND_MG0_DIVERGED"):
            self.run_gate()
    def test_bogus_native_evidence_key_rejected(self):
        self.native["rules"][gate.IDS[5]]["original_machine_checks"]["additional_fake"]=True
        with self.assertRaisesRegex(gate.Blocked,"MACHINE_OR_ORIGINAL_CLAUSE_DRIFT"):
            self.run_gate()
    def test_observed_same_attempt_finding_fails_only_its_rule(self):
        rid=gate.IDS[12]
        self.rows=[{"event":"QUALITY_FINDING","result":"FAIL","rule_id":rid,
                    "step":"STEP_ONLY","attempt_id":ATTEMPT,"record_hash":TAIL}]
        out=self.run_gate()
        self.assertEqual(out["rules"][rid]["semantic_verdict"],"FAIL")
        self.assertEqual(out["rules"][gate.IDS[11]]["semantic_verdict"],"UNKNOWN")
    def test_cross_attempt_failure_cannot_be_reused(self):
        self.rows=[{"event":"QUALITY_FINDING","result":"FAIL",
                    "rule_id":gate.IDS[12],"step":"STEP_ONLY",
                    "attempt_id":"d"*64,"record_hash":TAIL}]
        self.assertEqual(self.run_gate()["negative_rule_count"],0)
    def test_independent_mg0_failure_is_not_suppressed(self):
        self.mg["rules"][gate.IDS[24]]["verdict"]="FAIL"
        out=self.run_gate()
        self.assertEqual(out["negative_rule_count"],1)
        self.assertEqual(out["rules"][gate.IDS[24]]["semantic_verdict"],"FAIL")
    def test_missing_master_binding_rejected(self):
        self.ctx["plan"]["master_sha256"]="f"*64
        with self.assertRaisesRegex(gate.Blocked,"ACTIVE_ATTEMPT_REQUIRED"):
            self.run_gate()
    def test_persistent_controller_hook_is_present(self):
        text=Path(__file__).with_name("controlled_judgment.py").read_text("utf-8")
        self.assertIn("from c07_behavior001_025_semantic_replay import inspect as inspect_b25",text)
        self.assertIn("SUPERVISOR_C07_BEHAVIOR001_025_ORIGINAL_SEMANTIC_25",text)
if __name__=="__main__":
    unittest.main()

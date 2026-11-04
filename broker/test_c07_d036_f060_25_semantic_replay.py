"""C07 D036-F060: seventh original 25-rule P1 scope regression tests.

All reader returns are explicitly TEST-ONLY fixtures. No synthetic asset or
signing evidence may be used as an actual rule certification.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import c07_d036_f060_25_semantic_replay as gate
from c07_bf50_canonical import CLAUSES
from c07_bf50_predicates import SPEC

MASTER=b"TEST_ONLY_MASTER"
AUDIT=b"TEST_ONLY_AUDIT"
MASTER_SHA=hashlib.sha256(MASTER).hexdigest()
AUDIT_SHA=hashlib.sha256(AUDIT).hexdigest()
ATTEMPT="b"*64
OPERATION="c"*64
TAIL="a"*64

class D036F060Test(unittest.TestCase):
    def setUp(self):
        c=Mock()
        c.master.read_bytes.return_value=MASTER
        c.audit_path.return_value.read_bytes.return_value=AUDIT
        self.c=c
        self.inv={
            "schema":"gg-effective-family-inventory-v1",
            "rule_count":763,"canonical_master_sha256":MASTER_SHA,
            "source_digests":{"aaa_catalog":gate.CATALOG_SHA},"rules":{}}
        self.work={"phase":"P1","attempt_id":ATTEMPT,
                   "operation_sha256":OPERATION,"master_sha256":MASTER_SHA}
        self.plan={"phase":"P1","master_sha256":MASTER_SHA}
        self.context={
            "inventory":self.inv,"plan":self.plan,"controller":c,
            "asset":"TEST_ONLY","step":"STEP_TEST_ONLY","work":self.work,
            "source_loader":lambda path:b"test fixture"}
        self.bf={
            "schema":gate.BF_SCHEMA,"source_rules_examined":50,
            "native_conditions_evaluated":200,
            "original_audit_sha256":AUDIT_SHA,"original_audit_tail":TAIL,
            "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
            "full_rule_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        self.p1={
            "schema":gate.P1_SCHEMA,"source_rules_examined":30,
            "native_domain_criteria":90,"master_sha256":MASTER_SHA,
            "original_audit_sha256":AUDIT_SHA,"original_audit_tail":TAIL,
            "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
            "full_semantic_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        self.mg={
            "rule_count":25,"counts":{"PASS":0,"UNKNOWN":25,"FAIL":0},
            "audit_sha256":AUDIT_SHA,"audit_tail_sha256":TAIL,
            "attempt_id":ATTEMPT,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        for n,rid in enumerate(gate.IDS,36):
            sec,clause,phase,kind=CLAUSES[n]
            digest=hashlib.sha256(clause.encode()).hexdigest()
            self.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":sec,"catalog_phase":phase,"asset_type":kind,
                "requirement":clause,"requirement_sha256":digest,
                "source_sha256":gate.CATALOG_SHA}
            self.bf["rules"][rid]={
                "rule_id":rid,"canonical_requirement":clause,
                "source_sha256":gate.CATALOG_SHA,
                "requirement_sha256":digest,"applicability":"DUE",
                "original_native_predicates":{k:True for k in SPEC[n]},
                "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
                "owner_approval":"UNKNOWN","advancement_authorized":False}
            self.p1["rules"][rid]={
                "rule_id":rid,"source_sha256":gate.CATALOG_SHA,
                "requirement_sha256":digest,
                "original_native_measured_criteria":{
                    "scene_original_bytes":True,
                    "original_glb_byte_observation":True,
                    "independent_artistic_review":False},
                "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
                "artistic_approval":"UNKNOWN","advancement_authorized":False}
            self.mg["rules"][rid]={
                "verdict":"UNKNOWN","uncorrected_failure_count":0,
                "observation_sha256":hashlib.sha256(rid.encode()).hexdigest()}

    def run_gate(self):
        with patch.object(gate,"inspect_bf",return_value=self.bf),\
             patch.object(gate,"inspect_p1",return_value=self.p1),\
             patch.object(gate,"inspect_mg0",return_value=self.mg):
            return gate.inspect(self.context)

    def test_25_unique_canonical_source_clauses(self):
        gate.canonical(self.inv)
        self.assertEqual(len(gate.IDS),25)
        self.assertEqual(len(set(gate.IDS)),25)
        self.assertEqual(set(gate.TOPICS),set(range(36,61)))
    def test_all_25_original_text_mutations_blocked(self):
        for rid in gate.IDS:
            row=self.inv["rules"][rid];original=row["requirement"]
            row["requirement"]=original+" altered"
            with self.subTest(rid=rid),self.assertRaisesRegex(
                gate.Source25Blocked,"CANONICAL_REQUIREMENT_CHANGED"):
                gate.canonical(self.inv)
            row["requirement"]=original
    def test_original_25_disjoint_previous_150(self):
        previous={"EXEC-%03d"%n for n in range(1,26)}
        for n in list(range(61,111))+list(range(121,171))+list(range(176,201)):
            sec=("G" if n<=70 else "H" if n<=80 else "I" if n<=90
                 else "J" if n<=100 else "K" if n<=110 else "M" if n<=130
                 else "N" if n<=140 else "O" if n<=150 else "P" if n<=160
                 else "Q" if n<=170 else "R" if n<=180 else "S" if n<=190 else "T")
            previous.add("AAA-200-%s-%03d"%(sec,n))
        self.assertFalse(previous&set(gate.IDS))
    def test_25_times_seven_source_checks_without_mg0_pass(self):
        out=self.run_gate()
        self.assertEqual(out["rule_count"],25)
        self.assertEqual(out["actual_machine_subchecks_checked"],175)
        self.assertEqual(out["full_rule_semantic_passes"],0)
        self.assertEqual(out["individual_mg0_passes"],0)
        self.assertFalse(out["advancement_authorized"])
        self.assertTrue(all(x["semantic_verdict"]=="UNKNOWN"
                            for x in out["rules"].values()))
    def test_original_positive_subchecks_not_final_artistic_signoff(self):
        out=self.run_gate()
        self.assertGreater(out["actual_machine_subchecks_observed"],0)
        self.assertTrue(all(
            not x["full_clause_semantic_certified"] and
            not x["independent_mg0_certified"]
            for x in out["rules"].values()))
    def test_specific_mg0_failure_is_retained(self):
        rid=gate.IDS[14]
        self.mg["rules"][rid]["verdict"]="FAIL"
        self.mg["rules"][rid]["uncorrected_failure_count"]=1
        out=self.run_gate()
        self.assertEqual(out["negative_mg0_failures"],1)
        self.assertEqual(out["rules"][rid]["semantic_verdict"],"FAIL")
    def test_fake_positive_mg0_rejected(self):
        self.mg["counts"]["PASS"]=1
        with self.assertRaisesRegex(gate.Source25Blocked,"EVIDENCE_REPLAY_DIVERGED"):
            self.run_gate()
    def test_master_original_byte_mutation_rejected(self):
        self.c.master.read_bytes.return_value=b"DIFFERENT"
        with self.assertRaisesRegex(gate.Source25Blocked,"MASTER_BYTES_CHANGED"):
            self.run_gate()
    def test_original_audit_sha_mutation_rejected(self):
        self.p1["original_audit_sha256"]="f"*64
        with self.assertRaisesRegex(gate.Source25Blocked,"EVIDENCE_REPLAY_DIVERGED"):
            self.run_gate()
    def test_cross_attempt_reader_replay_rejected(self):
        self.bf["attempt_id"]="f"*64
        with self.assertRaisesRegex(gate.Source25Blocked,"EVIDENCE_REPLAY_DIVERGED"):
            self.run_gate()
    def test_original_independent_clause_hash_mismatch_rejected(self):
        self.p1["rules"][gate.IDS[4]]["requirement_sha256"]="f"*64
        with self.assertRaisesRegex(gate.Source25Blocked,"PER_RULE_SOURCE_DRIFT"):
            self.run_gate()
    def test_extra_unverified_predicate_is_rejected(self):
        self.p1["rules"][gate.IDS[7]]["original_native_measured_criteria"]["fake"]=True
        with self.assertRaisesRegex(gate.Source25Blocked,"SEVEN_SEMANTIC_SUBCHECKS"):
            self.run_gate()
    def test_missing_visual_source_does_not_infer_final_pass(self):
        rid=gate.IDS[8]
        for k in self.p1["rules"][rid]["original_native_measured_criteria"]:
            self.p1["rules"][rid]["original_native_measured_criteria"][k]=False
        out=self.run_gate()
        self.assertTrue(out["rules"][rid]["missing_machine_subchecks"])
        self.assertFalse(out["rules"][rid]["full_clause_semantic_certified"])
    def test_p0_prohibited_before_canonical_p1(self):
        self.work["phase"]=self.plan["phase"]="P0"
        with self.assertRaisesRegex(gate.Source25Blocked,"CURRENT_PHASE_ATTEMPT_REQUIRED"):
            self.run_gate()
    def test_controller_close_hook_is_present(self):
        text=Path(__file__).with_name("controlled_judgment.py").read_text("utf-8")
        for phrase in (
            "from c07_d036_f060_25_semantic_replay import inspect as inspect_df25",
            "SUPERVISOR_C07_D036_F060_ORIGINAL_SEMANTIC_25",
            "C07_D036_F060_SOURCE_REPLAY_REQUIRED",
            "scope_original=df25['rules']",
            "full_rule_semantic_passes=0,individual_mg0_passes=0"):
            with self.subTest(phrase=phrase):self.assertIn(phrase,text)

if __name__=="__main__":unittest.main()

"""C07 fifth 25 P2 semantic macro: original-source identity and adversarial gates.

Synthetic in-memory test data only; neither real asset proof nor owner MG0 PASS.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
import c07_i086_k110_25_semantic_replay as gate
from c07_gk50_canonical import CLAUSES
from c07_gk50_predicates import SPEC

MASTER=b"TEST_ONLY_MASTER_NOT_USER_DATA"
AUDIT=b"TEST_ONLY_AUDIT_NOT_REAL_ASSET"
MASTER_SHA=hashlib.sha256(MASTER).hexdigest()
AUDIT_SHA=hashlib.sha256(AUDIT).hexdigest()
TAIL="a"*64
ATTEMPT="b"*64
OPERATION="c"*64

class I086K110Test(unittest.TestCase):
    def setUp(self):
        self.c=Mock()
        self.c.master.read_bytes.return_value=MASTER
        self.c.audit_path.return_value.read_bytes.return_value=AUDIT
        self.inv={
            "schema":"gg-effective-family-inventory-v1","rule_count":763,
            "canonical_master_sha256":MASTER_SHA,
            "source_digests":{"aaa_catalog":gate.CATALOG_SHA},
            "rules":{}}
        self.type="organic"
        self.work={
            "asset_type":self.type,"phase":"P2",
            "master_sha256":MASTER_SHA,
            "attempt_id":ATTEMPT,"operation_sha256":OPERATION}
        self.plan={
            "asset_type":self.type,"phase":"P2","master_sha256":MASTER_SHA}
        self.context={
            "inventory":self.inv,"plan":self.plan,"work":self.work,
            "controller":self.c,"asset":"TEST_ASSET","step":"TEST_STEP",
            "source_loader":lambda path:b"test-only-original-file"}
        self.gk={
            "schema":gate.GK_SCHEMA,
            "source_rules_examined":50,"native_conditions_evaluated":175,
            "original_audit_sha256":AUDIT_SHA,"original_audit_tail":TAIL,
            "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
            "full_rule_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        self.p2={
            "schema":gate.P2_SCHEMA,
            "canonical_source_rule_count":50,"named_domain_probes":100,
            "master_sha256":MASTER_SHA,
            "original_audit_sha256":AUDIT_SHA,"original_audit_tail":TAIL,
            "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
            "full_semantic_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        self.mg={
            "rule_count":25,"counts":{"PASS":0,"FAIL":0,"UNKNOWN":25},
            "audit_sha256":AUDIT_SHA,"audit_tail_sha256":TAIL,
            "attempt_id":ATTEMPT,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        for n,rid in enumerate(gate.IDS,86):
            sec,clause,phase,kind=CLAUSES[n]
            requirement_sha=hashlib.sha256(clause.encode("utf-8")).hexdigest()
            self.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":sec,"catalog_phase":phase,
                "asset_type":kind,"source_sha256":gate.CATALOG_SHA,
                "requirement":clause,"requirement_sha256":requirement_sha}
            self.gk["rules"][rid]={
                "rule_id":rid,"canonical_requirement":clause,
                "source_sha256":gate.CATALOG_SHA,
                "requirement_sha256":requirement_sha,
                "native_byte_checks":{k:True for k in SPEC[n]},
                "applicability":"DUE" if kind==self.type else "N_A_ASSET_TYPE",
                "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
                "owner_approval":"UNKNOWN","advancement_authorized":False}
            self.p2["rules"][rid]={
                "rule_id":rid,"source_sha256":gate.CATALOG_SHA,
                "requirement_sha256":requirement_sha,
                "source_asset_type":kind,"current_asset_type":self.type,
                "applicability":"DUE" if kind==self.type else "N_A_ASSET_TYPE",
                "original_native_domain_predicates":({
                    "actual_original_byte_source_reopened":True,
                    "independent_qa_source_verified":False
                } if kind==self.type else {}),
                "full_rule_semantics":"UNKNOWN" if kind==self.type else "NOT_DUE",
                "individual_mg0":"UNKNOWN" if kind==self.type else "NOT_DUE",
                "owner_approval":"UNKNOWN","advancement_authorized":False}
            self.mg["rules"][rid]={
                "verdict":"UNKNOWN","uncorrected_failure_count":0,
                "observation_sha256":hashlib.sha256(rid.encode()).hexdigest()}

    def set_asset_type(self,kind):
        self.type=kind
        self.work["asset_type"]=self.plan["asset_type"]=kind
        for rid in gate.IDS:
            row=self.p2["rules"][rid]
            due=row["source_asset_type"]==kind
            row["current_asset_type"]=kind
            row["applicability"]="DUE" if due else "N_A_ASSET_TYPE"
            row["original_native_domain_predicates"]=({
                "actual_original_byte_source_reopened":True,
                "independent_qa_source_verified":False
            } if due else {})
            row["full_rule_semantics"]="UNKNOWN" if due else "NOT_DUE"
            row["individual_mg0"]="UNKNOWN" if due else "NOT_DUE"
            self.gk["rules"][rid]["applicability"]=row["applicability"]

    def replay(self):
        with patch.object(gate,"inspect_gk",return_value=self.gk),\
             patch.object(gate,"inspect_p2",return_value=self.p2),\
             patch.object(gate,"inspect_mg0",return_value=self.mg):
            return gate.inspect(self.context)

    def test_exact_25_original_rules_nonduplicate_previous_100(self):
        gate.canonical(self.inv)
        self.assertEqual(len(gate.IDS),25)
        self.assertEqual(len(set(gate.IDS)),25)
        self.assertEqual(set(gate.TOPICS),set(range(86,111)))
        previous={"EXEC-%03d"%n for n in range(1,26)}
        previous.update("AAA-200-%s-%03d"%(
             "M" if n<=130 else "N" if n<=140 else "O",n)
             for n in range(121,146))
        previous.update("AAA-200-%s-%03d"%(
             "O" if n<=150 else "P" if n<=160 else "Q",n)
             for n in range(146,171))
        previous.update("AAA-200-%s-%03d"%(
             "R" if n<=180 else "S" if n<=190 else "T",n)
             for n in range(176,201))
        self.assertFalse(set(gate.IDS)&previous)

    def test_all_25_source_clause_mutations_are_rejected(self):
        for rid in gate.IDS:
            old=self.inv["rules"][rid]["requirement"]
            self.inv["rules"][rid]["requirement"]=old+" FORGED"
            with self.subTest(rid=rid),self.assertRaisesRegex(
                gate.CohortBlocked,"CANONICAL_CLAUSE_CHANGED"):
                gate.canonical(self.inv)
            self.inv["rules"][rid]["requirement"]=old

    def test_organic_five_due_twenty_not_applicable(self):
        result=self.replay()
        self.assertEqual(result["rule_count"],25)
        self.assertEqual(result["due_rules"],5)
        self.assertEqual(result["not_applicable_rules"],20)
        self.assertEqual(result["machine_subcriteria_checked"],
             sum(len(SPEC[n])+2 for n in range(86,91)))
        self.assertEqual(result["independent_mg0_passes"],0)
        self.assertEqual(result["full_rule_semantic_passes"],0)
        self.assertFalse(result["advancement_authorized"])

    def test_vegetation_ten_due_rock_and_terrain_not_counted(self):
        self.set_asset_type("vegetation")
        result=self.replay()
        self.assertEqual(result["due_rules"],10)
        self.assertEqual(result["not_applicable_rules"],15)
        for rid in result["rules"]:
            if rid.startswith("AAA-200-I") or rid.startswith("AAA-200-K"):
                self.assertEqual(result["rules"][rid]["machine_subcriteria"],{})

    def test_terrain_ten_due_with_independent_source_audit(self):
        self.set_asset_type("terrain")
        result=self.replay()
        self.assertEqual(result["due_rules"],10)
        self.assertEqual(result["not_applicable_rules"],15)
        for row in result["rules"].values():
            if row["applicability"]=="DUE":
                self.assertTrue(any(x.startswith("independent:")
                                    for x in row["machine_subcriteria"]))
                self.assertFalse(row["individual_mg0_certified"])

    def test_architecture_none_due_must_never_count_as_positive(self):
        self.set_asset_type("architecture")
        result=self.replay()
        self.assertEqual(result["due_rules"],0)
        self.assertEqual(result["machine_subcriteria_checked"],0)
        self.assertEqual(result["machine_positive_subcriteria"],0)
        self.assertFalse(any(v["original_full_clause_certified"]
                             for v in result["rules"].values()))

    def test_true_machine_subcriteria_are_not_full_semantics(self):
        result=self.replay()
        self.assertGreater(result["machine_positive_subcriteria"],0)
        self.assertEqual(result["full_rule_semantic_passes"],0)
        self.assertEqual(result["independent_mg0_passes"],0)

    def test_a_real_mg0_fail_is_rule_specific(self):
        rid=gate.IDS[2]
        self.mg["rules"][rid]["verdict"]="FAIL"
        self.mg["rules"][rid]["uncorrected_failure_count"]=1
        r=self.replay()
        self.assertEqual(r["independent_negative_mg0_failures"],1)
        self.assertEqual(r["rules"][rid]["source_semantics_verdict"],"FAIL")

    def test_fake_mg0_pass_blocks_batch(self):
        self.mg["counts"]["PASS"]=1
        with self.assertRaisesRegex(gate.CohortBlocked,"READBACK_ENGINES_DISAGREE"):
            self.replay()

    def test_changed_source_bytes_block_batch(self):
        self.c.master.read_bytes.return_value=b"not original"
        with self.assertRaisesRegex(gate.CohortBlocked,"ORIGINAL_MASTER_CHANGED"):
            self.replay()

    def test_audit_sha_drift_blocks_batch(self):
        self.gk["original_audit_sha256"]="f"*64
        with self.assertRaisesRegex(gate.CohortBlocked,"READBACK_ENGINES_DISAGREE"):
            self.replay()

    def test_other_attempt_reader_blocks_batch(self):
        self.p2["attempt_id"]="f"*64
        with self.assertRaisesRegex(gate.CohortBlocked,"READBACK_ENGINES_DISAGREE"):
            self.replay()

    def test_untrusted_independent_clause_or_asset_type_blocks(self):
        self.p2["rules"][gate.IDS[0]]["source_asset_type"]="architecture"
        with self.assertRaisesRegex(gate.CohortBlocked,"DIFFERENT_ORIGINAL_RULE_OR_TYPE"):
            self.replay()

    def test_false_qa_for_other_asset_type_is_not_accepted(self):
        self.p2["rules"][gate.IDS[-1]]["original_native_domain_predicates"]={
            "forged":True}
        with self.assertRaisesRegex(gate.CohortBlocked,"ORIGINAL_RULE_EVIDENCE_REQUIRED"):
            self.replay()

    def test_controller_has_actual_p2_close_macro_wiring(self):
        code=Path(__file__).with_name("controlled_judgment.py").read_text("utf-8")
        for marker in (
            "from c07_i086_k110_25_semantic_replay import inspect as inspect_ik25",
            "SUPERVISOR_C07_I086_K110_ORIGINAL_SEMANTIC_25",
            "C07_I086_K110_REPLAY_REQUIRED",
            "original_scope=ik25['rules']",
            "full_rule_semantic_passes=0,individual_mg0_passes=0",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker,code)

if __name__=="__main__":
    unittest.main()

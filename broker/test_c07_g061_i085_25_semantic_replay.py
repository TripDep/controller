"""C07 G061-I085: 25 original clauses and fail-closed source test fixtures.

TEST ONLY: simulated reader responses do not represent real assets or MG0 PASS.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

import c07_g061_i085_25_semantic_replay as gate
from c07_gk50_canonical import CLAUSES
from c07_gk50_predicates import SPEC
from test_c07_i086_k110_25_semantic_replay import I086K110Test as Fixture

class G061I085Test(unittest.TestCase):
    def setUp(self):
        f=Fixture("test_exact_25_original_rules_nonduplicate_previous_100")
        f.setUp()
        f.work["asset_type"]=f.plan["asset_type"]="architecture"
        f.inv["rules"]={};f.gk["rules"]={};f.p2["rules"]={};f.mg["rules"]={}
        self.f=f
        for n,rid in enumerate(gate.IDS,61):
            sec,clause,phase,kind=CLAUSES[n]
            digest=hashlib.sha256(clause.encode()).hexdigest()
            due=kind=="architecture"
            f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":sec,"catalog_phase":phase,
                "asset_type":kind,"requirement":clause,
                "requirement_sha256":digest,
                "source_sha256":gate.CATALOG_SHA}
            f.gk["rules"][rid]={
                "rule_id":rid,"source_sha256":gate.CATALOG_SHA,
                "requirement_sha256":digest,"canonical_requirement":clause,
                "applicability":"DUE" if due else "N_A_ASSET_TYPE",
                "native_byte_checks":{name:True for name in SPEC[n]},
                "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
                "owner_approval":"UNKNOWN","advancement_authorized":False}
            f.p2["rules"][rid]={
                "rule_id":rid,"source_sha256":gate.CATALOG_SHA,
                "requirement_sha256":digest,"source_asset_type":kind,
                "current_asset_type":"architecture",
                "applicability":"DUE" if due else "N_A_ASSET_TYPE",
                "original_native_domain_predicates":(
                  {"file_source_read":True,"real_visual_qa_complete":False}
                  if due else {}),
                "full_rule_semantics":"UNKNOWN" if due else "NOT_DUE",
                "individual_mg0":"UNKNOWN" if due else "NOT_DUE",
                "owner_approval":"UNKNOWN","advancement_authorized":False}
            f.mg["rules"][rid]={
                "verdict":"UNKNOWN","uncorrected_failure_count":0,
                "observation_sha256":hashlib.sha256(rid.encode()).hexdigest()}
    def set_type(self,kind):
        f=self.f
        f.work["asset_type"]=f.plan["asset_type"]=kind
        for rid in gate.IDS:
            a=f.gk["rules"][rid];b=f.p2["rules"][rid]
            due=b["source_asset_type"]==kind
            a["applicability"]=b["applicability"]=(
                "DUE" if due else "N_A_ASSET_TYPE")
            b["current_asset_type"]=kind
            b["original_native_domain_predicates"]=(
                {"file_source_read":True,"real_visual_qa_complete":False}
                if due else {})
            b["full_rule_semantics"]=b["individual_mg0"]=(
                "UNKNOWN" if due else "NOT_DUE")
    def inspect(self):
        f=self.f
        with patch.object(gate,"inspect_gk",return_value=f.gk),\
             patch.object(gate,"inspect_p2",return_value=f.p2),\
             patch.object(gate,"inspect_mg0",return_value=f.mg):
            return gate.inspect(f.context)

    def test_25_canonical_unique(self):
        gate.canonical(self.f.inv)
        self.assertEqual(len(gate.IDS),len(set(gate.IDS)))
        self.assertEqual(len(gate.IDS),25)
    def test_no_duplicate_previous_125(self):
        previous={"EXEC-%03d"%n for n in range(1,26)}
        for n in list(range(86,111))+list(range(121,171))+list(range(176,201)):
            sec=("I" if n<=90 else "J" if n<=100 else "K" if n<=110
                 else "M" if n<=130 else "N" if n<=140 else "O" if n<=150
                 else "P" if n<=160 else "Q" if n<=170 else "R" if n<=180
                 else "S" if n<=190 else "T")
            previous.add("AAA-200-%s-%03d"%(sec,n))
        self.assertFalse(set(gate.IDS)&previous)
    def test_each_original_clause_mutation_blocked(self):
        for rid in gate.IDS:
            row=self.f.inv["rules"][rid];real=row["requirement"]
            row["requirement"]=real+" altered"
            with self.subTest(rule=rid),self.assertRaisesRegex(
                  gate.Original25Blocked,"ORIGINAL_CLAUSE_CHANGED"):
                gate.canonical(self.f.inv)
            row["requirement"]=real
    def test_architecture_20_due(self):
        out=self.inspect()
        self.assertEqual((out["due_rules"],out["nonapplicable_rules"]),(20,5))
        self.assertEqual(out["machine_subconditions_checked"],
            sum(len(SPEC[n])+2 for n in range(61,81)))
        self.assertEqual(out["independent_mg0_passes"],0)
        self.assertEqual(out["full_rule_semantic_passes"],0)
    def test_organic_5_due(self):
        self.set_type("organic");out=self.inspect()
        self.assertEqual((out["due_rules"],out["nonapplicable_rules"]),(5,20))
        self.assertEqual(out["machine_subconditions_checked"],
            sum(len(SPEC[n])+2 for n in range(81,86)))
    def test_vegetation_none_due(self):
        self.set_type("vegetation");out=self.inspect()
        self.assertEqual(out["due_rules"],0)
        self.assertEqual(out["machine_subconditions_observed"],0)
    def test_terrain_none_due(self):
        self.set_type("terrain");out=self.inspect()
        self.assertEqual(out["due_rules"],0)
        self.assertTrue(all(not row["original_machine_predicates"]
                         for row in out["rules"].values()))
    def test_positive_subchecks_do_not_grant_full_rule(self):
        out=self.inspect()
        self.assertGreater(out["machine_subconditions_observed"],0)
        self.assertTrue(all(not x["full_original_semantics_certified"]
                            for x in out["rules"].values()))
    def test_rule_specific_mg0_negative_is_preserved(self):
        rid=gate.IDS[12]
        self.f.mg["rules"][rid]["verdict"]="FAIL"
        self.f.mg["rules"][rid]["uncorrected_failure_count"]=1
        out=self.inspect()
        self.assertEqual(out["original_mg0_negative_failures"],1)
        self.assertEqual(out["rules"][rid]["original_semantic_verdict"],"FAIL")
    def test_fake_signed_mg0_pass_rejected(self):
        self.f.mg["counts"]["PASS"]=1
        with self.assertRaisesRegex(gate.Original25Blocked,"READERS_DIVERGED"):
            self.inspect()
    def test_master_byte_mutation_rejected(self):
        self.f.c.master.read_bytes.return_value=b"not original"
        with self.assertRaisesRegex(gate.Original25Blocked,"ORIGINAL_MASTER_CHANGED"):
            self.inspect()
    def test_audit_digest_mutation_rejected(self):
        self.f.p2["original_audit_sha256"]="f"*64
        with self.assertRaisesRegex(gate.Original25Blocked,"READERS_DIVERGED"):
            self.inspect()
    def test_cross_attempt_evidence_rejected(self):
        self.f.gk["attempt_id"]="f"*64
        with self.assertRaisesRegex(gate.Original25Blocked,"READERS_DIVERGED"):
            self.inspect()
    def test_misassigned_asset_type_rejected(self):
        self.f.p2["rules"][gate.IDS[0]]["source_asset_type"]="organic"
        with self.assertRaisesRegex(gate.Original25Blocked,"WRONG_ORIGINAL_RULE_OR_ASSET"):
            self.inspect()
    def test_additional_unverified_predicate_rejected(self):
        rid=gate.IDS[0]
        self.f.p2["rules"][rid]["original_native_domain_predicates"]["forged"]=True
        with self.assertRaisesRegex(gate.Original25Blocked,"PREDICATES_INVALID"):
            self.inspect()
    def test_source_fails_open_never_implies_visual_pass(self):
        rid=gate.IDS[17]
        row=self.f.p2["rules"][rid]["original_native_domain_predicates"]
        row["file_source_read"]=False
        out=self.inspect()
        self.assertIn("independent:file_source_read",
                       out["rules"][rid]["unproven_source_subconditions"])
        self.assertFalse(out["rules"][rid]["full_original_semantics_certified"])
    def test_real_controller_close_entrypoint_exists(self):
        source=Path(__file__).with_name("controlled_judgment.py").read_text("utf-8")
        for needle in ("from c07_g061_i085_25_semantic_replay import inspect as inspect_gi25",
                       "SUPERVISOR_C07_G061_I085_ORIGINAL_SEMANTIC_25",
                       "C07_G061_I085_REPLAY_REQUIRED",
                       "original_scope=gi25['rules']",
                       "full_rule_semantic_passes=0,individual_mg0_passes=0"):
            with self.subTest(needle=needle):
                self.assertIn(needle,source)

if __name__=="__main__":unittest.main()

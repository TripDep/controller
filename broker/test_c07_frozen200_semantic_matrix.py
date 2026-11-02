"""Adversarial source-level tests for all 200 original semantic obligations.

Synthetic fixtures verify joins and trust boundaries only. Passing these
tests is not real behavioral compliance, source-specific reviewer PASS or MG0.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from c07_positive200_evidence import R122_FROZEN_IDS
from c07_frozen200_semantic_matrix import inspect,FullMatrixBlocked,SCHEMA

MASTER=b"original synthetic master"
SHA=hashlib.sha256(MASTER).hexdigest()
WORK={"master_sha256":SHA,"attempt_id":"a"*64,"operation_sha256":"b"*64}
STEP="STEP042"
STATE={"last_audit_hash":"tail5","active_step":{"step":STEP}}
ORIGINAL_CHAIN=[{"record_hash":"tail"+str(i)} for i in range(1,6)]
def fixture():
    records={};bad={};gaps={};first={};last={};execs={}
    for rid in R122_FROZEN_IDS:
        requirement="The original source clause for "+rid
        hashed=hashlib.sha256(requirement.encode()).hexdigest()
        records[rid]={"family":"BEHAVIOR_110" if rid.startswith("BEHAVIOR-")
                      else "EXECUTION" if rid.startswith("EXEC-")
                      else "GOVERNANCE",
                      "source_sha256":SHA,"requirement_sha256":hashed}
        category=("ERROR_PREVENTION" if rid.startswith("BEHAVIOR-")
                  else "EXECUTION_REQUIREMENT" if rid.startswith("EXEC-")
                  else "CANONICAL_GOVERNANCE_OR_ASSET")
        bad[rid]={"rule_id":rid,"source_sha256":SHA,
                  "requirement_sha256":hashed,
                  "semantic_kind":category,
                  "original_required_prevention":"exact original prevention "+rid,
                  "original_prohibited_error":(
                      "forbidden original error "+rid
                      if rid.startswith("BEHAVIOR-") else None),
                  "semantic_result":"UNKNOWN",
                  "current_attempt_mg0_result":"UNKNOWN"}
        gaps[rid]={"rule_id":rid,"source_sha256":SHA,
                   "requirement_sha256":hashed,
                   "full_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
                   "work_pass":False,"missing_evidence":["CURRENT_REAL_INDEPENDENT_MG0"],
                   "machine_scoped_positive_observed":False,
                   "canonical_clause_count":1,
                   "source_decomposition":"SINGLE_SOURCE_OBLIGATION_REVIEW_PENDING"}
        evidence={"rule_id":rid,"source_sha256":SHA,
                  "requirement_sha256":hashed}
        if rid.startswith("BEHAVIOR-"):
            n=int(rid.rsplit("-",1)[-1])
            if n<=50:
                first[rid]={**evidence,"original_machine_checks":{
                    "actual_audit_readback":True,
                    "prevention_actually_enforced":False,
                    "owner_acceptance_independent":False}}
            else:
                last[rid]={**evidence,"original_native_criteria":{
                    "actual_provenance_checked":True,
                    "prevention_runtime_verified":False,
                    "owner_acceptance_independent":False}}
        elif rid.startswith("EXEC-"):
            execs[rid]={**evidence,"independent_outcome_checks":{
                "real_source_readback":True,
                "actual_measurable_result_proven":False}}
    # Original inventory is always 763, even though this cohort contains 200.
    for i in range(563):
        rid="OTHER_ORIGINAL_%03d"%i
        wording="Outside current frozen cohort "+rid
        records[rid]={"family":"OTHER","source_sha256":SHA,
            "requirement_sha256":hashlib.sha256(wording.encode()).hexdigest()}
    inv={"schema":"gg-effective-family-inventory-v1","rule_count":763,
         "canonical_master_sha256":SHA,"rules":records}
    ctrl=Mock()
    ctrl.master.read_bytes.return_value=MASTER
    def data(rules,tail):
        return {"rules":rules,"attempt_id":WORK["attempt_id"],
                "operation_sha256":WORK["operation_sha256"],
                "original_audit_tail":tail,
                "individual_mg0_passes":0,
                "advancement_authorized":False}
    reports={
        "semantic200":data(bad,"tail1"),
        "exec25":data(execs,"tail2"),
        "behavior_first50":data(first,"tail3"),
        "behavior_last60":data(last,"tail4"),
        "positive200":{**data(gaps,"tail5"),
                       "original_controller_audit_tail":"tail5"}
    }
    return inv,ctrl,reports

def evaluate(inv,ctrl,reports):
    with patch("c07_frozen200_semantic_matrix._original_attempt",
               return_value=(ORIGINAL_CHAIN,"tail5",STATE,"real_audit_digest")):
        return inspect(inv,{"master_sha256":SHA},ctrl,
                       "GOLDEN_GARDEN",STEP,WORK,**reports)

class SemanticMatrix200Tests(unittest.TestCase):
    def test_200_distinct_real_source_buckets_and_full_gap_accounting(self):
        inv,ctrl,reports=fixture()
        r=evaluate(inv,ctrl,reports)
        self.assertEqual(r["schema"],SCHEMA)
        self.assertEqual(r["source_rule_count"],200)
        self.assertEqual(r["source_groups"],{
            "BEHAVIOR":110,"EXEC":25,"OTHER":65})
        self.assertEqual(r["current_unknowns"],200)
        self.assertEqual(r["full_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertEqual(len(r["rules"]),200)
        self.assertFalse(r["advancement_authorized"])

    def test_actual_original_counterexample_is_fail_not_false_pass(self):
        inv,ctrl,reports=fixture()
        rid="BEHAVIOR-001"
        reports["semantic200"]["rules"][rid]["semantic_result"]="FAIL"
        r=evaluate(inv,ctrl,reports)
        self.assertEqual(r["current_failures"],1)
        self.assertEqual(r["current_unknowns"],199)
        self.assertEqual(r["rules"][rid]["semantic_decision"],"FAIL")

    def test_all_200_changed_original_source_digests_are_blocked(self):
        inv,ctrl,reports=fixture()
        for rid in R122_FROZEN_IDS:
            with self.subTest(rule=rid):
                old=reports["semantic200"]["rules"][rid]["source_sha256"]
                reports["semantic200"]["rules"][rid]["source_sha256"]="0"*64
                with self.assertRaises(FullMatrixBlocked):
                    evaluate(inv,ctrl,reports)
                reports["semantic200"]["rules"][rid]["source_sha256"]=old

    def test_any_one_missing_behavior_prevention_proof_blocks(self):
        inv,ctrl,reports=fixture()
        del reports["behavior_last60"]["rules"]["BEHAVIOR-110"]
        with self.assertRaises(FullMatrixBlocked):
            evaluate(inv,ctrl,reports)

    def test_any_missing_exec_positive_scope_blocks(self):
        inv,ctrl,reports=fixture()
        del reports["exec25"]["rules"]["EXEC-025"]
        with self.assertRaises(FullMatrixBlocked):
            evaluate(inv,ctrl,reports)

    def test_false_semantic_pass_is_not_relabelled_as_real(self):
        inv,ctrl,reports=fixture()
        reports["semantic200"]["rules"]["EXEC-001"]["semantic_result"]="PASS"
        with self.assertRaises(FullMatrixBlocked):
            evaluate(inv,ctrl,reports)

    def test_old_attempt_replay_blocks_original_source(self):
        inv,ctrl,reports=fixture()
        reports["behavior_first50"]["attempt_id"]="f"*64
        with self.assertRaises(FullMatrixBlocked):
            evaluate(inv,ctrl,reports)

    def test_audit_tail_not_in_original_history_blocks(self):
        inv,ctrl,reports=fixture()
        reports["positive200"]["original_controller_audit_tail"]="not-audit-tail"
        with self.assertRaises(FullMatrixBlocked):
            evaluate(inv,ctrl,reports)

    def test_live_controller_integration_uses_one_200_ledger(self):
        s=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_frozen200_semantic_matrix import inspect as inspect_semantic_matrix",s)
        self.assertIn("SUPERVISOR_C07_FROZEN200_CONSOLIDATED_SEMANTIC_EVIDENCE",s)
        self.assertIn("'BEHAVIOR':110,'EXEC':25,'OTHER':65",s)

if __name__=="__main__":
    unittest.main()

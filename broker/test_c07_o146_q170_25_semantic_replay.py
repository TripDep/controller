"""C07 O146..Q170: 25 individual source clauses and actual Controller audit integration.

The source readers are isolated by explicitly marked TEST-ONLY fixture reports.
No synthetic result is MG0, original asset evidence or actual FiveM PASS.
"""
import hashlib
import unittest
from unittest.mock import Mock,patch
from pathlib import Path

import c07_o146_q170_25_semantic_replay as gate
from c07_m121_q170_fifty_native import (
    IDS as MQ_IDS,CLAUSES as MQ_CLAUSES,RULE_PREDICATES as MQ_PREDICATES)
from c07_p345_forty_native_evidence import (
    IDS as P345_IDS,TEXT as P345_TEXT)
from c07_p678_forty_native_domain import (
    IDS as P678_IDS,TEXT as P678_TEXT)

MASTER=b"TEST_ONLY_MASTER_NOT_USER_SOURCE"
AUDIT=b"TEST_ONLY_AUDIT_NO_REAL_ASSET"
MASTER_SHA=hashlib.sha256(MASTER).hexdigest()
AUDIT_SHA=hashlib.sha256(AUDIT).hexdigest()
TAIL="a"*64
ATTEMPT="b"*64
OPERATION="c"*64

class O146Q170Test(unittest.TestCase):
    def setUp(self):
        self.c=Mock()
        self.c.master.read_bytes.return_value=MASTER
        self.c.audit_path.return_value.read_bytes.return_value=AUDIT
        self.inv={
           "schema":"gg-effective-family-inventory-v1",
           "rule_count":763,
           "canonical_master_sha256":MASTER_SHA,
           "source_digests":{"aaa_catalog":gate.CATALOG_SHA},
           "rules":{}}
        for n,rid in enumerate(gate.IDS,146):
            clause=gate.CLAUSES[rid]
            self.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":rid.split("-")[2],
                "catalog_phase":gate.REQUIRED_PHASE[rid],
                "asset_type":"all","source_sha256":gate.CATALOG_SHA,
                "requirement":clause,
                "requirement_sha256":hashlib.sha256(clause.encode()).hexdigest()}
        self.work={"phase":"P5","master_sha256":MASTER_SHA,
                   "attempt_id":ATTEMPT,"operation_sha256":OPERATION}
        self.plan={"phase":"P5","master_sha256":MASTER_SHA}
        self.context={"inventory":self.inv,"plan":self.plan,
                      "controller":self.c,"asset":"TEST_ASSET",
                      "step":"TEST_STEP","work":self.work,
                      "source_loader":lambda p:b"test-only"}
        self.mq={
            "schema":gate.MQ_SCHEMA,"source_rules_examined":50,
            "native_predicates_evaluated":180,
            "original_audit_sha256":AUDIT_SHA,"original_audit_tail":TAIL,
            "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
            "full_rule_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        self.p345={
            "schema":gate.P345_SCHEMA,"source_rule_count":40,
            "native_named_domain_checks":80,"master_sha256":MASTER_SHA,
            "original_audit_sha256":AUDIT_SHA,"original_audit_tail":TAIL,
            "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
            "full_rule_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        self.p678={
            "schema":gate.P678_SCHEMA,"source_rule_count":40,
            "named_machine_criteria":80,"master_sha256":MASTER_SHA,
            "original_audit_sha256":AUDIT_SHA,"original_audit_tail":TAIL,
            "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
            "full_semantic_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        self.mg0={"rule_count":25,"audit_sha256":AUDIT_SHA,
                  "audit_tail_sha256":TAIL,"attempt_id":ATTEMPT,
                  "counts":{"PASS":0,"FAIL":0,"UNKNOWN":25},
                  "individual_mg0_passes":0,
                  "advancement_authorized":False,"rules":{}}
        for n,rid in enumerate(MQ_IDS,121):
            clause=MQ_CLAUSES[n]
            self.mq["rules"][rid]={
                "rule_id":rid,"canonical_requirement":clause,
                "canonical_source_sha256":gate.CATALOG_SHA,
                "requirement_sha256":hashlib.sha256(clause.encode()).hexdigest(),
                "original_native_predicates":{
                    k:True for k in MQ_PREDICATES[n]},
                "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
                "owner_approval":"UNKNOWN","advancement_authorized":False}
        for rid in P345_IDS:
            n=int(rid.split("-")[-1])
            clause,phase=P345_TEXT[str(n)]
            self.p345["rules"][rid]=self.independent_row(rid,clause,phase,
                                                         kind="p345")
        for rid in P678_IDS:
            n=int(rid.split("-")[-1])
            clause,phase=P678_TEXT[str(n)]
            self.p678["rules"][rid]=self.independent_row(rid,clause,phase,
                                                         kind="p678")
        for rid in gate.IDS:
            self.mg0["rules"][rid]={
                "verdict":"UNKNOWN","uncorrected_failure_count":0,
                "observation_sha256":hashlib.sha256(rid.encode()).hexdigest()}
    def independent_row(self,rid,clause,phase,kind):
        due=gate.PHASE_INDEX[self.work["phase"]]>=int(phase[1])
        return {
            "rule_id":rid,"source_sha256":gate.CATALOG_SHA,
            "requirement_sha256":hashlib.sha256(clause.encode()).hexdigest(),
            "earliest_phase":phase,
            "applicability":"DUE" if due else "FUTURE_PHASE",
            ("machine_observations" if kind=="p345" else
             "native_original_machine_evidence"):({
                "independent_original_byte_read":True,
                "independent_actual_test_proven":False
             } if due else {}),
            "full_rule_semantics":"UNKNOWN" if due else "NOT_DUE",
            "individual_mg0":"UNKNOWN" if due else "NOT_DUE",
            "owner_acceptance":"UNKNOWN","advancement_authorized":False}
    def set_phase(self,phase):
        self.work["phase"]=self.plan["phase"]=phase
        for results,kind in [(self.p345,"p345"),(self.p678,"p678")]:
            for rid,r in results["rules"].items():
                n=int(rid.split("-")[-1])
                text,need=(P345_TEXT if kind=="p345" else P678_TEXT)[str(n)]
                results["rules"][rid]=self.independent_row(rid,text,need,kind)
    def replay(self):
        with patch.object(gate,"inspect_mq",return_value=self.mq),\
             patch.object(gate,"inspect_p345",return_value=self.p345),\
             patch.object(gate,"inspect_p678",return_value=self.p678),\
             patch.object(gate,"inspect_mg0",return_value=self.mg0):
            return gate.inspect(self.context)

    def test_exact_25_canonical_source_clauses_and_nonduplicate_cohort(self):
        gate.canonical(self.inv)
        self.assertEqual(len(gate.IDS),25)
        self.assertEqual(len(set(gate.IDS)),25)
        self.assertEqual(set(gate.TOPICS),set(range(146,171)))
        self.assertTrue(set(gate.IDS).isdisjoint(
            {"EXEC-%03d"%n for n in range(1,26)} |
            {"AAA-200-"+sec+"-%03d"%n
             for n in range(121,146)
             for sec in ("M","N","O")} |
            {"AAA-200-"+sec+"-%03d"%n
             for n in range(176,201)
             for sec in ("R","S","T")}))

    def test_all_25_original_requirement_tampers_rejected(self):
        for rid in gate.IDS:
            old=self.inv["rules"][rid]["requirement"]
            self.inv["rules"][rid]["requirement"]=old+" ALTERED"
            with self.subTest(rule_id=rid),self.assertRaisesRegex(
                gate.Semantic25Blocked,"SOURCE_OR_RULE_DRIFT"):
                gate.canonical(self.inv)
            self.inv["rules"][rid]["requirement"]=old

    def test_p5_five_due_twenty_future_none_certified(self):
        result=self.replay()
        self.assertEqual(result["rule_count"],25)
        self.assertEqual(result["due_rules"],5)
        self.assertEqual(result["future_phase_rules"],20)
        self.assertEqual(result["full_rule_semantic_passes"],0)
        self.assertEqual(result["individual_mg0_passes"],0)
        self.assertFalse(result["advancement_authorized"])
        self.assertEqual(result["original_named_machine_subcriteria"],
            sum(len(MQ_PREDICATES[n])+2 for n in range(146,151)))
        self.assertEqual(sum(x["source_semantic_verdict"]=="NOT_DUE"
                             for x in result["rules"].values()),20)

    def test_p6_fifteen_due_ten_future_and_no_false_fivem(self):
        self.set_phase("P6")
        result=self.replay()
        self.assertEqual(result["due_rules"],15)
        self.assertEqual(result["future_phase_rules"],10)
        self.assertEqual(result["individual_mg0_passes"],0)
        self.assertFalse(result["advancement_authorized"])

    def test_p7_twenty_five_due_independent_glb_collision_fivem_scopes(self):
        self.set_phase("P7")
        result=self.replay()
        self.assertEqual(result["due_rules"],25)
        self.assertEqual(result["future_phase_rules"],0)
        self.assertEqual(result["original_named_machine_subcriteria"],
            sum(len(MQ_PREDICATES[n])+2 for n in range(146,171)))
        self.assertTrue(all(
            any(k.startswith("native:") for k in r["original_machine_observations"])
            and any(k.startswith("independent:") for k in r["original_machine_observations"])
            for r in result["rules"].values()))
        self.assertEqual(result["full_rule_semantic_passes"],0)

    def test_p8_still_requires_all_twenty_five_not_automatic_pass(self):
        self.set_phase("P8")
        result=self.replay()
        self.assertEqual(result["due_rules"],25)
        self.assertEqual(result["individual_mg0_passes"],0)
        self.assertEqual(result["full_rule_semantic_passes"],0)

    def test_failing_original_mg0_applies_only_to_actual_rule(self):
        rid=gate.IDS[11]
        self.mg0["rules"][rid]["verdict"]="FAIL"
        self.mg0["rules"][rid]["uncorrected_failure_count"]=1
        result=self.replay()
        self.assertEqual(result["original_negative_mg0_failures"],1)
        self.assertEqual(result["rules"][rid]["source_semantic_verdict"],"FAIL")
        self.assertEqual(sum(r["source_semantic_verdict"]=="FAIL"
                             for r in result["rules"].values()),1)

    def test_false_mg0_positive_stops_entire_batch(self):
        self.mg0["individual_mg0_passes"]=25
        with self.assertRaisesRegex(gate.Semantic25Blocked,"SOURCE_REPLAYS_DISAGREE"):
            self.replay()

    def test_original_master_byte_drift_stops_replay(self):
        self.c.master.read_bytes.return_value=b"tampered"
        with self.assertRaisesRegex(gate.Semantic25Blocked,"MASTER_ORIGINAL_BYTES_CHANGED"):
            self.replay()

    def test_original_audit_digest_drift_stops_replay(self):
        self.p345["original_audit_sha256"]="f"*64
        with self.assertRaisesRegex(gate.Semantic25Blocked,"SOURCE_REPLAYS_DISAGREE"):
            self.replay()

    def test_untrusted_cross_attempt_reader_stops_replay(self):
        self.mq["attempt_id"]="f"*64
        with self.assertRaisesRegex(gate.Semantic25Blocked,"SOURCE_REPLAYS_DISAGREE"):
            self.replay()

    def test_invalid_independent_canonical_original_rejected(self):
        rid=gate.IDS[7]
        self.set_phase("P6")
        self.p678["rules"][rid]["requirement_sha256"]="f"*64
        with self.assertRaisesRegex(gate.Semantic25Blocked,
                                    "INDEPENDENT_SOURCE_REPLAY_CHANGED"):
            self.replay()

    def test_future_phase_fake_positive_fivem_evidence_rejected(self):
        rid=gate.IDS[-1]
        self.set_phase("P6")
        self.p678["rules"][rid]["native_original_machine_evidence"]={"fake":True}
        with self.assertRaisesRegex(gate.Semantic25Blocked,
                                    "PHASE_SCOPED_MACHINE_EVIDENCE_INVALID"):
            self.replay()

    def test_missing_native_collision_qa_not_a_false_pass(self):
        self.set_phase("P7")
        rid=gate.IDS[11]
        self.p678["rules"][rid]["native_original_machine_evidence"]={
            "independent_original_byte_read":False,
            "independent_actual_test_proven":False}
        result=self.replay()
        self.assertTrue(result["rules"][rid]["missing_subcriteria"])
        self.assertFalse(result["rules"][rid]["original_full_semantics_certified"])

    def test_new_cohort_is_wired_into_controller_actual_close(self):
        source=Path(__file__).with_name("controlled_judgment.py").read_text("utf-8")
        for marker in (
            "from c07_o146_q170_25_semantic_replay import inspect as inspect_oq25",
            "SUPERVISOR_C07_O146_Q170_ORIGINAL_SEMANTIC_25",
            "C07_O146_Q170_REPLAY_REQUIRED",
            "original_scope=oq25['rules']",
            "full_rule_semantic_passes=0,individual_mg0_passes=0",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker,source)

if __name__=="__main__":unittest.main()

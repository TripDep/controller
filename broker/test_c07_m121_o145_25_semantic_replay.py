"""C07 M121..O145 exact 25-rule semantic review adversarial test suite.

Producer fixtures are synthetic and do NOT confer an operational rule PASS,
artistic acceptability, real owner review or authentic MG0.
"""
import hashlib
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

import c07_m121_o145_25_semantic_replay as gate
from c07_m121_q170_fifty_native import (
    CLAUSES as MQ_CLAUSES, RULE_PREDICATES as MQ_PREDICATES, IDS as MQ_IDS)
from c07_p345_forty_native_evidence import IDS as P345_IDS, TEXT as P345_TEXT

MASTER=b"test-only-MASTER-not-a-user-asset"
AUDIT=b"test-only-original-audit-fixture"
MASTER_SHA=hashlib.sha256(MASTER).hexdigest()
AUDIT_SHA=hashlib.sha256(AUDIT).hexdigest()
TAIL="a"*64
ATTEMPT="b"*64
OPERATION="c"*64

class M121O145Test(unittest.TestCase):
    def setUp(self):
        self.controller=Mock()
        self.controller.master.read_bytes.return_value=MASTER
        self.controller.audit_path.return_value.read_bytes.return_value=AUDIT
        self.inv={"schema":"gg-effective-family-inventory-v1",
                  "rule_count":763,
                  "canonical_master_sha256":MASTER_SHA,
                  "source_digests":{"aaa_catalog":gate.CATALOG_SHA},
                  "rules":{}}
        for n,rid in enumerate(gate.IDS,121):
            clause=gate.CLAUSES[rid]
            self.inv["rules"][rid]={
              "family":"AAA-200","catalog_number":n,
              "catalog_section":rid.split("-")[2],
              "catalog_phase":gate.REQUIRED_PHASE[rid],
              "asset_type":"all","source_sha256":gate.CATALOG_SHA,
              "requirement":clause,
              "requirement_sha256":hashlib.sha256(clause.encode()).hexdigest()}
        self.work={"phase":"P4","master_sha256":MASTER_SHA,
                   "attempt_id":ATTEMPT,"operation_sha256":OPERATION}
        self.plan={"phase":"P4","master_sha256":MASTER_SHA}
        self.context={"inventory":self.inv,"plan":self.plan,
                      "controller":self.controller,"asset":"FIXTURE_ASSET",
                      "step":"FIXTURE_STEP","work":self.work,
                      "source_loader":lambda path: b"fixture"}
        self.mq={
          "schema":gate.MQ_SCHEMA,"source_rules_examined":50,
          "native_predicates_evaluated":180,
          "original_audit_sha256":AUDIT_SHA,"original_audit_tail":TAIL,
          "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
          "full_rule_passes":0,"individual_mg0_passes":0,
          "advancement_authorized":False,"rules":{}}
        self.r146={
          "schema":gate.R146_SCHEMA,"source_rule_count":40,
          "native_named_domain_checks":80,
          "original_audit_sha256":AUDIT_SHA,"original_audit_tail":TAIL,
          "master_sha256":MASTER_SHA,
          "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
          "full_rule_passes":0,"individual_mg0_passes":0,
          "advancement_authorized":False,"rules":{}}
        self.mg0={
          "rule_count":25,"audit_sha256":AUDIT_SHA,
          "audit_tail_sha256":TAIL,"attempt_id":ATTEMPT,
          "individual_mg0_passes":0,"advancement_authorized":False,
          "rules":{}}
        for n,rid in enumerate(MQ_IDS,121):
            row=self.inv["rules"].get(rid,{})
            if not row:
                row={
                 "source_sha256":gate.CATALOG_SHA,
                 "requirement_sha256":hashlib.sha256(MQ_CLAUSES[n].encode()).hexdigest()}
            self.mq["rules"][rid]={
              "rule_id":rid,"canonical_requirement":MQ_CLAUSES[n],
              "canonical_source_sha256":row["source_sha256"],
              "requirement_sha256":row["requirement_sha256"],
              "original_native_predicates":{
                  k:True for k in MQ_PREDICATES[n]},
              "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
              "owner_approval":"UNKNOWN","advancement_authorized":False}
        for rid in P345_IDS:
            n=int(rid.split("-")[-1])
            phase=P345_TEXT[str(n)][1]
            due=gate.PHASES["P4"]>=gate.PHASES[phase]
            row=self.inv["rules"].get(rid,{})
            if not row:
                row={"source_sha256":gate.CATALOG_SHA,
                     "requirement_sha256":hashlib.sha256(P345_TEXT[str(n)][0].encode()).hexdigest()}
            self.r146["rules"][rid]={
              "rule_id":rid,"source_sha256":row["source_sha256"],
              "requirement_sha256":row["requirement_sha256"],
              "earliest_phase":phase,
              "applicability":"DUE" if due else "FUTURE_PHASE",
              "machine_observations":{"independent_byte_test_a":True,
                                      "independent_byte_test_b":False} if due else {},
              "full_rule_semantics":"UNKNOWN" if due else "NOT_DUE",
              "individual_mg0":"UNKNOWN" if due else "NOT_DUE",
              "owner_acceptance":"UNKNOWN","advancement_authorized":False}
        for rid in gate.IDS:
            self.mg0["rules"][rid]={
                "verdict":"UNKNOWN","uncorrected_failure_count":0,
                "observation_sha256":hashlib.sha256(rid.encode()).hexdigest()
            }

    def set_phase(self,phase):
        self.plan["phase"]=phase
        self.work["phase"]=phase
        for rid, row in self.r146["rules"].items():
            due=gate.PHASES[phase]>=gate.PHASES[row["earliest_phase"]]
            row["applicability"]="DUE" if due else "FUTURE_PHASE"
            row["machine_observations"]=({
                 "independent_byte_test_a":True,
                 "independent_byte_test_b":False
            } if due else {})
            row["full_rule_semantics"]="UNKNOWN" if due else "NOT_DUE"
            row["individual_mg0"]="UNKNOWN" if due else "NOT_DUE"

    def review(self):
        with patch.object(gate,"inspect_mq",return_value=self.mq),\
             patch.object(gate,"inspect_r146",return_value=self.r146),\
             patch.object(gate,"inspect_mg0",return_value=self.mg0):
            return gate.inspect(self.context)

    def test_exact_25_distinct_original_material_lighting_lod_clauses(self):
        gate.canonical(self.inv)
        self.assertEqual(len(gate.IDS),len(set(gate.IDS)))
        self.assertEqual(len(gate.IDS),25)
        self.assertEqual(set(gate.IDS).intersection(
            {"AAA-200-"+s+"-%03d"%n
             for n in range(176,201)
             for s in ("R","S","T")}),set())
        self.assertEqual(set(gate.TOPICS),set(range(121,146)))

    def test_all_25_original_canonical_mutations_fail_closed(self):
        for rid in gate.IDS:
            row=self.inv["rules"][rid]
            original=row["requirement"]
            row["requirement"]=original+" forged"
            with self.subTest(rid=rid),self.assertRaisesRegex(
                gate.Batch25Blocked,"ORIGINAL_SOURCE_REQUIREMENT_CHANGED"):
                gate.canonical(self.inv)
            row["requirement"]=original

    def test_p4_only_twenty_rules_due_five_future(self):
        result=self.review()
        self.assertEqual(result["rule_count"],25)
        self.assertEqual(result["due_rules"],20)
        self.assertEqual(result["future_phase_rules"],5)
        self.assertEqual(result["original_named_semantic_subchecks"],
            sum(len(MQ_PREDICATES[n])+2 for n in range(121,141)))
        self.assertEqual(result["individual_mg0_passes"],0)
        self.assertEqual(result["full_rule_semantic_passes"],0)
        self.assertFalse(result["advancement_authorized"])
        for rid in gate.IDS:
            with self.subTest(rid=rid):
                rule=result["rules"][rid]
                self.assertFalse(rule["full_original_semantics_pass"])
                self.assertFalse(rule["independent_mg0_pass"])
                self.assertEqual(rule["semantic_verdict"],
                    "UNKNOWN" if rule["applicability"]=="DUE" else "NOT_DUE")

    def test_p3_all_rules_future_and_none_counted_positive(self):
        self.set_phase("P3")
        result=self.review()
        self.assertEqual(result["due_rules"],0)
        self.assertEqual(result["future_phase_rules"],25)
        self.assertEqual(result["original_named_semantic_subchecks"],0)
        self.assertEqual(result["source_observations_positive"],0)

    def test_p5_all_25_due_with_two_independent_evidence_engines(self):
        self.set_phase("P5")
        result=self.review()
        self.assertEqual(result["due_rules"],25)
        self.assertEqual(result["future_phase_rules"],0)
        self.assertEqual(result["original_named_semantic_subchecks"],
            sum(len(MQ_PREDICATES[n])+2 for n in range(121,146)))
        self.assertTrue(all(
            any(k.startswith("native:") for k in x["replayed_machine_checks"]) and
            any(k.startswith("independent:") for k in x["replayed_machine_checks"])
            for x in result["rules"].values()))

    def test_positive_machine_evidence_is_not_artistic_or_mg0_pass(self):
        self.set_phase("P5")
        r=self.review()
        self.assertGreater(r["source_observations_positive"],0)
        self.assertEqual(r["full_rule_semantic_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)

    def test_missing_real_raster_evidence_is_explicit_not_success(self):
        self.r146["rules"][gate.IDS[12]]["machine_observations"]={
            "independent_byte_test_a":False,"independent_byte_test_b":False}
        result=self.review()
        self.assertGreater(len(result["rules"][gate.IDS[12]]["missing_subchecks"]),0)
        self.assertFalse(result["rules"][gate.IDS[12]]["full_original_semantics_pass"])

    def test_real_individual_mg0_failure_only_affects_the_rule(self):
        rid=gate.IDS[10]
        self.mg0["rules"][rid]["verdict"]="FAIL"
        self.mg0["rules"][rid]["uncorrected_failure_count"]=1
        r=self.review()
        self.assertEqual(r["independent_negative_failures"],1)
        self.assertEqual(r["rules"][rid]["semantic_verdict"],"FAIL")
        self.assertTrue(all(
            v["semantic_verdict"]!="FAIL" for k,v in r["rules"].items() if k!=rid))

    def test_changed_master_original_bytes_block(self):
        self.controller.master.read_bytes.return_value=b"tampered"
        with self.assertRaisesRegex(gate.Batch25Blocked,"MASTER_BYTES_CHANGED"):
            self.review()

    def test_cross_attempt_replayed_engine_is_blocked(self):
        self.mq["attempt_id"]="f"*64
        with self.assertRaisesRegex(gate.Batch25Blocked,"ENGINES_DISAGREE"):
            self.review()

    def test_original_audit_bytes_divergence_fails_closed(self):
        self.r146["original_audit_sha256"]="f"*64
        with self.assertRaisesRegex(gate.Batch25Blocked,"ENGINES_DISAGREE"):
            self.review()

    def test_false_independent_mg0_pass_rejected(self):
        self.mg0["individual_mg0_passes"]=25
        with self.assertRaisesRegex(gate.Batch25Blocked,"ENGINES_DISAGREE"):
            self.review()

    def test_unverified_original_clause_from_other_reader_blocks(self):
        rid=gate.IDS[0]
        self.mq["rules"][rid]["canonical_requirement"]="FAKE"
        with self.assertRaisesRegex(gate.Batch25Blocked,"FALSIFIED_OR_DIFFERENT_RULE"):
            self.review()

    def test_future_phase_fake_positive_visual_qa_is_blocked(self):
        rid=gate.IDS[-1]
        self.r146["rules"][rid]["machine_observations"]={"fake":True}
        with self.assertRaisesRegex(gate.Batch25Blocked,"PHASE_SCOPED_EVIDENCE"):
            self.review()

    def test_new_cohort_is_wired_into_actual_controller_close(self):
        source=Path(__file__).with_name("controlled_judgment.py").read_text("utf-8")
        for marker in (
            "from c07_m121_o145_25_semantic_replay import inspect as inspect_mo25",
            "SUPERVISOR_C07_M121_O145_ORIGINAL_SEMANTIC_25",
            "C07_M121_O145_REPLAY_REQUIRED",
            "semantic_scope=mo25['rules']",
            "full_rule_semantic_passes=0,individual_mg0_passes=0",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker,source)

if __name__=="__main__":
    unittest.main()

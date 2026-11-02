"""Synthetic adversarial tests for 200 independently reviewed native verdicts.

A synthetic PASS here only tests the trusted caller boundary; it does not
certify production rules, artifacts, user approval or FiveM runtime.
"""
import hashlib
import unittest
from unittest.mock import patch

from c07_positive200_evidence import R122_FROZEN_IDS
from c07_frozen200_macro_native_decision import inspect,Macro200Blocked,SCHEMA
from supervisor_judgment import binding,digest as jd
from family_coverage import expected_result

MASTER="a"*64
WORK={
    "master_sha256":MASTER,"work_item_sha256":"b"*64,
    "attempt_id":"c"*64,"operation_sha256":"d"*64,
    "attempt_number":1,"previous_attempt_id":None,
    "phase":"P0","asset_type":"terrain","profiles":["demo"],
    "work_dependencies":{"e"*64:"f"*64},
}
def fixture():
    families={
      "BEHAVIOR_110":[],"EXECUTION":[],"AAA-200":[],"GOVERNANCE":[]
    }
    families.update({"SYNTH_FAMILY_%02d"%i:[] for i in range(16)})
    rules={}
    for rid in R122_FROZEN_IDS:
        family=("BEHAVIOR_110" if rid.startswith("BEHAVIOR-") else
                "EXECUTION" if rid.startswith("EXEC-") else
                "AAA-200" if rid.startswith("AAA-200-") else
                "GOVERNANCE")
        clause="Original obligation for "+rid
        rows={
            "family":family,
            "requirement":clause,
            "source_sha256":"1"*64,
            "requirement_sha256":hashlib.sha256(clause.encode()).hexdigest(),
        }
        families[family].append(rid)
        rules[rid]=rows
    for k in range(563):
        rid="SYNTHETIC_OTHER_%03d"%k
        family="SYNTH_FAMILY_%02d"%(k%16)
        clause="Additional original fixture "+rid
        rules[rid]={
           "family":family,"requirement":clause,
           "source_sha256":"1"*64,
           "requirement_sha256":hashlib.sha256(clause.encode()).hexdigest()}
        families[family].append(rid)
    inv={"schema":"gg-effective-family-inventory-v1","rule_count":763,
         "canonical_master_sha256":MASTER,
         "families":families,"rules":rules}
    plan={"master_sha256":MASTER,"enrolled":{}}
    byfamily={}
    for family,keys in families.items():
        byfamily[family]={}
        for rid in keys:
            row=rules[rid]
            due=expected_result(row,WORK["phase"],WORK["asset_type"],WORK["profiles"])
            byfamily[family][rid]={
                "result":"UNKNOWN" if due=="PASS" else
                         ("FUTURE_PHASE" if due=="FUTURE_PHASE" else "N_A"),
                "expected_applicability":due,
                "mg0":"UNKNOWN",
                "evidence_digest":None,
                "binding_sha256":jd(binding(WORK,row,rid)),
            }
    decision={
      "schema":"gg-process-judgment-v1",
      "synthetic_backend":False,
      "attempt_id":WORK["attempt_id"],
      "operation_sha256":WORK["operation_sha256"],
      "work_item_sha256":WORK["work_item_sha256"],
      "master_sha256":MASTER,"phase":WORK["phase"],
      "rule_count":763,"families":byfamily,
    }
    decision["decision_sha256"]=jd(decision)
    return inv,plan,decision
def rehash(native):
    native["decision_sha256"]=jd({
        k:v for k,v in native.items() if k!="decision_sha256"})
def evaluate(inv,plan,native):
    return inspect(inv,WORK,plan,native)

class Frozen200MacroPositiveTests(unittest.TestCase):
    def test_all_two_hundred_have_real_native_status_not_generic_pass(self):
        inv,plan,native=fixture()
        result=evaluate(inv,plan,native)
        self.assertEqual(result["schema"],SCHEMA)
        self.assertEqual(result["rule_count"],200)
        self.assertEqual(result["counts"]["UNKNOWN"],200)
        self.assertEqual(result["verified_full_semantic_and_mg0_passes"],0)
        self.assertEqual(len(result["rules"]),200)
        self.assertFalse(result["all_due_full_semantic_and_mg0_verified"])
        self.assertTrue(all(
            x["native_rule_verdict"]=="UNKNOWN" and
            not x["full_rule_and_mg0_pass"] and
            not x["advancement_authorized"]
            for x in result["rules"].values()))

    def test_all_200_tampered_source_clauses_are_rejected(self):
        inv,plan,native=fixture()
        for rid in R122_FROZEN_IDS:
            with self.subTest(rule=rid):
                c=inv["rules"][rid]
                original=c["requirement"]
                c["requirement"]=original+" forged"
                with self.assertRaisesRegex(Macro200Blocked,
                                             "SOURCE_REQUIREMENT_TAMPERED"):
                    evaluate(inv,plan,native)
                c["requirement"]=original

    def test_synthetic_decision_never_becomes_certification(self):
        inv,plan,native=fixture()
        native["synthetic_backend"]=True
        rehash(native)
        with self.assertRaisesRegex(Macro200Blocked,"TRUSTED_CURRENT_NATIVE"):
            evaluate(inv,plan,native)

    def test_replayed_attempt_is_blocked(self):
        inv,plan,native=fixture()
        native["attempt_id"]="f"*64
        rehash(native)
        with self.assertRaisesRegex(Macro200Blocked,"TRUSTED_CURRENT_NATIVE"):
            evaluate(inv,plan,native)

    def test_missing_one_of_763_native_rows_refused(self):
        inv,plan,native=fixture()
        rid=R122_FROZEN_IDS[0]
        del native["families"][inv["rules"][rid]["family"]][rid]
        rehash(native)
        with self.assertRaises(Macro200Blocked):
            evaluate(inv,plan,native)

    def test_unsupported_rule_forged_pass_is_blocked(self):
        inv,plan,native=fixture()
        rid="BEHAVIOR-001"
        row=native["families"]["BEHAVIOR_110"][rid]
        row.update(result="PASS",mg0="PASS",evidence_digest="a"*64)
        rehash(native)
        with self.assertRaisesRegex(
            Macro200Blocked,"POSITIVE_WITHOUT_APPROVED_REPLAYER_AND_MG0"):
            evaluate(inv,plan,native)

    def test_false_native_pass_without_mg0_is_blocked(self):
        inv,plan,native=fixture()
        rid="AAA-200-A-001"
        row=native["families"]["AAA-200"][rid]
        row.update(result="PASS",mg0="UNKNOWN",evidence_digest="a"*64)
        rehash(native)
        with self.assertRaises(Macro200Blocked):
            evaluate(inv,plan,native)

    def test_genuine_reviewed_native_pass_can_be_counted_conditionally(self):
        inv,plan,native=fixture()
        rid="AAA-200-A-001"
        rev=("original-source-specific-reviewer",("full_native_semantics",))
        row=inv["rules"][rid]
        plan["enrolled"][rid]={
            "validator_id":rev[0],
            "requirement_sha256":row["requirement_sha256"]}
        native["families"]["AAA-200"][rid].update(
            result="PASS",mg0="PASS",evidence_digest="f"*64)
        rehash(native)
        with patch("c07_frozen200_macro_native_decision.REVIEWED",{rid:rev}), \
             patch("c07_frozen200_macro_native_decision.validate_reviewed",
                   return_value={"reviewed_enrolled_count":1}):
            observed=evaluate(inv,plan,native)
        self.assertEqual(observed["verified_full_semantic_and_mg0_passes"],1)
        self.assertEqual(observed["counts"]["UNKNOWN"],199)
        self.assertFalse(observed["all_due_full_semantic_and_mg0_verified"])
        self.assertFalse(observed["advancement_authorized"])

    def test_fake_positive_packet_hash_is_rejected(self):
        inv,plan,native=fixture()
        rid="AAA-200-A-001"
        rev=("reviewed-only-under-test",("source",))
        canonical=inv["rules"][rid]
        plan["enrolled"][rid]={
            "validator_id":rev[0],
            "requirement_sha256":canonical["requirement_sha256"]}
        native["families"]["AAA-200"][rid].update(
            result="PASS",mg0="PASS",evidence_digest="not-a-sha")
        rehash(native)
        with patch("c07_frozen200_macro_native_decision.REVIEWED",{rid:rev}), \
             patch("c07_frozen200_macro_native_decision.validate_reviewed",
                   return_value={"reviewed_enrolled_count":1}):
            with self.assertRaises(Macro200Blocked):
                evaluate(inv,plan,native)

    def test_source_applicability_cannot_be_override(self):
        inv,plan,native=fixture()
        rid="BEHAVIOR-002"
        native["families"]["BEHAVIOR_110"][rid][
            "expected_applicability"]="FUTURE_PHASE"
        rehash(native)
        with self.assertRaisesRegex(
                Macro200Blocked,"SOURCE_OR_APPLICABILITY"):
            evaluate(inv,plan,native)

    def test_begin_path_wires_native_macro_before_authorization(self):
        from pathlib import Path
        source=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_frozen200_macro_native_decision import inspect",source)
        self.assertIn("SUPERVISOR_C07_FROZEN200_NATIVE_POSITIVE_SEMANTIC_GATE",source)
        self.assertLess(source.index("macro200 = macro200_inspect"),
                        source.index("receipt = j._consume_checked"))

if __name__=="__main__":unittest.main()

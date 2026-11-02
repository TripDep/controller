"""C07 native end-of-work 763-rule certification rollup regression.

All positive scenarios are SYNTHETIC isolated fixtures. A passing CI test
never certifies a real source rule or independent current project MG0.
"""
import unittest
from pathlib import Path
from unittest.mock import patch
from c07_positive200_evidence import R122_FROZEN_IDS
from c07_763_post_certification import inspect,Uncertified,SCHEMA
from test_c07_frozen200_macro_native_decision import fixture,rehash,WORK

def calculate(inv,plan,decision):
    return inspect(inv,plan,WORK,decision)

class Final763SemanticCertificationTests(unittest.TestCase):
    def test_all_763_present_but_no_false_certificates(self):
        inv,plan,decision=fixture()
        actual=calculate(inv,plan,decision)
        self.assertEqual(actual["schema"],SCHEMA)
        self.assertEqual(actual["canonical_rule_count"],763)
        self.assertEqual(actual["frozen200_rule_count"],200)
        self.assertEqual(actual["counts"]["UNKNOWN"],763)
        self.assertEqual(actual["first_200_counts"]["UNKNOWN"],200)
        self.assertEqual(actual["individual_native_and_mg0_certifications"],0)
        self.assertEqual(actual["first_200_certifications"],0)
        self.assertFalse(actual["owner_approval_inferred"])
        self.assertFalse(actual["advancement_authorized"])
        self.assertFalse(actual["all_763_approved"])

    def test_one_really_reviewed_semantic_plus_mg0_positive_counts_in_200(self):
        inv,plan,decision=fixture()
        rid="AAA-200-A-001"
        verified=("reviewed-exact-source-replayer",("source_full_semantics","mg0"))
        plan["enrolled"][rid]={
            "validator_id":verified[0],
            "requirement_sha256":inv["rules"][rid]["requirement_sha256"]}
        decision["families"][inv["rules"][rid]["family"]][rid].update(
            result="PASS",mg0="PASS",evidence_digest="e"*64)
        rehash(decision)
        with patch("c07_763_post_certification.REVIEWED",{rid:verified}),\
             patch("c07_763_post_certification.validate_reviewed",
                   return_value={"reviewed_enrolled_count":1}):
            actual=calculate(inv,plan,decision)
        self.assertEqual(actual["first_200_certifications"],1)
        self.assertEqual(actual["individual_native_and_mg0_certifications"],1)
        self.assertEqual(actual["counts"]["UNKNOWN"],762)
        self.assertEqual(actual["first_200_counts"]["UNKNOWN"],199)
        self.assertTrue(actual["rules"][rid]["semantically_certified"])
        self.assertFalse(actual["all_763_approved"])

    def test_outside_200_positive_is_not_misattributed_to_first_200(self):
        inv,plan,decision=fixture()
        rid="SYNTHETIC_OTHER_001"
        spec=("specific-native-reviewer",("source_full_semantics","mg0"))
        plan["enrolled"][rid]={
            "validator_id":spec[0],
            "requirement_sha256":inv["rules"][rid]["requirement_sha256"]}
        decision["families"][inv["rules"][rid]["family"]][rid].update(
            result="PASS",mg0="PASS",evidence_digest="a"*64)
        rehash(decision)
        with patch("c07_763_post_certification.REVIEWED",{rid:spec}),\
             patch("c07_763_post_certification.validate_reviewed",
                   return_value={"reviewed_enrolled_count":1}):
            actual=calculate(inv,plan,decision)
        self.assertEqual(actual["individual_native_and_mg0_certifications"],1)
        self.assertEqual(actual["first_200_certifications"],0)

    def test_fake_native_pass_without_source_replayer_cannot_count(self):
        inv,plan,decision=fixture()
        rid="AAA-200-A-001"
        decision["families"]["AAA-200"][rid].update(
            result="PASS",mg0="PASS",evidence_digest="e"*64)
        rehash(decision)
        with self.assertRaisesRegex(Uncertified,"FALSE_SEMANTIC"):
            calculate(inv,plan,decision)

    def test_original_native_rule_pass_without_individual_mg0_blocks(self):
        inv,plan,decision=fixture()
        rid="AAA-200-A-001";v=("reviewed-native",("source",))
        plan["enrolled"][rid]={
            "validator_id":v[0],
            "requirement_sha256":inv["rules"][rid]["requirement_sha256"]}
        decision["families"]["AAA-200"][rid].update(
            result="PASS",mg0="UNKNOWN",evidence_digest="a"*64)
        rehash(decision)
        with patch("c07_763_post_certification.REVIEWED",{rid:v}),\
             patch("c07_763_post_certification.validate_reviewed",return_value={}):
            with self.assertRaises(Uncertified):
                calculate(inv,plan,decision)

    def test_tampered_one_of_all_763_original_source_bytes_blocks(self):
        inv,plan,decision=fixture()
        for rid in inv["rules"]:
            with self.subTest(rule=rid):
                x=inv["rules"][rid]
                clause=x["requirement"]
                x["requirement"]=clause+" forged"
                with self.assertRaisesRegex(Uncertified,"ORIGINAL_REQUIREMENT_MUTATED"):
                    calculate(inv,plan,decision)
                x["requirement"]=clause

    def test_native_decision_digest_spoofing_blocks(self):
        inv,plan,decision=fixture()
        decision["phase"]="P7"
        with self.assertRaisesRegex(Uncertified,"ORIGINAL_POST_NATIVE_DECISION_REQUIRED"):
            calculate(inv,plan,decision)

    def test_pretend_synthetic_engine_cannot_certify(self):
        inv,plan,decision=fixture()
        decision["synthetic_backend"]=True
        rehash(decision)
        with self.assertRaises(Uncertified):
            calculate(inv,plan,decision)

    def test_cross_attempt_or_wrong_binding_blocks(self):
        inv,plan,decision=fixture()
        rid=R122_FROZEN_IDS[0]
        decision["families"][inv["rules"][rid]["family"]][rid]["binding_sha256"]="0"*64
        rehash(decision)
        with self.assertRaisesRegex(Uncertified,"RULE_ATTEMPT_OR_SOURCE_REPLAY"):
            calculate(inv,plan,decision)

    def test_rule_set_cannot_be_truncated_to_claim_completion(self):
        inv,plan,decision=fixture()
        rid=R122_FROZEN_IDS[0]
        del decision["families"][inv["rules"][rid]["family"]][rid]
        rehash(decision)
        with self.assertRaises(Uncertified):
            calculate(inv,plan,decision)

    def test_native_post_validation_wired_before_real_close(self):
        text=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_763_post_certification import inspect as certify763",text)
        self.assertIn("SUPERVISOR_C07_FINAL_763_SEMANTIC_MG0_CERTIFICATION",text)
        self.assertLess(text.index("native_final763 = certify763"),
                        text.index("rec = self.c.close(self.asset"))

if __name__=="__main__":
    unittest.main()

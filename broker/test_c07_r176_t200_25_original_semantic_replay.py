"""C07 R176..T200: 25-rule real-reader integration and adversarial gates.

Mocked producers below are TEST-ONLY fixtures to exercise binding, drift,
missing evidence, original per-rule identity, applicability and fail-closed
logic. They do not mint user assets, signatures, operational MG0 or PASS.
"""
import hashlib
import unittest
from unittest.mock import Mock,patch

from c07_batch100_canonical import AAA, CATALOG_SHA
from c07_batch100_predicates import AAA_SPEC
import c07_r176_t200_25_original_semantic_replay as gate

MASTER=b"test-only-original-master-bytes"
AUDIT=b"test-only-original-hash-chained-audit-fixture"
MASTER_SHA=hashlib.sha256(MASTER).hexdigest()
AUDIT_SHA=hashlib.sha256(AUDIT).hexdigest()
TAIL="a"*64
ATTEMPT="b"*64
OPERATION="c"*64
STEP="STEP-TEST-ONLY"
ASSET="TEST_ONLY_ASSET"

class R176T200Test(unittest.TestCase):
    def setUp(self):
        rules={}
        for n,rid in enumerate(gate.IDS,176):
            text=gate.ORIGINAL[rid]
            rules[rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":rid.split("-")[2],
                "catalog_phase":gate.CATEGORIZED[rid],
                "source_sha256":CATALOG_SHA,
                "requirement":text,
                "requirement_sha256":hashlib.sha256(text.encode()).hexdigest(),
            }
        self.inv={
            "schema":"gg-effective-family-inventory-v1",
            "rule_count":763,
            "canonical_master_sha256":MASTER_SHA,
            "source_digests":{"aaa_catalog":CATALOG_SHA},
            "rules":rules,
        }
        self.c=Mock()
        self.c.master.read_bytes.return_value=MASTER
        self.c.audit_path.return_value.read_bytes.return_value=AUDIT
        self.work={
            "master_sha256":MASTER_SHA,"operation_sha256":OPERATION,
            "attempt_id":ATTEMPT,"phase":"P0",
        }
        self.context={
            "inventory":self.inv,
            "plan":{"master_sha256":MASTER_SHA},
            "controller":self.c,
            "asset":ASSET,"step":STEP,"work":self.work,
            "source_loader":lambda path:bytes(),
        }
        rrules={}
        brules={}
        mrows={}
        for n,rid in enumerate(gate.IDS,176):
            row=rules[rid]
            checks=(
                {"r%03d_independent_native_%d"%(n,k):True
                 for k in range(1,5)}
                if n<=180 else
                {key:k<3 for k,key in enumerate(AAA_SPEC[n])}
            )
            base={
                "rule_id":rid,"canonical_requirement":gate.ORIGINAL[rid],
                "source_sha256":CATALOG_SHA,
                "requirement_sha256":row["requirement_sha256"],
                "advancement_authorized":False,
            }
            if n<=180:
                rrules[rid]={**base,"original_machine_criteria":checks,
                             "independent_mg0":"UNKNOWN"}
            else:
                brules[rid]={**base,"original_native_criteria":checks,
                             "individual_mg0":"UNKNOWN"}
            mrows[rid]={
                "verdict":"UNKNOWN","uncorrected_failure_count":0,
                "observation_sha256":hashlib.sha256(rid.encode()).hexdigest(),
            }
        self.r={
            "schema":gate.R_SCHEMA,"rule_count":10,
            "original_audit_sha256":AUDIT_SHA,
            "original_audit_tail":TAIL,
            "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
            "master_sha256":MASTER_SHA,"full_rule_passes":0,
            "individual_mg0_passes":0,"advancement_authorized":False,
            "rules":rrules
        }
        self.b={
            "schema":gate.B_SCHEMA,"source_rules_examined":100,
            "original_audit_sha256":AUDIT_SHA,
            "original_audit_tail":TAIL,
            "attempt_id":ATTEMPT,"operation_sha256":OPERATION,
            "full_rule_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":brules
        }
        self.m={
            "rule_count":25,"audit_sha256":AUDIT_SHA,
            "audit_tail_sha256":TAIL,"attempt_id":ATTEMPT,
            "individual_mg0_passes":0,"advancement_authorized":False,
            "rules":mrows
        }

    def report(self):
        with patch.object(gate,"inspect_r",return_value=self.r),\
             patch.object(gate,"inspect_batch",return_value=self.b),\
             patch.object(gate,"inspect_mg0",return_value=self.m):
            return gate.inspect(self.context)

    def test_exact_25_original_source_clauses_and_no_overlapping_exec(self):
        gate.canonical_requirements(self.inv)
        self.assertEqual(len(gate.IDS),25)
        self.assertEqual(len(set(gate.IDS)),25)
        self.assertEqual(len(gate.ORIGINAL),25)
        self.assertEqual(len(gate.CONCERNS),25)
        self.assertEqual(set(AAA[n][0] for n in range(181,201)),{"S","T"})
        self.assertTrue(set(gate.IDS).isdisjoint(
            {"EXEC-%03d"%n for n in range(1,26)}))

    def test_25_real_source_clause_tampers_all_rejected(self):
        for rid in gate.IDS:
            row=self.inv["rules"][rid]
            original=row["requirement"]
            row["requirement"]=original+" forged"
            with self.subTest(id=rid),self.assertRaisesRegex(
                    gate.Cohort25Blocked,"UNTRUSTED_ORIGINAL"):
                gate.canonical_requirements(self.inv)
            row["requirement"]=original

    def test_25_original_semantic_review_is_not_mg0_or_owner_pass(self):
        result=self.report()
        self.assertEqual(result["source_rules_exact"],25)
        self.assertEqual(result["original_semantic_criteria_checked"],100)
        self.assertEqual(result["source_scope_conditions_observed"],80)
        self.assertEqual(result["due_rules"],5)
        self.assertEqual(result["future_phase_rules"],20)
        self.assertEqual(result["independent_mg0_passes"],0)
        self.assertEqual(result["full_rule_semantic_passes"],0)
        self.assertFalse(result["advancement_authorized"])
        for rid,obs in result["rules"].items():
            with self.subTest(rule=rid):
                self.assertEqual(len(obs["machine_checks"]),4)
                self.assertEqual(obs["semantic_verdict"],"UNKNOWN")
                self.assertFalse(obs["full_clause_positive_certified"])
                self.assertFalse(obs["independent_mg0_certified"])

    def test_p8_triggers_all_25_without_minting_a_single_pass(self):
        self.work["phase"]="P8"
        result=self.report()
        self.assertEqual(result["due_rules"],25)
        self.assertEqual(result["future_phase_rules"],0)
        self.assertEqual(result["independent_mg0_passes"],0)
        self.assertEqual(result["full_rule_semantic_passes"],0)

    def test_one_real_independent_negative_is_a_rule_specific_fail(self):
        rid=gate.IDS[17]
        self.m["rules"][rid]["verdict"]="FAIL"
        self.m["rules"][rid]["uncorrected_failure_count"]=1
        result=self.report()
        self.assertEqual(result["negative_failures"],1)
        self.assertEqual(result["rules"][rid]["semantic_verdict"],"FAIL")
        for other in set(gate.IDS)-{rid}:
            self.assertEqual(result["rules"][other]["semantic_verdict"],"UNKNOWN")

    def test_source_audit_sha_divergence_blocks_every_rule(self):
        self.b["original_audit_sha256"]="f"*64
        with self.assertRaisesRegex(gate.Cohort25Blocked,
                                    "THREE_ORIGINAL_SOURCE_REPLAYS_DIVERGED"):
            self.report()

    def test_attempt_replay_or_cross_work_reuse_blocks(self):
        self.r["attempt_id"]="f"*64
        with self.assertRaisesRegex(gate.Cohort25Blocked,
                                    "THREE_ORIGINAL_SOURCE_REPLAYS_DIVERGED"):
            self.report()

    def test_private_master_byte_mutation_blocks(self):
        self.c.master.read_bytes.return_value=b"changed source bytes"
        with self.assertRaisesRegex(gate.Cohort25Blocked,
                                    "ORIGINAL_MASTER_CHANGED"):
            self.report()

    def test_forged_positive_mg0_from_legacy_oracle_is_blocked(self):
        self.m["individual_mg0_passes"]=25
        with self.assertRaisesRegex(gate.Cohort25Blocked,
                                    "THREE_ORIGINAL_SOURCE_REPLAYS_DIVERGED"):
            self.report()

    def test_source_clause_wording_mismatch_in_oracle_fails(self):
        self.b["rules"][gate.IDS[10]]["canonical_requirement"]="invented"
        with self.assertRaisesRegex(gate.Cohort25Blocked,
                                    "SPECIFIC_ORIGINAL_MACHINE_RULE_CHANGED"):
            self.report()

    def test_malformed_or_reused_machine_evidence_field_blocks(self):
        rid=gate.IDS[-1]
        row=self.b["rules"][rid]
        row["original_native_criteria"]["not-real"]=True
        with self.assertRaisesRegex(gate.Cohort25Blocked,
                                    "SPECIFIC_ORIGINAL_MACHINE_RULE_CHANGED"):
            self.report()

    def test_any_unverified_mg0_is_not_inferred_pass_from_green_scopes(self):
        r=self.report()
        self.assertTrue(r["source_scope_conditions_observed"]>0)
        self.assertEqual(r["independent_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])

if __name__=="__main__":unittest.main()

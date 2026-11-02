"""C07 EXEC25 true original-byte native replay, 25 individual rule checks.

All tests use synthetic original files/audits; no user asset MG0 is certified.
"""
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_c07_exec25_native_observation import Exec25Test
from c07_exec25_native_observation import IDS
from c07_exec25_original_reviewed_native import (
    SCHEMA, VALIDATOR, CRITERIA, MASTER_PATH,
    inspect, packet_for_original, native_rule_readback, ExecReviewBlocked,
)

class Exec25ReviewedOriginalTests(unittest.TestCase):
    def setUp(self):
        self.fixture=Exec25Test(
            "test_all_25_named_source_specific_observations_no_fake_pass")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture.f
        self.context={
            "inventory":self.f.inv,
            "plan":self.f.plan,
            "controller":self.f.controller,
            "asset":self.f.asset,
            "step":self.f.step,
            "work":self.f.work,
            "source_loader":lambda p:Path(p).read_bytes(),
        }

    def expected(self,rid):
        row=self.f.inv["rules"][rid]
        return {
            "rule_id":rid,
            "attempt_id":self.f.work["attempt_id"],
            "operation_sha256":self.f.work["operation_sha256"],
            "source_sha256":row["source_sha256"],
            "requirement_sha256":row["requirement_sha256"],
            "master_sha256":self.f.work["master_sha256"],
        }

    def spec(self,rid):
        return {
            "validator_id":VALIDATOR,
            "criteria":list(CRITERIA[rid]),
            "source_ref":"1"*40,
        }

    def api(self, raw=None):
        api=Mock()
        api.call.return_value={"raw": (
            self.f.master if raw is None else raw)}
        return api

    def readback(self,rid,packet=None,raw=None):
        api=self.api(raw)
        if packet is None:
            packet=packet_for_original(self.context,rid,self.expected(rid))
        with patch("broker_live_review.decode_file",
                   side_effect=lambda response,path:response["raw"]):
            return native_rule_readback(
                api,packet,self.expected(rid),self.spec(rid),self.context)

    def test_all_25_distinct_original_rules_and_100_distinct_criteria(self):
        report=inspect(self.context)
        self.assertEqual(report["schema"],SCHEMA)
        self.assertEqual(report["rule_count"],25)
        self.assertEqual(report["criteria_count"],100)
        self.assertEqual(set(report["rules"]),set(IDS))
        self.assertEqual(report["full_rule_passes"],0)
        self.assertEqual(report["individual_mg0_passes"],0)
        self.assertFalse(report["advancement_authorized"])
        names=[]
        for rid in IDS:
            with self.subTest(rule=rid):
                row=report["rules"][rid]
                self.assertEqual(set(row["criteria"]),set(CRITERIA[rid]))
                self.assertEqual(len(row["criteria"]),4)
                self.assertTrue(all(type(v) is bool for v in row["criteria"].values()))
                self.assertEqual(row["full_literal_semantics"],"UNKNOWN")
                self.assertEqual(row["individual_mg0"],"UNKNOWN")
                names.extend(row["criteria"])
        self.assertEqual(len(names),100)
        self.assertEqual(len(set(names)),100)

    def test_packet_cannot_mint_full_semantic_or_mg0(self):
        rid=IDS[0]
        packet=packet_for_original(self.context,rid,self.expected(rid))
        self.assertEqual(packet["rule"]["result"],"UNKNOWN")
        self.assertEqual(packet["mg0"]["result"],"UNKNOWN")
        self.assertIsNone(packet["mg0"]["triggered"])
        accepted=self.readback(rid,packet)
        self.assertEqual(accepted["individual_mg0"],"UNKNOWN")
        self.assertFalse(accepted["advancement_authorized"])

    def test_real_immutable_source_byte_readback_required(self):
        rid=IDS[2]
        packet=packet_for_original(self.context,rid,self.expected(rid))
        with self.assertRaisesRegex(ExecReviewBlocked,"MASTER_REPLACED"):
            self.readback(rid,packet,raw=b"wrong immutable master")
        self.assertEqual(self.readback(rid,packet)["rule_id"],rid)

    def test_forged_positive_packet_blocked(self):
        rid=IDS[5]
        p=packet_for_original(self.context,rid,self.expected(rid))
        p["mg0"]["result"]="PASS"
        with self.assertRaisesRegex(ExecReviewBlocked,"UNTRUSTED_FULL"):
            self.readback(rid,p)

    def test_producer_tampering_with_a_scoped_machine_predicate_is_detected(self):
        rid=IDS[10]
        p=packet_for_original(self.context,rid,self.expected(rid))
        k=next(iter(p["rule"]["checks"]))
        p["rule"]["checks"][k]=not p["rule"]["checks"][k]
        with self.assertRaisesRegex(ExecReviewBlocked,"UNTRUSTED_FULL"):
            self.readback(rid,p)

    def test_25_original_requirement_mutations_fail_closed(self):
        for rid in IDS:
            before=self.f.inv["rules"][rid]["requirement"]
            self.f.inv["rules"][rid]["requirement"]=before+" FORGED"
            with self.subTest(rule=rid):
                with self.assertRaises(ValueError):
                    inspect(self.context)
            self.f.inv["rules"][rid]["requirement"]=before

    def test_other_attempt_cannot_reuse_native_packet(self):
        rid=IDS[0]
        expected=self.expected(rid)
        expected["attempt_id"]="f"*64
        with self.assertRaisesRegex(ExecReviewBlocked,"BINDING_DRIFT"):
            packet_for_original(self.context,rid,expected)

    def test_missing_original_export_does_not_confer_success(self):
        del self.f.items["NATIVE_EXPORT"]
        self.fixture.rebuild()
        self.context["controller"]=self.f.controller
        report=inspect(self.context)
        self.assertEqual(report["full_rule_passes"],0)
        self.assertEqual(report["individual_mg0_passes"],0)
        self.assertFalse(report["rules"]["EXEC-005"]["criteria"][
            "actual_export_has_nondegenerate_geometry"])

    def test_source_reader_missing_is_blocked(self):
        self.context["source_loader"]=None
        with self.assertRaisesRegex(ExecReviewBlocked,"CONTEXT_REQUIRED"):
            inspect(self.context)

    def test_reviewed_has_correct_source_name_and_specific_id_count(self):
        self.assertEqual(MASTER_PATH,
            "governance/sources/GOLDEN_GARDEN_MASTER_RULES_AND_STATE.md")
        self.assertEqual(len(CRITERIA),25)
        self.assertEqual(set(CRITERIA),set(IDS))

if __name__=="__main__":
    unittest.main()

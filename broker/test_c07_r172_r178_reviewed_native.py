"""C07 fully independent source-native positive reviewer tests for R172/R178.

Synthetic original Golden Controller fixture with REAL BYTES and hash-chained
audit; tests only positive literal source semantics and negative MG0 boundary.
No actual Pine Haven asset, owner acceptance or per-rule MG0 is certified.
"""
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

import supervisor_judgment as j
from approved_validators import REVIEWED,validate,InvalidEnrollment
from c07_r172_r178_reviewed_native import (
    VALIDATOR,CRITERIA,packet_for_original,native_rule_readback,
    ExactLocalReviewBlocked
)
from test_c07_two_exact_process_semantics import ProcessSemantics

IDS=tuple(CRITERIA)
SOURCE=b'private test canonical catalog immutable original'
SOURCE_SHA=hashlib.sha256(SOURCE).hexdigest()

class OriginalNativeReviewerTests(unittest.TestCase):
    def setUp(self):
        self.nested=ProcessSemantics(
            "test_both_original_literal_process_semantics_positive")
        self.nested.setUp()
        self.addCleanup(self.nested.doCleanups)
        f=self.nested.fixture
        self.f=f
        self.asset=f.asset
        self.ref="e"*40
        self.work=f.work
        self.work.update({
            "work_item_sha256":"3"*64,
            "attempt_number":1,
            "previous_attempt_id":None,
            "phase":"P0",
            "asset_type":"terrain",
            "profiles":["FOLIAGE_PROFILE"],
        })
        self.f.inv["source_digests"]["aaa_catalog"]=SOURCE_SHA
        for row in self.f.inv["rules"].values():
            row["source_sha256"]=SOURCE_SHA
        f.rebuild()
        self.nested.persist()
        self.context={
            "inventory":f.inv,"plan":f.plan,"controller":f.controller,
            "asset":f.asset,"step":f.step,"work":f.work,
            "source_loader":lambda p:Path(p).read_bytes(),
        }
        self.api=Mock()
        self.api.call.return_value={"content":"not-used-in-mock"}
        self.issuer={"workflow_blob":"a"*40,"public_sha":"b"*40}

    def expected(self,rid):
        return j.binding(self.work,self.f.inv["rules"][rid],rid)

    def spec(self,rid):
        return {
            "validator_id":VALIDATOR,
            "criteria":list(CRITERIA[rid]),
            "requirement_sha256":self.expected(rid)["requirement_sha256"],
            "source_ref":self.ref,
            "issuer":self.issuer,
        }

    def producer(self,rid):
        return packet_for_original(self.context,rid,self.expected(rid))

    def readback(self,rid,packet=None,context=None,spec=None):
        with patch("broker_live_review.decode_file",return_value=SOURCE):
            return native_rule_readback(
                self.api,packet if packet is not None else self.producer(rid),
                self.expected(rid),spec if spec is not None else self.spec(rid),
                context if context is not None else self.context)

    def test_both_positive_replayers_are_real_source_specific_enrolled_implementations(self):
        self.assertEqual(set(IDS),{"AAA-200-R-172","AAA-200-R-178"})
        for rid in IDS:
            with self.subTest(rule=rid):
                self.assertIn(rid,REVIEWED)
                self.assertEqual(REVIEWED[rid][0],VALIDATOR)
                self.assertEqual(set(REVIEWED[rid][1]),set(CRITERIA[rid]))
                result=validate({rid:self.spec(rid)},self.f.inv)
                self.assertEqual(result["reviewed_enrolled_count"],1)
                self.assertFalse(result["work_authorized"])

    def test_both_literal_semantic_positive_from_original_bytes_not_fake_mg0(self):
        for rid in IDS:
            with self.subTest(rule=rid):
                packet=self.producer(rid)
                self.assertEqual(packet["rule"]["result"],"PASS")
                self.assertTrue(all(packet["rule"]["checks"].values()))
                self.assertEqual(packet["mg0"]["result"],"UNKNOWN")
                self.assertIsNone(packet["mg0"]["triggered"])
                result=self.readback(rid,packet)
                self.assertEqual(result["literal_semantics"],"PASS")
                self.assertEqual(result["individual_mg0"],"UNKNOWN")
                self.assertFalse(result["advancement_authorized"])

    def test_local_original_absent_never_passes_just_by_signed_log(self):
        for rid in IDS:
            with self.subTest(rule=rid):
                packet=self.producer(rid)
                ctx=dict(self.context,source_loader=lambda p:b"FALSIFIED")
                with self.assertRaises((ValueError,ExactLocalReviewBlocked)):
                    self.readback(rid,packet,context=ctx)

    def test_missing_local_context_does_not_accept_signed_packet(self):
        for rid in IDS:
            with self.subTest(rule=rid):
                with self.assertRaises(ExactLocalReviewBlocked):
                    self.readback(rid,context={})

    def test_forged_mg0_pass_is_rejected_after_immutable_readback(self):
        for rid in IDS:
            with self.subTest(rule=rid):
                packet=self.producer(rid)
                packet["mg0"]["result"]="PASS"
                packet["mg0"]["triggered"]=False
                packet["mg0"]["checks"]["canonical_triggers_checked"]=True
                with self.assertRaisesRegex(
                    ExactLocalReviewBlocked,"UNTRUSTED_PRODUCER"):
                    self.readback(rid,packet)

    def test_forged_literal_positive_packet_is_rejected(self):
        rid=IDS[0]
        packet=self.producer(rid)
        packet["rule"]["proof_digest"]="f"*64
        with self.assertRaises(ExactLocalReviewBlocked):
            self.readback(rid,packet)

    def test_changed_original_export_blocks_replayed_positive(self):
        rid="AAA-200-R-172"
        packet=self.producer(rid)
        (self.f.root/"scene.glb").write_bytes(b"tampered original")
        with self.assertRaises((ValueError,ExactLocalReviewBlocked)):
            self.readback(rid,packet)

    def test_changed_persisted_state_downgrades_actual_178_positive(self):
        rid="AAA-200-R-178"
        packet=self.producer(rid)
        saved=self.f.controller.state_path
        data=json.loads(saved.read_text())
        data["assets"][self.asset]["active_step"]["step"]="wrong"
        saved.write_text(json.dumps(data))
        with self.assertRaisesRegex(ExactLocalReviewBlocked,"UNTRUSTED_PRODUCER"):
            self.readback(rid,packet)

    def test_changed_immutable_private_catalog_sha_rejected(self):
        rid=IDS[0]
        with patch("broker_live_review.decode_file",
                   return_value=b"DIFFERENT PRIVATE CATALOG"):
            with self.assertRaisesRegex(ExactLocalReviewBlocked,"SOURCE_CHANGED"):
                native_rule_readback(
                    self.api,self.producer(rid),self.expected(rid),
                    self.spec(rid),self.context)

    def test_invalid_source_ref_and_missing_issuer_are_rejected(self):
        rid=IDS[0]
        spec=self.spec(rid)
        spec["source_ref"]="main"
        with self.assertRaises(InvalidEnrollment):
            validate({rid:spec},self.f.inv)
        spec=self.spec(rid)
        spec["issuer"]={}
        with self.assertRaises(InvalidEnrollment):
            validate({rid:spec},self.f.inv)

    def test_real_backend_reads_native_log_but_still_returns_unknown_mg0(self):
        rid=IDS[0]
        expected=self.expected(rid)
        packet=self.producer(rid)
        logs=("2026-11-02T16:40:00Z "+j.PREFIX+
              json.dumps(packet,separators=(",",":")))
        api=Mock()
        api.origin={"run_id":100,"job_id":200}
        api.call.return_value={}
        backend=j.NativeRuleBackend(api,{rid:self.spec(rid)},
                                   local_source_context=self.context)
        offer={"native_origin":api.origin,
               "expected_packet_sha256":j.digest(packet)}
        with patch.object(j.evidence,"native",return_value=logs),\
             patch("broker_live_review.decode_file",return_value=SOURCE):
            output=backend.rule(rid,expected,offer)
        self.assertEqual(output["result"],"UNKNOWN")
        self.assertEqual(output["mg0"],"UNKNOWN")
        self.assertEqual(output["semantic_scope"],j.SEMANTIC_SCOPE)

    def test_real_backend_without_local_bytes_returns_unknown_not_positive(self):
        rid=IDS[0];packet=self.producer(rid)
        api=Mock();api.origin={"run_id":100,"job_id":200}
        logs=("2026-11-02T16:40:00Z "+j.PREFIX+json.dumps(packet))
        backend=j.NativeRuleBackend(api,{rid:self.spec(rid)})
        offer={"native_origin":api.origin,"expected_packet_sha256":j.digest(packet)}
        with patch.object(j.evidence,"native",return_value=logs):
            observed=backend.rule(rid,self.expected(rid),offer)
        self.assertEqual(observed["result"],"UNKNOWN")

    def test_native_reviewer_is_wired_inside_original_post_lock(self):
        c=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("local_source_context={",c)
        jsrc=Path(__file__).with_name("supervisor_judgment.py").read_text()
        self.assertIn("from c07_r172_r178_reviewed_native import native_rule_readback",jsrc)

if __name__=="__main__":
    unittest.main()

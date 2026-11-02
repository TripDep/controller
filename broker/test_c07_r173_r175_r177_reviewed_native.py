"""C07 source-specific 173/175/177 positive and adversarial ORIGINAL data tests.

Synthetic fixture's audit is hash-chained and its artifact bytes are read from
actual temporary source files. Synthetic PASS is NOT real Pine Haven C07 MG0.
"""
import json
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from datetime import datetime,timedelta,timezone

from test_c07_r171_r180_more_reviewed_native import FourMoreOriginalReviewers
from test_c07_positive_native_process import canonical,sha
from test_glb_machine_qa import synthetic_glb
from c07_r173_r175_r177_reviewed_native import (
    IDS,CRITERIA,VALIDATOR,packet_for_original,
    native_rule_readback,measured_repeated_automation,
    original_immutable_git_versions,RemainderBlocked)
from approved_validators import REVIEWED,validate,InvalidEnrollment
import supervisor_judgment as j

class FurtherThreeOriginalReviewers(unittest.TestCase):
    def setUp(self):
        self.fixture=FourMoreOriginalReviewers(
            "test_original_171_source_organization_genuine_positive")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture.f
        self.ctx=self.fixture.ctx
        self.work=self.f.work
        self.asset=self.f.asset
        self.step=self.f.step
        self.api=Mock()
        self.git_content={}

        def api_call(method,path):
            if method!="GET":raise ValueError("read only")
            if "ref=" not in path:raise ValueError("unpinned source")
            ref=path.split("ref=",1)[1]
            if ref not in self.git_content:raise ValueError("missing private source")
            return {"raw":self.git_content[ref]}
        self.api.call.side_effect=api_call

    def spec(self,rid):
        return {
            "validator_id":VALIDATOR,
            "criteria":list(CRITERIA[rid]),
            "requirement_sha256":self.f.inv["rules"][rid]["requirement_sha256"],
            "source_ref":"d"*40,
            "issuer":{"workflow_blob":"a"*40,"public_sha":"b"*40},
        }
    def expected(self,rid):
        return j.binding(self.work,self.f.inv["rules"][rid],rid)
    def packet(self,rid):
        with patch("broker_live_review.decode_file",side_effect=lambda x,path:x["raw"]):
            return packet_for_original(self.ctx,rid,self.expected(rid),self.api)
    def write_audit(self):
        f=self.f;prev="GENESIS"
        for x in f.records:
            x["prev_hash"]=prev
            x["record_hash"]=sha(canonical({
                k:v for k,v in x.items() if k!="record_hash"}))
            prev=x["record_hash"]
        f.controller.audit_path(f.asset).write_bytes(b"".join(
            canonical(row)+b"\n" for row in f.records))
        f.controller._state["last_audit_hash"]=prev
        self.fixture.save_current()

    def prepare_173(self):
        f=self.f
        before=b"blender source original version A"
        current=b"blender source current version B"
        f.add_item("SOURCE_EDITABLE","scene.blend",current)
        f.add_item("SOURCE_VERSION_BASELINE","previous-source.blend",before)
        f.add_item("BASELINE_SNAPSHOT","approved-original.blend",before)
        f.rebuild();self.fixture.save_current()
        self.git_content={"1"*40:current,"2"*40:before}
        self.fixture.append_current("SOURCE_VERSION_INDEPENDENTLY_VERIFIED",
            step=self.step,attempt_id=self.work["attempt_id"],
            operation_sha256=self.work["operation_sha256"],result="PASS",
            repo_path="assets/scene.blend",current_git_ref="1"*40,
            previous_git_ref="2"*40,
            original_current_sha256=sha(current),
            original_previous_sha256=sha(before))
    def prepare_175(self,*,faster=True,include_reimport=True):
        self.fixture.prepare_176()
        f=self.f
        current=f.items["NATIVE_EXPORT"]["sha256"]
        begin=datetime(2026,11,2,10,0,0,tzinfo=timezone.utc)
        sessions=[
            ("MANUAL_QA_BASELINE",0,100),
            ("AUTOMATED_QA",1,20 if faster else 120),
            ("AUTOMATED_QA",2,30 if faster else 125)]
        for kind,num,seconds in sessions:
            stamp=lambda n:(begin+timedelta(seconds=n)).isoformat()
            ref=f"{num+1:064x}"
            self.fixture.append_current("QA_RUN_STARTED",step=self.step,
                attempt_id=self.work["attempt_id"],
                operation_sha256=self.work["operation_sha256"],
                run_id=ref,run_kind=kind,
                output_sha256=current,result="STARTED",
                timestamp_utc=stamp(num*120))
            self.fixture.append_current("QA_RUN_FINISHED",step=self.step,
                attempt_id=self.work["attempt_id"],
                operation_sha256=self.work["operation_sha256"],
                run_id=ref,run_kind=kind,
                output_sha256=current,result="PASS",
                timestamp_utc=stamp(num*120+seconds))
            if kind=="AUTOMATED_QA":
                self.fixture.append_current("AUTOMATED_ORIGINAL_OUTPUT_CHECK",
                   step=self.step,attempt_id=self.work["attempt_id"],
                   operation_sha256=self.work["operation_sha256"],
                   result="PASS",
                   evidence_operation={"artifact_sha256":current})
        if not include_reimport:
            del f.items["NATIVE_REIMPORT"]
            f.rebuild();self.fixture.save_current()
            # Rebuild discards per-attempt QA evidence; fail-closed is expected.

    def prepare_177(self,*,bad_copy=False):
        f=self.f
        old=synthetic_glb()
        new=synthetic_glb(triangles=[
            (0.,0.,0.),(2.,0.,0.),(0.,1.,0.)])
        f.add_item("BASELINE_SNAPSHOT","approved.glb",old)
        f.add_item("APPROVED_COPY_POST_AUTOMATION",
                   "approved-after.glb",
                   new if bad_copy else old)
        f.add_item("NATIVE_EXPORT","scene.glb",new)
        f.add_item("DELIVERY_PACKAGE","scene.zip",f.make_zip())
        f.rebuild();self.fixture.save_current()
        tail=[i for i,x in enumerate(f.records) if
            x.get("event")=="ARTIFACT_RECORDED" and
            x.get("evidence_operation",{}).get("role")==
                "APPROVED_COPY_POST_AUTOMATION"]
        self.assertEqual(len(tail),1)
        last=f.records.pop(tail[0])
        i=tail[0]
        def ev(name,**extra):
            return {"asset":f.asset,"event":name,"step":self.step,
                "attempt_id":self.work["attempt_id"],
                "operation_sha256":self.work["operation_sha256"],
                "result":"PASS",**extra}
        original=sha(old)
        f.records[i:i]=[
            ev("OWNER_APPROVED_ASSET_COPY_VERIFIED",
                approved_original_sha256=original),
            ev("AUTOMATED_ORIGINAL_OUTPUT_CHECK",
                evidence_operation={"artifact_sha256":f.items["NATIVE_EXPORT"]["sha256"]}),
            last,
            ev("APPROVED_ORIGINAL_BYTES_RECHECKED",
                approved_original_sha256=original),
        ]
        self.write_audit()

    def test_three_new_reviewed_implementations_have_original_source_requirements(self):
        self.assertEqual(set(IDS),{
            "AAA-200-R-173","AAA-200-R-175","AAA-200-R-177"})
        for rid in IDS:
            with self.subTest(rid=rid):
                self.assertEqual(REVIEWED[rid],(VALIDATOR,CRITERIA[rid]))
                validated=validate({rid:self.spec(rid)},self.f.inv)
                self.assertEqual(validated["reviewed_enrolled_count"],1)
                self.assertFalse(validated["work_authorized"])

    def test_r173_two_distinct_git_original_versions_byte_identical(self):
        self.prepare_173()
        packet=self.packet("AAA-200-R-173")
        self.assertEqual(packet["rule"]["result"],"PASS",packet["rule"]["checks"])
        self.assertEqual(packet["mg0"]["result"],"UNKNOWN")
        self.assertIsNone(packet["mg0"]["triggered"])

    def test_r173_no_prior_immutable_git_bytes_not_positive(self):
        self.prepare_173()
        del self.git_content["2"*40]
        packet=self.packet("AAA-200-R-173")
        self.assertEqual(packet["rule"]["result"],"UNKNOWN")
        self.assertFalse(packet["rule"]["checks"][
            "independent_version_storage_readback"])

    def test_r173_git_provenance_different_original_source_not_positive(self):
        self.prepare_173()
        self.git_content["1"*40]=b"forged changed Git blob"
        packet=self.packet("AAA-200-R-173")
        self.assertEqual(packet["rule"]["result"],"UNKNOWN")

    def test_r173_old_audit_label_without_git_binaries_not_positive(self):
        self.prepare_173()
        self.git_content.clear()
        packet=self.packet("AAA-200-R-173")
        self.assertEqual(packet["rule"]["result"],"UNKNOWN")

    def test_r175_real_repeated_qa_faster_both_runs_and_real_glb(self):
        self.prepare_175()
        packet=self.packet("AAA-200-R-175")
        self.assertEqual(packet["rule"]["result"],"PASS",packet["rule"]["checks"])
        self.assertEqual(packet["mg0"]["result"],"UNKNOWN")

    def test_r175_slow_automated_qa_is_not_a_benefit(self):
        self.prepare_175(faster=False)
        packet=self.packet("AAA-200-R-175")
        self.assertEqual(packet["rule"]["result"],"UNKNOWN")
        self.assertFalse(packet["rule"]["checks"][
            "measured_net_benefit_independently_proven"])

    def test_r175_quick_qa_without_native_binary_reimport_no_benefit(self):
        self.prepare_175(include_reimport=False)
        packet=self.packet("AAA-200-R-175")
        self.assertEqual(packet["rule"]["result"],"UNKNOWN")

    def test_r175_qa_timestamp_replay_from_other_attempt_rejected(self):
        self.prepare_175()
        self.f.records=[dict(x,attempt_id="e"*64) if x.get("event")==
                        "QA_RUN_FINISHED" else x for x in self.f.records]
        self.write_audit()
        packet=self.packet("AAA-200-R-175")
        self.assertEqual(packet["rule"]["result"],"UNKNOWN")

    def test_r177_actual_approved_asset_untouched_after_automation(self):
        self.prepare_177()
        packet=self.packet("AAA-200-R-177")
        self.assertEqual(packet["rule"]["result"],"PASS",packet["rule"]["checks"])
        self.assertEqual(packet["mg0"]["result"],"UNKNOWN")

    def test_r177_changed_approved_original_is_not_protected(self):
        self.prepare_177(bad_copy=True)
        packet=self.packet("AAA-200-R-177")
        self.assertEqual(packet["rule"]["result"],"UNKNOWN")
        self.assertFalse(packet["rule"]["checks"][
            "independent_pre_and_post_approved_copy_hashes_equal"])

    def test_r177_missing_approved_owner_binding_not_proven(self):
        self.prepare_177()
        self.f.records=[x for x in self.f.records if
                        x.get("event")!="OWNER_APPROVED_ASSET_COPY_VERIFIED"]
        self.write_audit()
        packet=self.packet("AAA-200-R-177")
        self.assertEqual(packet["rule"]["result"],"UNKNOWN")

    def test_untrusted_owner_or_mg0_packet_does_not_mint_certification(self):
        self.prepare_177()
        rid="AAA-200-R-177";packet=self.packet(rid)
        packet["mg0"]["result"]="PASS"
        with patch("broker_live_review.decode_file",
                   return_value=b"not canonical catalog"):
            with self.assertRaises(RemainderBlocked):
                native_rule_readback(
                    self.api,packet,self.expected(rid),self.spec(rid),self.ctx)

    def test_missing_authenticated_local_context_blocks_all_three(self):
        for rid in IDS:
            with self.subTest(rid=rid):
                with self.assertRaises(RemainderBlocked):
                    native_rule_readback(self.api,{},self.expected(rid),
                                         self.spec(rid),{})

if __name__=="__main__":unittest.main()

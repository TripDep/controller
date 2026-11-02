"""C07 six source-specific native reviewers: four new canonical R171/176/179/180.

These are synthetic ORIGINAL-BYTE and hash-chain fixtures for enforcement
regression, not real Pine Haven work or individual MG0 certification.
"""
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from test_c07_two_exact_process_semantics import ProcessSemantics
from test_c07_positive_native_process import canonical,sha
from test_glb_machine_qa import synthetic_glb
from c07_r171_r180_source_native import CLAUSES,CATALOG_SHA
from c07_r171_r180_more_reviewed_native import (
    VALIDATOR,CRITERIA,packet_for_original,native_rule_readback,
    OriginalSemanticsBlocked
)
from approved_validators import REVIEWED,validate,InvalidEnrollment
import supervisor_judgment as j

class FourMoreOriginalReviewers(unittest.TestCase):
    def setUp(self):
        self.nested=ProcessSemantics(
            "test_both_original_literal_process_semantics_positive")
        self.nested.setUp()
        self.addCleanup(self.nested.doCleanups)
        f=self.f=self.nested.fixture
        f.inv["source_digests"]["aaa_catalog"]=CATALOG_SHA
        for n,clause in CLAUSES.items():
            rid="AAA-200-R-%03d"%n
            f.inv["rules"][rid]={
                "family":"AAA-200","catalog_number":n,
                "catalog_section":"R","catalog_phase":"P0",
                "requirement":clause,
                "requirement_sha256":sha(clause.encode("utf-8")),
                "source_sha256":CATALOG_SHA,
            }
        f.work.update({
            "work_item_sha256":"3"*64,
            "attempt_number":1,
            "previous_attempt_id":None,
            "phase":"P0",
            "asset_type":"terrain",
            "profiles":["QA_PROFILE"]
        })
        f.rebuild()
        self.nested.persist()
        self.issuer={"workflow_blob":"a"*40,"public_sha":"b"*40}
        self.ctx={
            "inventory":f.inv,"plan":f.plan,"controller":f.controller,
            "asset":f.asset,"step":f.step,"work":f.work,
            "source_loader":lambda p:Path(p).read_bytes(),
        }

    def expected(self,rid):return j.binding(self.f.work,self.f.inv["rules"][rid],rid)
    def spec(self,rid):
        return {
            "validator_id":VALIDATOR,"criteria":list(CRITERIA[rid]),
            "requirement_sha256":self.expected(rid)["requirement_sha256"],
            "issuer":self.issuer,"source_ref":"e"*40,
        }
    def original(self,rid):return packet_for_original(self.ctx,rid,self.expected(rid))
    def save_current(self):
        # Rebuild creates a NEW Controller with a new immutable original
        # audit/state identity. Never replay evidence against a stale one.
        self.nested.persist()
        self.ctx["controller"]=self.f.controller
        self.ctx["plan"]=self.f.plan
        self.ctx["work"]=self.f.work

    def append_current(self,event,**fields):
        f=self.f;records=f.records
        row={
            "asset":f.asset,
            "event":event,
            "prev_hash":records[-1]["record_hash"],
            **fields,
        }
        row["record_hash"]=sha(canonical(row))
        records.append(row)
        f.controller.audit_path(f.asset).write_bytes(
            b"".join(canonical(x)+b"\n" for x in records))
        f.controller._state["last_audit_hash"]=row["record_hash"]
        self.save_current()

    def prepare_176(self):
        f=self.f;raw=synthetic_glb()
        f.add_item("NATIVE_EXPORT","scene.glb",raw)
        f.add_item("NATIVE_REIMPORT","validated_reimport.glb",raw)
        f.add_item("DELIVERY_PACKAGE","scene.zip",f.make_zip())
        f.plan["outcome_contract"]={"acceptance_criteria":[
            {"name":"triangles_examined","operator":"gte","expected":1},
            {"name":"degenerate_triangles","operator":"eq","expected":0}]}
        f.rebuild();self.save_current()
        self.append_current(
            "NATIVE_OUTPUT_INDEPENDENT_QA",
            step=f.step,attempt_id=f.work["attempt_id"],
            operation_sha256=f.work["operation_sha256"],
            result="PASS",evidence_operation={
                "artifact_sha256":f.items["NATIVE_EXPORT"]["sha256"]})

    def prepare_180(self):
        f=self.f
        before=synthetic_glb()
        after=synthetic_glb(triangles=[
            (0.,0.,0.),(2.,0.,0.),(0.,1.,0.)])
        f.add_item("BASELINE_SNAPSHOT","baseline.glb",before)
        f.add_item("NATIVE_EXPORT","scene.glb",after)
        f.add_item("DELIVERY_PACKAGE","scene.zip",f.make_zip())
        f.rebuild();self.save_current()

    def prepare_179(self):
        f=self.f
        old=b"genuine original saved checkpoint bytes"
        path=f.root/"checkpoint_historic.blend"
        path.write_bytes(old)
        previous="8"*64
        f.work["previous_attempt_id"]=previous
        f.add_item("CHECKPOINT_RESTORED_SOURCE",
                   "checkpoint_restored.blend",old)
        f.rebuild()
        records=f.records
        insert=next(i for i,r in enumerate(records)
                    if r["event"]=="ARTIFACT_RECORDED")
        historic=[
            {"event":"CHECKPOINT_CREATED","result":"PASS",
             "attempt_id":previous,"checkpoint_sha256":sha(old)},
            {"event":"ARTIFACT_RECORDED","result":"PASS",
             "step":"OLD_STEP",
             "evidence_operation":{"role":"CHECKPOINT_SOURCE",
                "path":str(path),"size_bytes":len(old),
                "sha256":sha(old)}},
            {"event":"STEP_CLOSE","step":"OLD_STEP","result":"PASS"},
        ]
        for row in reversed(historic):
            records.insert(insert,{"asset":f.asset,**row})
        # Hash chain reflow; pointers to earlier enrollment and reservation
        # remain intact because history is inserted after STEP_OPEN.
        prev="GENESIS"
        for row in records:
            row["prev_hash"]=prev
            row["record_hash"]=sha(canonical({
                k:v for k,v in row.items() if k!="record_hash"}))
            prev=row["record_hash"]
        f.controller.audit_path(f.asset).write_bytes(
            b"".join(canonical(x)+b"\n" for x in records))
        f.controller._state["last_audit_hash"]=prev
        self.save_current()
        self.append_current(
            "CHECKPOINT_RESTORED_AND_VERIFIED",
            step=f.step,attempt_id=f.work["attempt_id"],
            operation_sha256=f.work["operation_sha256"],
            checkpoint_sha256=sha(old),result="PASS")

    def test_four_new_original_source_implementations_reviewed_not_mg0(self):
        self.assertEqual(set(CRITERIA),{
            "AAA-200-R-171","AAA-200-R-176",
            "AAA-200-R-179","AAA-200-R-180"})
        for rid in CRITERIA:
            with self.subTest(rule=rid):
                self.assertEqual(REVIEWED[rid],(VALIDATOR,CRITERIA[rid]))
                enrolled=validate({rid:self.spec(rid)},self.f.inv)
                self.assertEqual(enrolled["reviewed_enrolled_count"],1)
                self.assertFalse(enrolled["work_authorized"])

    def test_original_171_source_organization_genuine_positive(self):
        rid="AAA-200-R-171"
        p=self.original(rid)
        self.assertEqual(p["rule"]["result"],"PASS")
        self.assertTrue(all(p["rule"]["checks"].values()))
        self.assertEqual(p["mg0"]["result"],"UNKNOWN")
        self.assertIsNone(p["mg0"]["triggered"])

    def test_changed_editable_original_is_rejected_before_source_pass(self):
        rid="AAA-200-R-171"
        p=self.original(rid)
        (self.f.root/"scene.blend").write_bytes(b"changed after original audit")
        with self.assertRaises(ValueError):
            self.original(rid)

    def test_missing_noncanonical_source_root_is_never_positive(self):
        rid="AAA-200-R-171"
        self.f.controller.root=Path("/unrelated/does-not-exist")
        # The original dependency reader may directly block: either remains
        # no positive, never a forged certificate.
        with self.assertRaises((ValueError,OSError)):
            self.original(rid)

    def test_176_binary_output_source_and_native_qa_positive(self):
        self.prepare_176()
        p=self.original("AAA-200-R-176")
        self.assertEqual(p["rule"]["result"],"PASS",p["rule"]["checks"])
        self.assertEqual(p["mg0"]["result"],"UNKNOWN")

    def test_176_same_triangle_count_changed_geometry_not_positive(self):
        self.prepare_176()
        rid="AAA-200-R-176"
        self.assertEqual(self.original(rid)["rule"]["result"],"PASS")
        f=self.f
        original=synthetic_glb(triangles=[
            (0.,0.,0.),(3.,0.,0.),(0.,1.,0.)])
        f.add_item("NATIVE_REIMPORT","validated_reimport.glb",original)
        f.rebuild();self.save_current()
        self.append_current("NATIVE_OUTPUT_INDEPENDENT_QA",
            step=f.step,attempt_id=f.work["attempt_id"],
            operation_sha256=f.work["operation_sha256"],
            result="PASS",evidence_operation={
                "artifact_sha256":f.items["NATIVE_EXPORT"]["sha256"]})
        p=self.original(rid)
        self.assertEqual(p["rule"]["result"],"UNKNOWN")
        self.assertFalse(p["rule"]["checks"][
            "preauthorized_numeric_criteria_and_mesh_reimport"])

    def test_176_no_original_enrolled_acceptance_criteria_not_positive(self):
        self.prepare_176()
        self.f.plan.pop("outcome_contract")
        self.f.rebuild();self.save_current()
        self.append_current("NATIVE_OUTPUT_INDEPENDENT_QA",
            step=self.f.step,attempt_id=self.f.work["attempt_id"],
            operation_sha256=self.f.work["operation_sha256"],
            result="PASS",evidence_operation={
                "artifact_sha256":self.f.items["NATIVE_EXPORT"]["sha256"]})
        p=self.original("AAA-200-R-176")
        self.assertEqual(p["rule"]["result"],"UNKNOWN")

    def test_180_real_changed_model_geometry_not_document_count(self):
        self.prepare_180()
        p=self.original("AAA-200-R-180")
        self.assertEqual(p["rule"]["result"],"PASS",p["rule"]["checks"])
        self.assertEqual(p["mg0"]["result"],"UNKNOWN")

    def test_180_changed_file_metadata_not_modified_geometry(self):
        self.prepare_180()
        f=self.f
        f.add_item("BASELINE_SNAPSHOT","baseline.glb",
                   (f.root/"scene.glb").read_bytes())
        f.rebuild();self.save_current()
        p=self.original("AAA-200-R-180")
        self.assertEqual(p["rule"]["result"],"UNKNOWN")
        self.assertFalse(p["rule"]["checks"][
            "actual_geometric_change_not_document_count"])

    def test_179_historical_raw_checkpoint_and_lineage(self):
        self.prepare_179()
        p=self.original("AAA-200-R-179")
        self.assertEqual(p["rule"]["result"],"PASS",p["rule"]["checks"])
        self.assertEqual(p["mg0"]["result"],"UNKNOWN")

    def test_179_changed_historic_checkpoint_cannot_pass(self):
        self.prepare_179()
        old=self.f.root/"checkpoint_historic.blend"
        old.write_bytes(b"forged historical bytes")
        p=self.original("AAA-200-R-179")
        self.assertEqual(p["rule"]["result"],"UNKNOWN")
        self.assertFalse(p["rule"]["checks"][
            "historical_checkpoint_original_bytes_independently_read"])

    def test_immutable_git_catalog_readback_rejects_forged_mg0(self):
        rid="AAA-200-R-171";packet=self.original(rid)
        packet["mg0"]["result"]="PASS"
        packet["mg0"]["triggered"]=False
        with patch("broker_live_review.decode_file",return_value=b"fake"):
            with self.assertRaises(OriginalSemanticsBlocked):
                native_rule_readback(Mock(),packet,self.expected(rid),
                                     self.spec(rid),self.ctx)

    def test_signed_native_packet_without_original_context_stays_unknown(self):
        rid="AAA-200-R-171";packet=self.original(rid)
        with self.assertRaises(OriginalSemanticsBlocked):
            native_rule_readback(Mock(),packet,self.expected(rid),
                                 self.spec(rid),{})

if __name__=="__main__":
    unittest.main()

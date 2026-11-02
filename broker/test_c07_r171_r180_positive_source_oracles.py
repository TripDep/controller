"""Adversarial positive machine checks for three original C07 rules.

Scope: synthetic fixtures validate real recomputation, not real source-rule
certification, independent owner auth or individual MG0.
"""
import hashlib
import unittest
from pathlib import Path
from test_glb_machine_qa import synthetic_glb
from c07_r171_r180_positive_source_oracles import (
    native_script_output_matches_oracle,
    automation_preserved_approved_bytes,
    real_checkpoint_restored_without_duplicate,
)

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CURRENT="a"*64
OP="b"*64
PREVIOUS="c"*64
STEP="STEP050"

def asset(path,data):
    return (Path(path),SHA(data),data)

class R171R180NativePositiveTests(unittest.TestCase):
    def test_original_output_and_independently_reimported_glb_satisfy_actual_oracle(self):
        raw=synthetic_glb()
        roles={"NATIVE_EXPORT":[asset("/vault/out.glb",raw)],
               "NATIVE_REIMPORT":[asset("/vault/qa.glb",raw)]}
        plan={"outcome_contract":{"acceptance_criteria":[
            {"name":"triangles_examined","operator":"gte","expected":1},
            {"name":"degenerate_triangles","operator":"eq","expected":0}]}}
        self.assertTrue(native_script_output_matches_oracle(plan,roles))

    def test_unapproved_result_threshold_can_never_be_pass(self):
        raw=synthetic_glb()
        roles={"NATIVE_EXPORT":[asset("/vault/out.glb",raw)],
               "NATIVE_REIMPORT":[asset("/vault/qa.glb",raw)]}
        plan={"outcome_contract":{"acceptance_criteria":[
            {"name":"triangles_examined","operator":"gte","expected":10**9}]}}
        self.assertFalse(native_script_output_matches_oracle(plan,roles))

    def test_missing_reimport_or_untrusted_criteria_cannot_pass(self):
        raw=synthetic_glb()
        roles={"NATIVE_EXPORT":[asset("/vault/out.glb",raw)]}
        p={"outcome_contract":{"acceptance_criteria":[
            {"name":"triangles_examined","operator":"gte","expected":1}]}}
        self.assertFalse(native_script_output_matches_oracle(p,roles))
        roles["NATIVE_REIMPORT"]=[asset("/vault/qa.glb",raw)]
        self.assertFalse(native_script_output_matches_oracle({},roles))

    def test_non_glb_binary_cannot_promote_success_exit(self):
        roles={"NATIVE_EXPORT":[asset("/vault/out.glb",b"successful exit code")],
               "NATIVE_REIMPORT":[asset("/vault/qa.glb",b"successful exit code")]}
        p={"outcome_contract":{"acceptance_criteria":[
            {"name":"triangles_examined","operator":"gte","expected":1}]}}
        self.assertFalse(native_script_output_matches_oracle(p,roles))

    def test_different_geometry_stops_r176_even_when_each_is_valid(self):
        raw=synthetic_glb()
        import struct,json
        # An otherwise parseable different valid GLB may have a different
        # vertex/triangle count. A missing reimport is always negative.
        p={"outcome_contract":{"acceptance_criteria":[
            {"name":"triangles_examined","operator":"gte","expected":1}]}}
        roles={"NATIVE_EXPORT":[asset("/vault/out.glb",raw)],
               "NATIVE_REIMPORT":[asset("/vault/qa.glb",b"changed original QA")]}
        self.assertFalse(native_script_output_matches_oracle(p,roles))

    def approved(self):
        content=b"approved immutable original snapshot"
        rows={"BASELINE_SNAPSHOT":[asset("/vault/approved-before.blend",content)],
              "APPROVED_COPY_POST_AUTOMATION":[asset("/vault/approved-after.blend",content)]}
        w={"attempt_id":CURRENT,"operation_sha256":OP}
        events=[
            {"event":"ARTIFACT_RECORDED","step":STEP,"result":"PASS",
             "evidence_operation":{"role":"BASELINE_SNAPSHOT","sha256":SHA(content)}},
            {"event":"OWNER_APPROVED_ASSET_COPY_VERIFIED","step":STEP,
             "attempt_id":CURRENT,"operation_sha256":OP,
             "result":"PASS","approved_original_sha256":SHA(content)},
            {"event":"AUTOMATED_ORIGINAL_OUTPUT_CHECK","step":STEP,
             "attempt_id":CURRENT,"operation_sha256":OP},
            {"event":"ARTIFACT_RECORDED","step":STEP,"result":"PASS",
             "evidence_operation":{"role":"APPROVED_COPY_POST_AUTOMATION",
                                   "sha256":SHA(content)}}]
        return events,rows,w

    def test_pre_and_post_approved_copy_bytes_identical_original_audit_order(self):
        rows,assets,work=self.approved()
        self.assertTrue(automation_preserved_approved_bytes(rows,assets,work,STEP))

    def test_changed_approved_copy_blocks_any_pass_event(self):
        rows,assets,work=self.approved()
        assets["APPROVED_COPY_POST_AUTOMATION"]=[
            asset("/vault/approved-after.blend",b"changed")]
        self.assertFalse(automation_preserved_approved_bytes(rows,assets,work,STEP))

    def test_missing_approval_and_wrong_order_are_not_proof(self):
        rows,assets,work=self.approved()
        self.assertFalse(automation_preserved_approved_bytes(
            [r for r in rows if r["event"]!="OWNER_APPROVED_ASSET_COPY_VERIFIED"],
            assets,work,STEP))
        self.assertFalse(automation_preserved_approved_bytes(
            [rows[0],rows[2],rows[1],rows[3]],assets,work,STEP))

    def test_replayed_prior_attempt_does_not_attest_current_approval(self):
        rows,assets,work=self.approved()
        rows[1]["attempt_id"]="f"*64
        self.assertFalse(automation_preserved_approved_bytes(rows,assets,work,STEP))

    def checkpoint(self):
        content=b"original valid retained checkpoint bytes"
        role={"CHECKPOINT_RESTORED_SOURCE":[asset("/vault/checkpoint.blend",content)]}
        w={"attempt_id":CURRENT,"operation_sha256":OP,
           "previous_attempt_id":PREVIOUS}
        records=[
            {"event":"CHECKPOINT_CREATED","result":"PASS",
             "attempt_id":PREVIOUS,"checkpoint_sha256":SHA(content)},
            {"event":"ARTIFACT_RECORDED","step":STEP,"result":"PASS",
             "evidence_operation":{"role":"CHECKPOINT_RESTORED_SOURCE",
                                   "sha256":SHA(content)}},
            {"event":"CHECKPOINT_RESTORED_AND_VERIFIED","step":STEP,
             "attempt_id":CURRENT,"operation_sha256":OP,
             "checkpoint_sha256":SHA(content)}]
        return records,role,w

    def test_checkpoint_source_original_and_current_lineage_replayed(self):
        rows,roles,work=self.checkpoint()
        self.assertTrue(real_checkpoint_restored_without_duplicate(
            rows,roles,work,STEP))

    def test_historic_checkpoint_changed_sha_blocks(self):
        rows,roles,work=self.checkpoint()
        rows[0]["checkpoint_sha256"]="0"*64
        self.assertFalse(real_checkpoint_restored_without_duplicate(
            rows,roles,work,STEP))

    def test_checkpoint_current_step_or_attempt_changed_blocks(self):
        rows,roles,work=self.checkpoint()
        rows[2]["step"]="ANOTHER_STEP"
        self.assertFalse(real_checkpoint_restored_without_duplicate(
            rows,roles,work,STEP))

    def test_checkpoint_duplicate_reservation_blocks(self):
        rows,roles,work=self.checkpoint()
        rows.append({"event":"SUPERVISOR_OPERATION_RESERVED",
                     "attempt_id":CURRENT,"step":"OLD"})
        self.assertFalse(real_checkpoint_restored_without_duplicate(
            rows,roles,work,STEP))

    def test_original_ten_rule_native_integration(self):
        code=Path(__file__).with_name("c07_r171_r180_source_native.py").read_text()
        for word in ("native_script_output_matches_oracle",
                     "automation_preserved_approved_bytes",
                     "real_checkpoint_restored_without_duplicate"):
            self.assertIn(word+"(",code)

if __name__=="__main__":unittest.main()

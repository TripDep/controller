"""C07 EXEC 25 real measurement regression tests.

These tests certify only deterministic native measurement routines, NEVER
full original-rule acceptance, external owner review or individual MG0.
"""
import hashlib
import unittest
from test_glb_machine_qa import synthetic_glb
from glb_machine_qa import audit_bytes
from c07_exec25_true_measurements import (
    ALLOWED_METRICS,criteria_well_formed,measured_original_glb,
    real_rollback_restored,measured_timebox
)
SHA=lambda x:hashlib.sha256(x).hexdigest()

class RealMeasuredOutcomesTests(unittest.TestCase):
    def setUp(self):
        self.original=synthetic_glb()
        self.technical=audit_bytes(self.original)
        self.plan={"acceptance_criteria":[
            {"name":"triangles_examined","operator":"gte","expected":1},
            {"name":"mesh_primitives","operator":"gte","expected":1},
            {"name":"degenerate_triangles","operator":"eq","expected":0},
            {"name":"nonfinite_positions","operator":"lte","expected":0}
        ]}

    def test_real_native_geometry_with_original_thresholds_is_positive(self):
        self.assertTrue(criteria_well_formed(self.plan))
        self.assertTrue(measured_original_glb(self.plan,self.technical))

    def test_actual_geometry_failure_cannot_be_turned_pass_by_label(self):
        changed={"acceptance_criteria":[
            {"name":"triangles_examined","operator":"gte","expected":10**12}]}
        self.assertFalse(measured_original_glb(changed,self.technical))

    def test_missing_glb_cannot_pass_with_approved_criteria(self):
        self.assertFalse(measured_original_glb(self.plan,None))
        self.assertFalse(measured_original_glb(self.plan,{"errors":[]}))

    def test_duplicate_or_unknown_criteria_are_not_approved(self):
        duplicate={"acceptance_criteria":self.plan["acceptance_criteria"]*2}
        fake={"acceptance_criteria":[{"name":"artistic_quality",
                    "operator":"eq","expected":1}]}
        self.assertFalse(criteria_well_formed(duplicate))
        self.assertFalse(criteria_well_formed(fake))
        self.assertFalse(measured_original_glb(fake,self.technical))

    def test_boolean_nan_and_infinite_thresholds_are_invalid(self):
        for value in (True,float("nan"),float("inf"),float("-inf")):
            plan={"acceptance_criteria":[{
                "name":"triangles_examined","operator":"gte","expected":value}]}
            with self.subTest(value=str(value)):
                self.assertFalse(criteria_well_formed(plan))
                self.assertFalse(measured_original_glb(plan,self.technical))

    def test_unsupported_independent_checks_cannot_get_geometry_pass(self):
        t=dict(self.technical)
        t["unsupported_requires_independent_check"]=["not-native"]
        self.assertFalse(measured_original_glb(self.plan,t))
        t["unsupported_requires_independent_check"]=[]
        t["errors"]=["real native error"]
        self.assertFalse(measured_original_glb(self.plan,t))

    def test_original_restored_bytes_and_matching_audit_are_required(self):
        original=b"approved original binary"
        a=("/vault/baseline.blend",SHA(original),original)
        b=("/vault/rollback.blend",SHA(original),original)
        records=[{"event":"ROLLBACK_READBACK","result":"PASS",
                  "baseline_sha256":SHA(original),
                  "restored_sha256":SHA(original),
                  "attempt_id":"a"*64,"operation_sha256":"b"*64}]
        self.assertTrue(real_rollback_restored(
            {"BASELINE_SNAPSHOT":[a],"ROLLBACK_RESTORED":[b]},records))
        self.assertFalse(real_rollback_restored(
            {"BASELINE_SNAPSHOT":[a],"ROLLBACK_RESTORED":[b]},[]))

    def test_claimed_pass_does_not_override_changed_rollback_bytes(self):
        original=b"approved original binary"
        changed=b"modified or partial rollback"
        data={"BASELINE_SNAPSHOT":[("/base.blend",SHA(original),original)],
              "ROLLBACK_RESTORED":[("/new.blend",SHA(changed),changed)]}
        records=[{"event":"ROLLBACK_READBACK","result":"PASS",
                  "baseline_sha256":SHA(original),"restored_sha256":SHA(original),
                  "attempt_id":"a"*64,"operation_sha256":"b"*64}]
        self.assertFalse(real_rollback_restored(data,records))

    def test_unrelated_rollback_proof_does_not_authorize_ours(self):
        raw=b"approved original binary"
        data={"BASELINE_SNAPSHOT":[("/base.blend",SHA(raw),raw)],
              "ROLLBACK_RESTORED":[("/new.blend",SHA(raw),raw)]}
        forged=[{"event":"ROLLBACK_READBACK","result":"PASS",
                 "baseline_sha256":"f"*64,"restored_sha256":SHA(raw),
                 "attempt_id":"a"*64,"operation_sha256":"b"*64}]
        self.assertFalse(real_rollback_restored(data,forged))

    def test_timebox_is_measured_from_two_real_events_not_a_pass_label(self):
        plan={"timebox_seconds":120}
        good=[{"event":"RUN_STARTED","timestamp_utc":"2026-11-02T10:00:00+00:00"},
              {"event":"RUN_FINISHED","timestamp_utc":"2026-11-02T10:01:30+00:00"}]
        self.assertTrue(measured_timebox(plan,good))
        self.assertFalse(measured_timebox(plan,[
            {"event":"TIMEBOX_EXAMINED","result":"PASS"}]))

    def test_timebox_real_elapsed_over_threshold_fails(self):
        old={"timebox_seconds":60}
        events=[{"event":"RUN_STARTED","timestamp_utc":"2026-11-02T10:00:00Z"},
                {"event":"RUN_FINISHED","timestamp_utc":"2026-11-02T10:01:01Z"}]
        self.assertFalse(measured_timebox(old,events))
        self.assertFalse(measured_timebox({"timebox_seconds":True},events))

    def test_timebox_duplicate_missing_invalid_or_naive_timestamps_fail(self):
        s={"event":"RUN_STARTED","timestamp_utc":"2026-11-02T10:00:00Z"}
        e={"event":"RUN_FINISHED","timestamp_utc":"2026-11-02T10:00:10Z"}
        plan={"timebox_seconds":60}
        for events in ([s,s,e],[e],[s],
                       [s,{"event":"RUN_FINISHED","timestamp_utc":"not-time"}],
                       [s,{"event":"RUN_FINISHED","timestamp_utc":"2026-11-02T10:00:05"}]):
            with self.subTest(events=events):
                self.assertFalse(measured_timebox(plan,events))

if __name__=="__main__":
    unittest.main()

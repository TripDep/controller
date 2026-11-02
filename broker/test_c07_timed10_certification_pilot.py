"""C07 ten-rule elapsed-time pilot adversarial tests.

These tests exercise the real coordinator timing source but mock the original
asset and audit data. They prove enforcement logic ONLY, not project MG0.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

from c07_r171_r180_source_native import IDS,SCHEMA as TEN_SCHEMA
from c07_timed10_certification_pilot import (
    measure,SCHEMA as PILOT_SCHEMA,PilotBlocked
)

MASTER=b"synthetic original master"
AUDIT=b"synthetic original audit not an actual project audit"
SHA=lambda data:hashlib.sha256(data).hexdigest()
WORK={"master_sha256":SHA(MASTER),
      "attempt_id":"a"*64,"operation_sha256":"b"*64}

def fixture():
    import c07_r171_r180_source_native as original
    inventory={"schema":"gg-effective-family-inventory-v1",
               "rule_count":763,
               "canonical_master_sha256":SHA(MASTER),
               "rules":{}}
    for rid in IDS:
        n=int(rid[-3:])
        clause=original.CLAUSES[n]
        inventory["rules"][rid]={
            "source_sha256":original.CATALOG_SHA,
            "requirement_sha256":SHA(clause.encode())}
    controller=Mock()
    controller.master.read_bytes.return_value=MASTER
    controller.audit_path.return_value=Mock(read_bytes=Mock(return_value=AUDIT))
    checks={"read_original":True,"source_check":True,
            "owner_runtime_check":False,"mg0_required":False}
    ten={
        "schema":TEN_SCHEMA,
        "rule_count":10,"source_rules_examined":10,
        "full_rule_passes":0,"individual_mg0_passes":0,
        "advancement_authorized":False,
        "attempt_id":WORK["attempt_id"],
        "operation_sha256":WORK["operation_sha256"],
        "master_sha256":WORK["master_sha256"],
        "original_audit_sha256":SHA(AUDIT),
        "original_audit_tail":"tail10",
        "rules":{rid:{
            "rule_id":rid,
            "source_sha256":inventory["rules"][rid]["source_sha256"],
            "requirement_sha256":inventory["rules"][rid]["requirement_sha256"],
            "original_machine_criteria":dict(checks),
            "observed_criteria":["read_original","source_check"],
            "full_rule_pass":False,
            "independent_mg0":"UNKNOWN",
        } for rid in IDS},
    }
    mg0={"rule_count":10,
         "audit_tail_sha256":"tail10",
         "individual_mg0_passes":0,
         "advancement_authorized":False,
         "rules":{rid:{"verdict":"UNKNOWN"} for rid in IDS}}
    return inventory,controller,ten,mg0

def do_run(inv,controller,ten,mg0):
    with patch("c07_timed10_certification_pilot.inspect10",return_value=ten),\
         patch("c07_timed10_certification_pilot.inspect_mg0",return_value=mg0):
        return measure(inv,{"enrolled":{}},controller,"GOLDEN_GARDEN",
            "STEP999",WORK,source_loader=lambda _:b"original")
class TimedTenPilotTests(unittest.TestCase):
    def test_real_monotonic_execution_duration_not_person_hours(self):
        inv,controller,ten,mg0=fixture()
        report,out=do_run(inv,controller,ten,mg0)
        self.assertEqual(report["schema"],PILOT_SCHEMA)
        self.assertEqual(out,ten)
        self.assertEqual(report["source_rules"],10)
        self.assertEqual(report["counts"],{"FAIL":0,"UNKNOWN":10,"CERTIFIED":0})
        self.assertGreaterEqual(report["total_measured_execution_ns"],0)
        self.assertEqual(report["total_measured_execution_ns"],
            report["original_source_validation_ns"]+report["mg0_readback_ns"])
        self.assertEqual(report["duration_scope"],
            "NATIVE_VERIFIER_EXECUTION_ONLY_NOT_ACTIVE_DEVELOPMENT_HOURS")
        self.assertIsNone(report["remaining_763_person_hours"])
        self.assertIsNone(report["certifications_per_active_development_hour"])
        self.assertFalse(report["advancement_authorized"])
        # Synthetic fixture measurement is intentionally NOT real asset time.
        print("C07_PILOT10_SYNTHETIC_COORDINATOR_RUNTIME_NS="+
            str(report["total_measured_execution_ns"]))

    def test_all_ten_real_original_ids_are_counted_once(self):
        inv,controller,ten,mg0=fixture()
        report,_=do_run(inv,controller,ten,mg0)
        self.assertEqual(set(report["rules"]),set(IDS))
        self.assertTrue(all(x["machine_predicates_total"]==4
              and x["machine_predicates_observed"]==2
              and not x["reviewed_native_full_rule_verifier_enrolled"]
              and x["certification"]=="UNKNOWN"
              for x in report["rules"].values()))

    def test_foreign_tentative_mg0_pass_rejected(self):
        inv,controller,ten,mg0=fixture()
        mg0["rules"]["AAA-200-R-171"]["verdict"]="PASS"
        with self.assertRaises(PilotBlocked):
            do_run(inv,controller,ten,mg0)

    def test_forged_source_record_hash_mismatch_rejected(self):
        inv,controller,ten,mg0=fixture()
        ten["rules"]["AAA-200-R-171"]["requirement_sha256"]="f"*64
        with self.assertRaises(PilotBlocked):
            do_run(inv,controller,ten,mg0)

    def test_mg0_wrong_original_audit_tail_rejected(self):
        inv,controller,ten,mg0=fixture()
        mg0["audit_tail_sha256"]="different"
        with self.assertRaises(PilotBlocked):
            do_run(inv,controller,ten,mg0)

    def test_cross_attempt_mg0_replay_cannot_get_full_pass(self):
        inv,controller,ten,mg0=fixture()
        ten["attempt_id"]="f"*64
        with self.assertRaises(PilotBlocked):
            do_run(inv,controller,ten,mg0)

    def test_missing_current_real_audit_original_rejected(self):
        inv,controller,ten,mg0=fixture()
        ten["original_audit_sha256"]="e"*64
        with self.assertRaises(PilotBlocked):
            do_run(inv,controller,ten,mg0)

    def test_observed_mg0_failure_is_fail_not_implicit_pass(self):
        inv,controller,ten,mg0=fixture()
        mg0["rules"]["AAA-200-R-173"]["verdict"]="FAIL"
        report,_=do_run(inv,controller,ten,mg0)
        self.assertEqual(report["counts"],{"FAIL":1,"UNKNOWN":9,"CERTIFIED":0})
        self.assertFalse(report["advancement_authorized"])

    def test_real_controller_close_includes_duration_evidence_event(self):
        source=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_timed10_certification_pilot import measure as measure_cert10",source)
        self.assertIn("SUPERVISOR_C07_TIMED_TEN_RULE_MG0_PILOT",source)
        self.assertIn("real_verifier_runtime_ns=pilot10['total_measured_execution_ns']",source)
        self.assertIn("'NATIVE_VERIFIER_EXECUTION_ONLY_NOT_ACTIVE_DEVELOPMENT_HOURS'",source)

if __name__=="__main__":
    unittest.main()

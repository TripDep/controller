"""C07 first 200 semantic judgments — adversarial original-proof regression.

All tests are synthetic negative/unknown tests: NO certification or native
artistic/owner/FiveM pass may be inferred from passing this test suite.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

from c07_positive200_evidence import R122_FROZEN_IDS
from c07_frozen200_semantic_verdicts import (
    inspect,_semantic_source,Semantic200Blocked,SCHEMA
)

MASTER=b"synthetic immutable master"
SHA=hashlib.sha256(MASTER).hexdigest()
WORK={"master_sha256":SHA,"operation_sha256":"b"*64,
      "attempt_id":"a"*64}
STEP="STEP010";ASSET="GOLDEN_GARDEN"
PLAN={"master_sha256":SHA}
STATE={"last_audit_hash":"tail","active_step":{"step":STEP}}
RAW=b"immutable original geometry"
ROW=("NATIVE_EXPORT","/safe/current.glb",hashlib.sha256(RAW).hexdigest(),RAW)
def fake_inventory():
    rules={}
    groups={}
    digests={"master":SHA,"error_registry":"1"*64,"aaa_catalog":"2"*64}
    for rid in R122_FROZEN_IDS:
        if rid.startswith("BEHAVIOR-"):
            family,src="BEHAVIOR_110","error_registry"
            n=int(rid.split("-")[1])
            clause="Errore: recorded distinct failure case %03d. → Prevent that exact cause %03d."%(n,n)
        elif rid.startswith("AAA-200-"):
            family,src="AAA-200","aaa_catalog"
            clause="Original operational requirement "+rid
        elif rid.startswith("EXEC-"):
            family,src="EXECUTION","master"
            clause="**VERIFIED_FILE.** Check original step "+rid
        else:
            family,src="MASTER_CHAIN","master"
            clause="Read original authorization and requirements for "+rid
        groups.setdefault(family,[]).append(rid)
        rules[rid]={
            "family":family,"source":src,
            "source_sha256":digests[src],
            "requirement":clause,
            "requirement_sha256":hashlib.sha256(clause.encode()).hexdigest(),
        }
    for i in range(763-len(rules)):
        rid="FAKE_OTHER_%03d"%i
        groups.setdefault("OTHER",[]).append(rid)
        rules[rid]={"family":"OTHER","source":"master",
                    "source_sha256":SHA,
                    "requirement":"Other canonical placeholder "+rid}
    return {"schema":"gg-effective-family-inventory-v1",
            "rule_count":763,"source_digests":digests,
            "canonical_master_sha256":SHA,
            "rules":rules,"families":groups}

def mg0():
    return {"rule_count":200,"individual_mg0_passes":0,
            "advancement_authorized":False,
            "rules":{rid:{"verdict":"UNKNOWN"}
                     for rid in R122_FROZEN_IDS}}

def invoke(records=None,registered=None,inv=None,mg0_result=None):
    inventory=inv or fake_inventory()
    ctrl=Mock()
    ctrl.master.read_bytes.return_value=MASTER
    ctrl.audit_path.return_value=Mock(read_bytes=Mock(return_value=b"original audit"))
    with patch("c07_frozen200_semantic_verdicts._original_attempt",
               return_value=(records or [],"tail",STATE,"authentic_audit_sha")), \
         patch("c07_frozen200_semantic_verdicts._registered_artifacts",
               return_value=registered if registered is not None else [ROW]), \
         patch("c07_frozen200_semantic_verdicts.inspect_mg0_batch",
               return_value=mg0_result or mg0()):
        return inspect(inventory,PLAN,ctrl,ASSET,STEP,WORK,
                       source_loader=lambda _:RAW)

class Frozen200SemanticsTest(unittest.TestCase):
    def test_exact_200_source_semantics_are_extracted(self):
        r=invoke()
        self.assertEqual(r["schema"],SCHEMA)
        self.assertEqual(r["source_rules_evaluated"],200)
        self.assertEqual(r["behavior_prevention_obligations"],110)
        self.assertEqual(r["exec_obligations"],25)
        self.assertEqual(r["semantic_unknowns"],200)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertTrue(all(x["semantic_result"]=="UNKNOWN" and
                            x["independent_positive_semantics"]=="UNKNOWN" and
                            not x["advancement_authorized"] for x in r["rules"].values()))

    def test_every_behavior_error_and_prevention_is_distinct(self):
        r=invoke()
        for number in range(1,111):
            rid="BEHAVIOR-%03d"%number
            with self.subTest(rid=rid):
                x=r["rules"][rid]
                self.assertIn("%03d"%number,x["original_prohibited_error"])
                self.assertIn("%03d"%number,x["original_required_prevention"])
                self.assertNotEqual(x["original_prohibited_error"],
                                    x["original_required_prevention"])

    def test_each_original_clause_modification_is_refused(self):
        for rid in R122_FROZEN_IDS:
            with self.subTest(rule=rid):
                inv=fake_inventory()
                inv["rules"][rid]["requirement"]+=" corrupted"
                with self.assertRaises(Semantic200Blocked):
                    invoke(inv=inv)

    def test_true_attempt_bound_original_counterexample_fails(self):
        rid="BEHAVIOR-004"
        inv=fake_inventory()
        records=[{"event":"QUALITY_FINDING","result":"FAIL",
                  "step":STEP,"attempt_id":WORK["attempt_id"],
                  "operation_sha256":WORK["operation_sha256"],
                  "rule_id":rid,"artifact_sha256":ROW[2],
                  "requirement_sha256":inv["rules"][rid]["requirement_sha256"],
                  "record_hash":"recorded-hash-004"}]
        r=invoke(records=records,inv=inv)
        self.assertEqual(r["rules"][rid]["semantic_result"],"FAIL")
        self.assertEqual(r["semantic_failures"],1)
        self.assertEqual(r["semantic_unknowns"],199)

    def test_wrong_attempt_does_not_falsely_replay_failure(self):
        rid="BEHAVIOR-004"
        inv=fake_inventory()
        records=[{"event":"QUALITY_FINDING","result":"FAIL",
                  "step":STEP,"attempt_id":"f"*64,
                  "operation_sha256":WORK["operation_sha256"],
                  "rule_id":rid,"artifact_sha256":ROW[2],
                  "requirement_sha256":inv["rules"][rid]["requirement_sha256"],
                  "record_hash":"unrelated"}]
        self.assertEqual(invoke(records=records,inv=inv)["semantic_failures"],0)

    def test_unmatched_original_file_does_not_certify_failure(self):
        rid="EXEC-001"
        inv=fake_inventory()
        records=[{"event":"QUALITY_FINDING","result":"FAIL",
                  "step":STEP,"attempt_id":WORK["attempt_id"],
                  "operation_sha256":WORK["operation_sha256"],
                  "rule_id":rid,"artifact_sha256":"f"*64,
                  "requirement_sha256":inv["rules"][rid]["requirement_sha256"],
                  "record_hash":"unmatched"}]
        self.assertEqual(invoke(records=records,inv=inv)["semantic_failures"],0)

    def test_wrong_rule_requirement_hash_does_not_certify_failure(self):
        rid="EXEC-025"
        records=[{"event":"QUALITY_FINDING","result":"FAIL",
                  "step":STEP,"attempt_id":WORK["attempt_id"],
                  "operation_sha256":WORK["operation_sha256"],
                  "rule_id":rid,"artifact_sha256":ROW[2],
                  "requirement_sha256":"f"*64,"record_hash":"fake"}]
        self.assertEqual(invoke(records=records)["semantic_failures"],0)

    def test_individual_mg0_negative_cannot_become_pass(self):
        data=mg0()
        data["rules"]["BEHAVIOR-050"]["verdict"]="FAIL"
        r=invoke(mg0_result=data)
        self.assertEqual(r["semantic_failures"],1)
        self.assertEqual(r["rules"]["BEHAVIOR-050"]["semantic_result"],"FAIL")
        self.assertEqual(r["individual_mg0_passes"],0)

    def test_forged_individual_mg0_positive_rejected(self):
        data=mg0()
        data["rules"]["BEHAVIOR-050"]["verdict"]="PASS"
        with self.assertRaisesRegex(Semantic200Blocked,"UNVERIFIED_MG0_POSITIVE"):
            invoke(mg0_result=data)

    def test_malformed_error_prevention_clause_rejected(self):
        inv=fake_inventory()
        rid="BEHAVIOR-001"
        text="A generic check without a prevention"
        inv["rules"][rid]["requirement"]=text
        inv["rules"][rid]["requirement_sha256"]=hashlib.sha256(text.encode()).hexdigest()
        with self.assertRaisesRegex(Semantic200Blocked,"ERROR_PREVENTION_MISSING"):
            invoke(inv=inv)

    def test_live_controller_close_wired(self):
        s=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_frozen200_semantic_verdicts import inspect as semantic200_inspect",s)
        self.assertIn("SUPERVISOR_C07_FIRST200_ORIGINAL_SEMANTIC_VERDICTS",s)
        self.assertIn("semantic200['semantic_failures'] == 0",s)

if __name__=="__main__":unittest.main()

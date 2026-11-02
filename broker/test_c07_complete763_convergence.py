"""C07 adversarial 763 original-source coverage/convergence test.

Synthetic inventories test missing IDs, duplicates, source drift, replay and
false MG0. They do not certify real project assets or rules.
"""
import hashlib
import unittest
from unittest.mock import Mock,patch
from c07_complete763_convergence import inspect,ConvergenceBlocked,SCHEMA
from c07_cohort200_canonical import FAMILY_COUNTS

MASTER=b"original synthetic master only"
SHA=hashlib.sha256(MASTER).hexdigest()
WORK={"master_sha256":SHA,"attempt_id":"a"*64,"operation_sha256":"b"*64}
ASSET="GOLDEN_GARDEN";STEP="STEP009"
PLAN={"master_sha256":SHA}
AUDIT=[{"record_hash":"audit%02d"%n} for n in range(1,12)]
TAIL=AUDIT[-1]["record_hash"]
STATE={"last_audit_hash":TAIL,"active_step":{"step":STEP}}
NAMES=("cohort200","batch100","beh50","bf50","gk50","mq50","ten_process",
       "q200_actual","q100_final")

def rule_row(rid,family):
    clause="Original literal requirement "+rid
    return {"family":family,"source":"master","source_sha256":SHA,
            "requirement":clause,
            "requirement_sha256":hashlib.sha256(clause.encode()).hexdigest()}

def fixture():
    f={}
    for group,count in FAMILY_COUNTS.items():
        f[group]=["ORIGINAL_"+group+"_%03d"%n for n in range(1,count+1)]
    f["AAA-200"]=["AAA-200-"+chr(65+(n-1)//10)+"-%03d"%n
                  for n in range(1,201)]
    f["BEHAVIOR_110"]=["BEHAVIOR-%03d"%n for n in range(1,111)]
    f["QUESTIONS_300"]=["Q-%03d"%n for n in range(1,301)]
    data={rid:rule_row(rid,group)
          for group,ids in f.items() for rid in ids}
    inv={"schema":"gg-effective-family-inventory-v1","rule_count":763,
         "source_digests":{"master":SHA},"canonical_master_sha256":SHA,
         "families":f,"rules":data}
    controller=Mock()
    controller.master.read_bytes.return_value=MASTER
    bank={rid:data[rid]["requirement"] for rid in f["QUESTIONS_300"]}
    groups={}
    all_nonasset=[rid for g,ids in f.items()
                  if g not in ("AAA-200","BEHAVIOR_110","QUESTIONS_300")
                  for rid in ids]
    groups["cohort200"]=all_nonasset+["Q-%03d"%n for n in range(254,301)]
    groups["batch100"]=(
        ["AAA-200-"+chr(65+(n-1)//10)+"-%03d"%n
         for n in list(range(1,11))+list(range(111,121))+
                  list(range(181,201))]
        +["BEHAVIOR-%03d"%n for n in range(51,111)])
    groups["beh50"]=["BEHAVIOR-%03d"%n for n in range(1,51)]
    groups["bf50"]=["AAA-200-"+chr(65+(n-1)//10)+"-%03d"%n
                    for n in range(11,61)]
    groups["gk50"]=["AAA-200-"+chr(65+(n-1)//10)+"-%03d"%n
                    for n in range(61,111)]
    groups["mq50"]=["AAA-200-"+chr(65+(n-1)//10)+"-%03d"%n
                    for n in range(121,171)]
    groups["ten_process"]=["AAA-200-R-%03d"%n for n in range(171,181)]
    groups["q200_actual"]=["Q-%03d"%n for n in range(1,201)]
    groups["q100_final"]=["Q-%03d"%n for n in range(201,301)]
    reports={}
    for i,(key,ids) in enumerate(groups.items(),1):
        rows={rid:{"rule_id":rid,
                   "source_sha256":SHA,
                   "requirement_sha256":data[rid]["requirement_sha256"],
                   "individual_mg0":"UNKNOWN",
                   "advancement_authorized":False,
                   "original_question":bank[rid] if rid.startswith("Q-") else None,
                   "semantic_verdict":"UNKNOWN",
                   } for rid in ids}
        reports[key]={
            "rules":rows,
            "source_rules_examined":len(ids),
            "source_question_count":len(ids),
            "individual_mg0_passes":0,
            "advancement_authorized":False,
            "attempt_id":WORK["attempt_id"],
            "operation_sha256":WORK["operation_sha256"],
            "original_audit_tail":AUDIT[i-1]["record_hash"],
            "original_audit_sha256":hashlib.sha256(str(i).encode()).hexdigest(),
        }
    return inv,controller,bank,reports

def call(inv,controller,bank,reports):
    with patch("c07_complete763_convergence.extract_bank",
               return_value=bank), \
         patch("c07_complete763_convergence._original_attempt",
               return_value=(AUDIT,TAIL,STATE,"actual-full-audit-sha")):
        return inspect(inv,PLAN,controller,ASSET,STEP,WORK,**reports)

class Convergence763Tests(unittest.TestCase):
    def test_exactly_763_original_ids_and_253_are_not_reimplemented(self):
        inv,controller,bank,reports=fixture()
        out=call(inv,controller,bank,reports)
        self.assertEqual(out["schema"],SCHEMA)
        self.assertEqual(out["source_rules_covered"],763)
        self.assertEqual(out["prior_six_batches_distinct"],510)
        self.assertEqual(out["existing_original_question_rules_reconciled"],253)
        self.assertEqual(out["all_question_ids_verified"],300)
        self.assertEqual(out["per_engine_primary_ownership"]["Q001_Q200"],200)
        self.assertEqual(out["per_engine_primary_ownership"]["Q201_Q300"],53)
        self.assertEqual(len(out["all_rule_ids"]),763)
        self.assertEqual(out["independent_mg0_passes"],0)
        self.assertFalse(out["advancement_authorized"])

    def test_historic_q254_q300_overlap_is_not_double_counted(self):
        inv,c,bank,reports=fixture()
        out=call(inv,c,bank,reports)
        self.assertEqual(sum(out["per_engine_primary_ownership"].values()),763)
        self.assertEqual(out["per_engine_primary_ownership"][
                         "GOVERNANCE_153_Q254_300"],200)

    def test_any_missing_original_rule_blocks(self):
        inv,c,bank,reports=fixture()
        del reports["q100_final"]["rules"]["Q-253"]
        with self.assertRaises(ConvergenceBlocked):call(inv,c,bank,reports)

    def test_duplicate_early_question_in_another_cohort_blocks(self):
        inv,c,bank,reports=fixture()
        r=reports["cohort200"]["rules"]
        r["Q-200"]=reports["q200_actual"]["rules"]["Q-200"]
        del r["Q-300"]
        with self.assertRaises(ConvergenceBlocked):call(inv,c,bank,reports)

    def test_source_digest_substitution_blocks(self):
        inv,c,bank,reports=fixture()
        reports["gk50"]["rules"]["AAA-200-G-061"]["source_sha256"]="0"*64
        with self.assertRaises(ConvergenceBlocked):call(inv,c,bank,reports)

    def test_fake_positive_mg0_blocks(self):
        inv,c,bank,reports=fixture()
        reports["q200_actual"]["rules"]["Q-001"]["individual_mg0"]="PASS"
        with self.assertRaises(ConvergenceBlocked):call(inv,c,bank,reports)

    def test_replayed_source_engine_from_other_attempt_blocks(self):
        inv,c,bank,reports=fixture()
        reports["bf50"]["attempt_id"]="f"*64
        with self.assertRaises(ConvergenceBlocked):call(inv,c,bank,reports)

    def test_source_engine_outside_real_audit_chain_blocks(self):
        inv,c,bank,reports=fixture()
        reports["ten_process"]["original_audit_tail"]="fake-tail"
        with self.assertRaises(ConvergenceBlocked):call(inv,c,bank,reports)

    def test_original_master_bytes_drift_blocks(self):
        inv,c,bank,reports=fixture()
        c.master.read_bytes.return_value=b"modified-master"
        with self.assertRaises(ConvergenceBlocked):call(inv,c,bank,reports)

    def test_duplicate_ids_inside_canonical_families_blocks(self):
        inv,c,bank,reports=fixture()
        inv["families"]["QUESTIONS_300"][1]="Q-001"
        with self.assertRaises(ConvergenceBlocked):call(inv,c,bank,reports)

    def test_integrated_real_controller_close_records_763(self):
        from pathlib import Path
        src=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_complete763_convergence import inspect as inspect_763",src)
        self.assertIn("SUPERVISOR_C07_ALL763_ORIGINAL_SOURCE_CONVERGENCE",src)
        self.assertIn("all763['source_rules_covered'] == 763",src)

if __name__=="__main__":
    unittest.main()

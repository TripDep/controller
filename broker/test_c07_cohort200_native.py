"""Adversarial synthetic test of 153 governance + 47 final question sources.

Tests verify only source correctness and machine witness handling; no scenario
passes independent full semantics, owner review, FiveM runtime or MG0.
"""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch,Mock

from test_glb_machine_qa import synthetic_glb
from c07_cohort200_canonical import FAMILY_COUNTS,Q_IDS
from c07_cohort200_domains import FAMILY_LANES,QUESTION_BANDS
from c07_cohort200_source import select,CohortSourceBlocked
from c07_cohort200_native import (
    inspect,SCHEMA,NativeCohort200Blocked
)

MASTER=b"unmodified fixture master for original-source test"
MASTER_SHA=hashlib.sha256(MASTER).hexdigest()
STEP="STEP006"
WORK={"master_sha256":MASTER_SHA,"attempt_id":"a"*64,
      "operation_sha256":"b"*64,"phase":"P0","work_dependencies":{}}
PLAN={"master_sha256":MASTER_SHA,"operation":{"action":"MODEL"},
      "dependency_files":{}}
STATE={"active_step":{"step":STEP},"last_audit_hash":"tail"}
GLB=synthetic_glb()
ORIGINAL=("NATIVE_EXPORT","/safe/asset.glb",hashlib.sha256(GLB).hexdigest(),GLB)
SOURCE=("SOURCE_EDITABLE","/safe/asset.blend",
        hashlib.sha256(b"original blender bytes").hexdigest(),b"original blender bytes")

def fixture():
    families={}
    for group,count in FAMILY_COUNTS.items():
        families[group]=["SYNTH_"+group+"-"+str(n).zfill(3) for n in range(1,count+1)]
    families["AAA-200"]=["AAA-200-A-"+str(n).zfill(3) for n in range(1,201)]
    families["BEHAVIOR_110"]=["BEHAVIOR-"+str(n).zfill(3) for n in range(1,111)]
    families["QUESTIONS_300"]=["Q-"+str(n).zfill(3) for n in range(1,301)]
    rule_data={}
    question_bank={}
    for group,ids in families.items():
        for rid in ids:
            wording="Immutable original "+rid+" source requirement"
            question_bank[rid]=wording
            rule_data[rid]={"family":group,"source":"master",
                            "source_sha256":MASTER_SHA,
                            "requirement":wording,
                            "requirement_sha256":hashlib.sha256(wording.encode()).hexdigest()}
    inventory={
        "schema":"gg-effective-family-inventory-v1","rule_count":763,
        "canonical_master_sha256":MASTER_SHA,
        "source_digests":{"master":MASTER_SHA},
        "families":families,"rules":rule_data,
    }
    ctrl=Mock()
    ctrl.root=Path("/safe")
    ctrl.master.read_bytes.return_value=MASTER
    return inventory,ctrl,question_bank

class Cohort200Tests(unittest.TestCase):
    def test_all_new_200_and_original_17_family_counts(self):
        inv,ctrl,bank=fixture()
        with patch("c07_cohort200_source.MASTER_SHA",MASTER_SHA), \
             patch("c07_cohort200_source.extract_bank",return_value={
                rid:bank[rid] for rid in inv["families"]["QUESTIONS_300"]}):
            ids,groups=select(inv,ctrl,WORK)
        self.assertEqual(len(ids),200)
        self.assertEqual(len(set(ids)),200)
        self.assertEqual(sum(x not in Q_IDS for x in ids),153)
        self.assertEqual(set(ids)&set(Q_IDS),set(Q_IDS))
        self.assertEqual(len(FAMILY_LANES),17)
        self.assertEqual(set(FAMILY_LANES),set(FAMILY_COUNTS))
        self.assertEqual({n for first,last,_ in QUESTION_BANDS
                          for n in range(first,last+1)},set(range(254,301)))

    def test_each_of_200_original_source_clauses_rejects_tampering(self):
        inv,ctrl,bank=fixture()
        for rid in [k for k in inv["rules"]
                    if inv["rules"][k]["family"] not in
                       ("AAA-200","BEHAVIOR_110","QUESTIONS_300")]+list(Q_IDS):
            with self.subTest(source=rid):
                altered=fixture()[0]
                altered["rules"][rid]["requirement"]+=" forged"
                with patch("c07_cohort200_source.MASTER_SHA",MASTER_SHA), \
                     patch("c07_cohort200_source.extract_bank",
                           return_value={q:bank[q] for q in
                               inv["families"]["QUESTIONS_300"]}):
                    with self.assertRaises(CohortSourceBlocked):
                        select(altered,ctrl,WORK)

    def test_real_attempt_all_200_have_six_original_predicates_no_mg0(self):
        inv,ctrl,bank=fixture()
        with patch("c07_cohort200_source.MASTER_SHA",MASTER_SHA), \
             patch("c07_cohort200_source.extract_bank",
                   return_value={q:bank[q] for q in
                       inv["families"]["QUESTIONS_300"]}), \
             patch("c07_cohort200_native._original_attempt",
                   return_value=([],"tail",STATE,"auditsha")), \
             patch("c07_cohort200_native._registered_artifacts",
                   return_value=[SOURCE,ORIGINAL]):
            r=inspect(inv,PLAN,ctrl,"GOLDEN_GARDEN",STEP,WORK,
                      source_loader=lambda _:b"original")
        self.assertEqual(r["schema"],SCHEMA)
        self.assertEqual(r["source_rules_examined"],200)
        self.assertEqual(r["governance_rules_examined"],153)
        self.assertEqual(r["final_question_rules_examined"],47)
        self.assertEqual(r["original_source_evidence_checks"],1200)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertEqual(r["full_rule_passes"],0)
        self.assertTrue(all(len(row["original_machine_criteria"])==6 and
                            row["full_rule_semantics"]=="UNKNOWN" and
                            row["individual_mg0"]=="UNKNOWN" and
                            row["owner_approval"]=="UNKNOWN" and
                            not row["advancement_authorized"]
                            for row in r["rules"].values()))

    def test_wrong_original_digest_never_counts_as_source_evidence(self):
        inv,ctrl,bank=fixture()
        corrupted=("NATIVE_EXPORT","/safe/asset.glb","0"*64,GLB)
        with patch("c07_cohort200_source.MASTER_SHA",MASTER_SHA), \
             patch("c07_cohort200_source.extract_bank",
                   return_value={q:bank[q] for q in
                       inv["families"]["QUESTIONS_300"]}), \
             patch("c07_cohort200_native._original_attempt",
                   return_value=([],"tail",STATE,"auditsha")), \
             patch("c07_cohort200_native._registered_artifacts",
                   return_value=[corrupted]):
            with self.assertRaisesRegex(NativeCohort200Blocked,
                                        "UNVERIFIED_ORIGINAL_BYTES"):
                inspect(inv,PLAN,ctrl,"GOLDEN_GARDEN",STEP,WORK,
                        source_loader=lambda _:b"original")

    def test_current_rule_receipt_only_if_original_artifact_matches(self):
        inv,ctrl,bank=fixture()
        rid="Q-300"
        event={"event":"SUPERVISOR_RULE_EVIDENCE","step":STEP,
               "attempt_id":WORK["attempt_id"],
               "operation_sha256":WORK["operation_sha256"],
               "rule_id":rid,
               "requirement_sha256":inv["rules"][rid]["requirement_sha256"],
               "artifact_sha256":ORIGINAL[2]}
        with patch("c07_cohort200_source.MASTER_SHA",MASTER_SHA), \
             patch("c07_cohort200_source.extract_bank",
                   return_value={q:bank[q] for q in
                       inv["families"]["QUESTIONS_300"]}), \
             patch("c07_cohort200_native._original_attempt",
                   return_value=([event],"tail",STATE,"auditsha")), \
             patch("c07_cohort200_native._registered_artifacts",
                   return_value=[ORIGINAL]):
            r=inspect(inv,PLAN,ctrl,"GOLDEN_GARDEN",STEP,WORK,
                      source_loader=lambda _:b"original")
        check=r["rules"][rid]["original_machine_criteria"]
        self.assertTrue(check["current_rule_specific_original_file_witness"])
        self.assertFalse(check["complete_semantics_independently_approved"])
        self.assertEqual(r["individual_mg0_passes"],0)

    def test_controller_close_has_executable_cohort_consumer_and_audit(self):
        c=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_cohort200_native import inspect as inspect_cohort200",c)
        self.assertIn("SUPERVISOR_C07_NEW200_ORIGINAL_NATIVE",c)

if __name__=="__main__":
    unittest.main()

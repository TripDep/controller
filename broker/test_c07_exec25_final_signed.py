"""EXEC25 final: 25/25 SIGNED positive only on test-only isolated fixtures.

The test-only signer MUST NOT be used for real C07; CI green has no authority
to mark production original-source rules or individual MG0 as certified.
"""
import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

import c07_exec25_final_signed as gate
from c07_exec25_native_observation import IDS
from c07_exec25_original_reviewed_native import CRITERIA
from c07_mg0_signed25 import canonical

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

class TestIndependentEXEC25Close(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="test-only-exec25-owner-signer-")
        root=Path(cls.temp.name)
        cls.key=root/"TEST_ONLY_OWNER_PRIVATE.pem"
        cls.pub=root/"TEST_ONLY_OWNER_PUBLIC.pem"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(cls.key)],capture_output=True,check=True)
        subprocess.run(["openssl","pkey","-in",str(cls.key),"-pubout",
                        "-out",str(cls.pub)],capture_output=True,check=True)
        cls.public=cls.pub.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def sign(self,data):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"data").write_bytes(canonical(data))
            subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(self.key),
                            "-rawin","-in",str(root/"data"),
                            "-out",str(root/"signature")],
                           capture_output=True,check=True)
            return base64.b64encode((root/"signature").read_bytes()).decode()

    def setUp(self):
        self.master=b"fixture MASTER only (not user original source)"
        self.audit=b"fixture audit - actual production uses checked hash-chain"
        self.master_sha=sha(self.master)
        self.asset="SYNTHETIC_ASSET"
        self.attempt="a"*64
        self.operation="b"*64
        self.id="TEST_ONLY_SIGNER"
        self.work={"master_sha256":self.master_sha,"attempt_id":self.attempt,
                   "operation_sha256":self.operation}
        self.controller=Mock()
        self.controller.master.read_bytes.return_value=self.master
        self.controller.audit_path.return_value.read_bytes.return_value=self.audit
        self.inv={"rule_count":763,"canonical_master_sha256":self.master_sha,
                  "rules":{rid:{"requirement_sha256":sha(rid.encode()),
                                "source_sha256":self.master_sha} for rid in IDS}}
        self.context={"controller":self.controller,"asset":self.asset,
                      "step":"TEST_ONLY_STEP","work":self.work,
                      "inventory":self.inv,"plan":{"master_sha256":self.master_sha}}
        self.original={"rule_count":25,"criteria_count":100,
            "positive_scope_observations":100,
            "original_audit_sha256":sha(self.audit),
            "original_audit_tail":"c"*64,
            "attempt_id":self.attempt,"master_sha256":self.master_sha,
            "full_rule_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":{}}
        self.mg0={"rule_count":25,"audit_sha256":sha(self.audit),
                  "audit_tail_sha256":"c"*64,"attempt_id":self.attempt,
                  "counts":{"FAIL":0,"UNKNOWN":25,"PASS":0},
                  "failed_rule_ids":[],"individual_mg0_passes":0,"rules":{}}
        for rid in IDS:
            self.original["rules"][rid]={
                "rule_id":rid,
                "criteria":{k:True for k in CRITERIA[rid]},
                "scoped_positive_count":4,
                "requirement_sha256":self.inv["rules"][rid]["requirement_sha256"],
                "source_sha256":self.master_sha}
            self.mg0["rules"][rid]={
                "verdict":"UNKNOWN",
                "uncorrected_failure_count":0,
                "observation_sha256":sha((rid+":original-negative-MG0").encode())}
        self.reviews={}
        for rid in IDS:
            row=self.inv["rules"][rid]
            ref=sha((rid+":independently-reviewed-artifact-test-only").encode())
            evidence={
                "schema":gate.EVIDENCE_SCHEMA,"rule_id":rid,
                "attempt_id":self.attempt,"master_sha256":self.master_sha,
                "requirement_sha256":row["requirement_sha256"],
                "full_clause_findings":[{
                    "clause":rid+" full original clause actually reviewed",
                    "finding":"PASS","evidence_sha256":ref}],
                "five_mg0_trigger_findings":[{
                    "trigger_id":n,"independently_replayed":True,
                    "finding":"PASS","evidence_sha256":ref} for n in range(1,6)],
                "independent_evidence_references":[{
                    "sha256":ref,"source":"TEST_ONLY_ORIGINAL_EVIDENCE_FIXTURE",
                    "verified":True}],
                "independent_review_method":"TEST_ONLY_cryptography_fixture_not_real_review",
            }
            raw=canonical(evidence)
            payload={
                "schema":gate.SCHEMA,"rule_id":rid,"asset":self.asset,
                "attempt_id":self.attempt,"operation_sha256":self.operation,
                "master_sha256":self.master_sha,
                "audit_sha256":sha(self.audit),"audit_tail_sha256":"c"*64,
                "requirement_sha256":row["requirement_sha256"],
                "source_sha256":row["source_sha256"],
                "original_exec25_observation_sha256":sha(canonical(self.original["rules"][rid])),
                "original_mg0_observation_sha256":self.mg0["rules"][rid]["observation_sha256"],
                "external_evidence_sha256":sha(raw),"reviewer_id":self.id,
                "full_original_clause_pass":True,
                "five_independent_mg0_triggers_pass":True,
                "owner_provenance_authenticated":True,
                "current_attempt_reapplication_verified":True,
            }
            self.reviews[rid]={
                "payload":payload,"signature_base64":self.sign(payload),
                "evidence_base64":base64.b64encode(raw).decode(),
            }

    def run(self):
        with patch.object(gate,"inspect_exec",return_value=self.original),\
             patch.object(gate,"read_mg0",return_value=self.mg0):
            return gate.certify(self.context,self.reviews,self.public,self.id)

    def test_complete_25_properly_signed_synthetic_fixture_only(self):
        report=self.run()
        self.assertEqual(report["independent_mg0_passes"],25)
        self.assertEqual(report["independent_full_semantic_passes"],25)
        self.assertEqual(report["full_original_source_criteria_verified"],100)
        self.assertEqual(set(report["rules"]),set(IDS))
        self.assertFalse(report["advancement_authorized"])
        self.assertTrue(report["other_738_rules_not_certified_by_this_report"])

    def test_missing_one_signed_rule_prevents_any_batch_pass(self):
        self.reviews.pop(IDS[24])
        with self.assertRaisesRegex(gate.FinalCertificationBlocked,"EXACT_25"):
            self.run()

    def test_negative_original_mg0_failure_cannot_be_overridden(self):
        self.mg0["counts"]={"FAIL":1,"UNKNOWN":24,"PASS":0}
        self.mg0["failed_rule_ids"]=[IDS[3]]
        self.mg0["rules"][IDS[3]]["verdict"]="FAIL"
        self.mg0["rules"][IDS[3]]["uncorrected_failure_count"]=1
        with self.assertRaisesRegex(gate.FinalCertificationBlocked,"ORIGINAL_CRITERIA"):
            self.run()

    def test_99_of_100_source_observations_rejects_complete_certificate(self):
        self.original["positive_scope_observations"]=99
        self.original["rules"][IDS[5]]["scoped_positive_count"]=3
        with self.assertRaisesRegex(gate.FinalCertificationBlocked,"ORIGINAL_CRITERIA"):
            self.run()

    def test_tampered_signed_evidence_bytes_do_not_pass(self):
        rid=IDS[2]
        self.reviews[rid]["evidence_base64"]=base64.b64encode(b'{"spoof":true}').decode()
        with self.assertRaisesRegex(gate.FinalCertificationBlocked,"EVIDENCE_SCHEMA"):
            self.run()

    def test_other_attempt_signed_review_does_not_pass(self):
        rid=IDS[5]
        self.reviews[rid]["payload"]["attempt_id"]="f"*64
        with self.assertRaisesRegex(gate.FinalCertificationBlocked,"CROSS_ATTEMPT"):
            self.run()

    def test_wrong_owner_key_cannot_approve_even_if_signed(self):
        with self.assertRaisesRegex(gate.FinalCertificationBlocked,""):
            with patch.object(gate,"signature_valid",
                              side_effect=gate.FinalCertificationBlocked("UNTRUSTED_OWNER_KEY")):
                self.run()

    def test_forged_positive_without_real_independent_signature_rejected(self):
        rid=IDS[9]
        self.reviews[rid]["signature_base64"]="A"*88
        with self.assertRaises(Exception):
            self.run()

    def test_missing_one_of_five_trigger_proofs_never_certifies(self):
        rid=IDS[1]
        evidence=json.loads(base64.b64decode(self.reviews[rid]["evidence_base64"]))
        evidence["five_mg0_trigger_findings"].pop()
        self.reviews[rid]["evidence_base64"]=base64.b64encode(canonical(evidence)).decode()
        with self.assertRaisesRegex(gate.FinalCertificationBlocked,"FIVE_MG0"):
            self.run()

    def test_no_global_763_pass_is_required_for_scoped_signed_review(self):
        # The 738 other canonical rules remain untouched and cannot be falsely
        # counted by this independent 25-rule *certificate only*.
        self.assertEqual(set(self.original["rules"]),set(IDS))
        self.assertEqual(self.run()["independent_full_semantic_passes"],25)

if __name__=="__main__":unittest.main()

"""Isolated TEST-ONLY Ed25519 fixtures; no production signer or asset PASS."""
import base64
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import c07_mg0_signed25 as signed

def sha(data):
    return hashlib.sha256(data).hexdigest()

class TestSignedMG0Macro25(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="c07-mg0-test-only-")
        folder = Path(cls.temp.name)
        cls.private = folder / "TEST_ONLY_signer_private.pem"
        cls.public = folder / "TEST_ONLY_signer_public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out",
                        str(cls.private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(cls.private), "-pubout",
                        "-out", str(cls.public)], check=True, capture_output=True)
        cls.pem = cls.public.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.master = b"synthetic-original-master-not-production"
        self.audit = b"synthetic-audit-verified-only-in-isolated-test"
        self.master_sha = sha(self.master)
        self.asset = "TEST_ASSET"
        self.attempt = "a" * 64
        self.rules = [f"TEST-{n:03d}" for n in range(25)]
        self.inv = {"canonical_master_sha256": self.master_sha,
                    "rules": {rid: {"requirement_sha256": sha(rid.encode()),
                                    "source_sha256": sha((rid + ":source").encode())}
                              for rid in self.rules}}
        self.work = {"attempt_id": self.attempt, "master_sha256": self.master_sha}
        self.native_input = {"decision_sha256": "b" * 64}
        self.native = {"schema": "gg-c07-763-independent-post-operation-certification-v1",
                       "attempt_id": self.attempt, "master_sha256": self.master_sha,
                       "native_decision_sha256": self.native_input["decision_sha256"],
                       "rules": {rid: {"post_native_semantic": "PASS",
                                      "individual_mg0": "PASS",
                                      "source_specific_reviewer_approved": True,
                                      "semantically_certified": True,
                                      "verified_native_packet_digest": sha((rid + ":packet").encode())}
                                 for rid in self.rules}}
        self.mg0 = {"rule_count": 25, "audit_sha256": sha(self.audit),
                    "audit_tail_sha256": "c" * 64,
                    "attempt_id": self.attempt,
                    "rules": {rid: {"verdict": "UNKNOWN", "uncorrected_failure_count": 0,
                                    "observation_sha256": sha((rid + ":mg0").encode())}
                              for rid in self.rules}}
        self.reviews = {}
        for rid in self.rules:
            row = self.inv["rules"][rid]
            payload = {
                "schema": signed.SCHEMA, "asset": self.asset, "rule_id": rid,
                "attempt_id": self.attempt, "master_sha256": self.master_sha,
                "audit_sha256": sha(self.audit),
                "audit_tail_sha256": self.mg0["audit_tail_sha256"],
                "requirement_sha256": row["requirement_sha256"],
                "source_sha256": row["source_sha256"],
                "native_decision_sha256": self.native_input["decision_sha256"],
                "native_packet_sha256": self.native["rules"][rid]["verified_native_packet_digest"],
                "original_mg0_observation_sha256": self.mg0["rules"][rid]["observation_sha256"],
                "external_evidence_sha256": sha((rid + ":external-evidence").encode()),
                "reviewer_id": "SYNTHETIC_TEST_ONLY_REVIEWER",
                "reviewed_trigger_ids": [1, 2, 3, 4, 5],
                "independent_full_semantic_pass": True,
                "independent_mg0_pass": True,
                "owner_provenance_authenticated": True,
                "current_attempt_reapplication_verified": True,
            }
            self.reviews[rid] = {"payload": payload,
                                 "signature_base64": self.sign(payload)}

    def sign(self, payload):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "data").write_bytes(signed.canonical(payload))
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(self.private),
                            "-rawin", "-in", str(p / "data"), "-out", str(p / "sig")],
                           check=True, capture_output=True)
            return base64.b64encode((p / "sig").read_bytes()).decode()

    def check(self, reviews=None, pem=None):
        with patch("c07_mg0_individual.inspect_batch", return_value=self.mg0), \
             patch("c07_763_post_certification.inspect", return_value=self.native):
            return signed.certify_25(self.master, self.audit, self.asset, self.master_sha,
                                     self.rules, self.attempt, self.inv, {}, self.work,
                                     self.native_input, self.reviews if reviews is None else reviews,
                                     self.pem if pem is None else pem)

    def test_synthetic_signatures_all_25_complete(self):
        result = self.check()
        self.assertEqual(result["full_semantic_passes"], 25)
        self.assertEqual(result["independent_mg0_passes"], 25)
        self.assertFalse(result["advancement_authorized"])
        self.assertEqual(len(result["rules"]), 25)

    def test_missing_1_of_25_never_partial_success(self):
        reviews = dict(self.reviews)
        reviews.pop(self.rules[-1])
        with self.assertRaisesRegex(signed.CertificationBlocked, "25_EXTERNAL_REVIEWS"):
            self.check(reviews)

    def test_changed_binding_with_original_signature_rejected(self):
        reviews = {k:dict(v) for k,v in self.reviews.items()}
        changed = self.rules[0]
        reviews[changed] = {**reviews[changed],
                            "payload": {**reviews[changed]["payload"],
                                        "attempt_id": "b" * 64}}
        with self.assertRaisesRegex(signed.CertificationBlocked, "CROSS_ATTEMPT"):
            self.check(reviews)

    def test_tampered_signed_review_rejected(self):
        reviews = {k:dict(v) for k,v in self.reviews.items()}
        changed = self.rules[0]
        reviews[changed] = {**reviews[changed],
                            "payload": {**reviews[changed]["payload"],
                                        "reviewer_id": "FORGED_ID"}}
        with self.assertRaisesRegex(signed.CertificationBlocked, "SIGNATURE_REJECTED"):
            self.check(reviews)

    def test_untrusted_public_key_rejected(self):
        with self.assertRaisesRegex(signed.CertificationBlocked, "PUBLIC_KEY_REQUIRED"):
            self.check(pem=b"")

    def test_unknown_native_rule_cannot_be_signed_into_pass(self):
        self.native["rules"][self.rules[10]]["post_native_semantic"] = "UNKNOWN"
        with self.assertRaisesRegex(signed.CertificationBlocked, "UNCERTIFIED_NATIVE"):
            self.check()

    def test_uncorrected_audit_failure_cannot_be_signed_into_pass(self):
        self.mg0["rules"][self.rules[10]]["verdict"] = "FAIL"
        self.mg0["rules"][self.rules[10]]["uncorrected_failure_count"] = 1
        with self.assertRaisesRegex(signed.CertificationBlocked, "UNCORRECTED"):
            self.check()

    def test_partial_trigger_review_rejected(self):
        reviews = {k:dict(v) for k,v in self.reviews.items()}
        rid = self.rules[7]
        reviews[rid] = {**reviews[rid],
                        "payload": {**reviews[rid]["payload"],
                                    "reviewed_trigger_ids": [1, 2, 3, 4]}}
        with self.assertRaisesRegex(signed.CertificationBlocked, "ALL_FIVE_TRIGGER"):
            self.check(reviews)

    def test_missing_owner_verification_rejected(self):
        reviews = {k:dict(v) for k,v in self.reviews.items()}
        rid = self.rules[9]
        reviews[rid] = {**reviews[rid],
                        "payload": {**reviews[rid]["payload"],
                                    "owner_provenance_authenticated": False}}
        with self.assertRaisesRegex(signed.CertificationBlocked, "ALL_FIVE_TRIGGER"):
            self.check(reviews)

    def test_source_or_audit_drift_rejected(self):
        self.inv["rules"][self.rules[4]]["source_sha256"] = "f" * 64
        with self.assertRaisesRegex(signed.CertificationBlocked, "CROSS_ATTEMPT"):
            self.check()
        self.inv["rules"][self.rules[4]]["source_sha256"] = sha((self.rules[4]+':source').encode())
        self.mg0["audit_sha256"] = "e"*64
        with self.assertRaisesRegex(signed.CertificationBlocked, "AUDIT_READBACK"):
            self.check()

if __name__ == "__main__":
    unittest.main()

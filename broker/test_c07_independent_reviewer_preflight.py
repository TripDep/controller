"""C07 reviewer onboarding preflight adversarial tests (TEST-ONLY keys)."""
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from c07_independent_reviewer_preflight import (
    TRUST_PATH, ReviewerNotEnrolled, check,
)

class ReviewerPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="c07-reviewer-test-only-")
        self.root = Path(self.temp.name)
        self.destination = self.root / TRUST_PATH
        self.destination.parent.mkdir(parents=True)
        self.authorized_identity = "TEST_ONLY_EXTERNAL_REVIEWER"

    def tearDown(self):
        self.temp.cleanup()

    def key(self):
        private = self.root / "TEST_ONLY_PRIVATE.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                        "-out", str(private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout",
                        "-out", str(self.destination)], check=True, capture_output=True)
        return hashlib.sha256(self.destination.read_bytes()).hexdigest()

    def inspect(self, digest):
        return check(self.root, reviewer_identity=self.authorized_identity,
                     owner_authorized_sha256=digest)

    def test_missing_public_key_never_enrolls(self):
        with self.assertRaisesRegex(ReviewerNotEnrolled, "NOT_ENROLLED"):
            self.inspect("0" * 64)

    def test_fingerprint_must_be_externally_provided(self):
        valid = self.key()
        with self.assertRaisesRegex(ReviewerNotEnrolled, "FINGERPRINT_REQUIRED"):
            self.inspect(None)
        with self.assertRaisesRegex(ReviewerNotEnrolled, "NOT_OWNER_AUTHORIZED"):
            self.inspect("f" * 64 if valid != "f" * 64 else "e" * 64)

    def test_test_only_ed25519_key_can_pass_preflight_not_mg0(self):
        approved = self.key()
        result = self.inspect(approved)
        self.assertEqual(result["owner_authorized_public_key_sha256"], approved)
        self.assertTrue(result["key_preflight_passed"])
        self.assertFalse(result["independent_review_performed"])
        self.assertEqual(result["signed_rules_certified"], 0)
        self.assertEqual(result["individual_mg0_certified"], 0)
        self.assertFalse(result["production_work_authorized"])

    def test_empty_reviewer_identity_rejected(self):
        self.key()
        with self.assertRaisesRegex(ReviewerNotEnrolled, "IDENTITY_NOT_AUTHORIZED"):
            check(self.root, reviewer_identity="",
                  owner_authorized_sha256="a" * 64)

    def test_swapped_key_fails_previous_owner_fingerprint(self):
        expected = self.key()
        self.key()
        with self.assertRaisesRegex(ReviewerNotEnrolled, "NOT_OWNER_AUTHORIZED"):
            self.inspect(expected)

    def test_fake_pem_with_matching_hash_not_accepted(self):
        self.destination.write_bytes(b"-----BEGIN PUBLIC KEY-----\nnot a real key\n")
        digest = hashlib.sha256(self.destination.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ReviewerNotEnrolled, "VALID_ED25519"):
            self.inspect(digest)

    def test_symlink_to_external_key_rejected(self):
        outside = self.root / "external_key.pem"
        self.key()
        self.destination.rename(outside)
        self.destination.symlink_to(outside)
        with self.assertRaisesRegex(ReviewerNotEnrolled, "SYMLINK_FORBIDDEN"):
            self.inspect(hashlib.sha256(outside.read_bytes()).hexdigest())

    def test_wrong_algorithm_rejected(self):
        private = self.root / "TEST_ONLY_RSA.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(private)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout",
                        "-out", str(self.destination)], check=True, capture_output=True)
        digest = hashlib.sha256(self.destination.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ReviewerNotEnrolled, "VALID_ED25519"):
            self.inspect(digest)

if __name__ == "__main__":
    unittest.main()

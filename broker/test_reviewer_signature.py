"""Synthetic negative tests; temporary signing keys are deleted, never enrolled."""
from __future__ import annotations
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import reviewer_signature as gate

SYNTHETIC_REPO = "example-sandbox/nonexistent-private-project"


class SignatureContractTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 13, 9, 0, tzinfo=timezone.utc)
        self.policy = {
            "schema": "gg-git-broker-v1", "enabled": True,
            "base_branch": "main", "repository_sha256": hashlib.sha256(SYNTHETIC_REPO.encode()).hexdigest(),
            "master_sha256": "a" * 64, "public_controller_sha": "b" * 40,
            "reviewer_public_key_sha256": "c" * 64,
            "required_checks": ["guard-tests", "phase-guard", "public-controller"],
        }
        self.auth = {
            "schema": "gg-owner-reviewed-pr-v1", "repository": SYNTHETIC_REPO,
            "pr_number": 19, "head_sha": "d" * 40, "base_sha": "e" * 40,
            "master_sha256": "a" * 64, "public_controller_sha": "b" * 40,
            "decision": "APPROVE_MERGE", "expires_at": "2026-10-13T09:10:00Z",
            "nonce": "synthetic_nonce_12345",
        }
        self.envelope = {"authorization": self.auth, "signature_base64": base64.b64encode(b"x" * 64).decode()}

    def test_fail_closed_with_unconfigured_public_policy(self):
        p = copy.deepcopy(self.policy)
        p["enabled"] = False
        with self.assertRaisesRegex(gate.Blocked, "BROKER_NOT_ARMED"):
            gate.checked_policy(p)

    def test_no_reviewer_public_key_is_enrolled(self):
        p = copy.deepcopy(self.policy)
        p["reviewer_public_key_sha256"] = None
        with self.assertRaisesRegex(gate.Blocked, "POLICY_SHA256_INVALID"):
            gate.checked_policy(p)

    def test_valid_synthetic_envelope_structure(self):
        p = gate.checked_policy(self.policy)
        auth, sig = gate.checked_authorization(self.envelope, p, now=self.now)
        self.assertEqual(auth["pr_number"], 19)
        self.assertEqual(len(sig), 64)

    def test_expired_signature(self):
        with self.assertRaisesRegex(gate.Blocked, "AUTH_EXPIRED_OR_OVER24H"):
            gate.checked_authorization(self.envelope, self.policy, now=self.now + timedelta(days=1))

    def test_too_far_future(self):
        with self.assertRaisesRegex(gate.Blocked, "AUTH_EXPIRED_OR_OVER24H"):
            gate.checked_authorization(self.envelope, self.policy, now=self.now - timedelta(days=3))

    def test_changed_head_sha_denies_signed_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            priv = root / "synthetic_only.key"
            pub = root / "synthetic_only.pub.pem"
            payload = root / "payload.json"
            sig = root / "signature.bin"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)], check=True, capture_output=True)
            payload.write_bytes(gate.canonical_authorization(self.auth))
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(priv), "-rawin", "-in", str(payload), "-out", str(sig)], check=True, capture_output=True)
            pin = hashlib.sha256(pub.read_bytes()).hexdigest()
            self.assertTrue(gate.verify_detached(self.auth, sig.read_bytes(), pub, pin))
            altered = {**self.auth, "head_sha": "f" * 40}
            with self.assertRaisesRegex(gate.Blocked, "ED25519_SIGNATURE_INVALID"):
                gate.verify_detached(altered, sig.read_bytes(), pub, pin)
            with self.assertRaisesRegex(gate.Blocked, "REVIEWER_PUBLIC_KEY_PIN_MISMATCH"):
                gate.verify_detached(self.auth, sig.read_bytes(), pub, "0" * 64)

    def test_wrong_repository_hash(self):
        p = {**self.policy, "repository_sha256": "0" * 64}
        with self.assertRaisesRegex(gate.Blocked, "REPOSITORY_PIN_MISMATCH"):
            gate.checked_authorization(self.envelope, p, now=self.now)

    def test_wrong_master_hash(self):
        p = {**self.policy, "master_sha256": "0" * 64}
        with self.assertRaisesRegex(gate.Blocked, "SOURCE_PIN_MISMATCH"):
            gate.checked_authorization(self.envelope, p, now=self.now)

    def test_boolean_pr_number_rejected(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["authorization"]["pr_number"] = True
        with self.assertRaisesRegex(gate.Blocked, "AUTH_PR_NUMBER_INVALID"):
            gate.checked_authorization(envelope, self.policy, now=self.now)

    def test_tampered_decision(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["authorization"]["decision"] = "UNKNOWN"
        with self.assertRaisesRegex(gate.Blocked, "AUTH_DECISION_INVALID"):
            gate.checked_authorization(envelope, self.policy, now=self.now)

    def test_invalid_signature_length(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["signature_base64"] = base64.b64encode(b"x" * 63).decode()
        with self.assertRaisesRegex(gate.Blocked, "SIGNATURE_INVALID"):
            gate.checked_authorization(envelope, self.policy, now=self.now)

    def test_base64_unvalidated_padding(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["signature_base64"] = "!!not-base64!!"
        with self.assertRaisesRegex(gate.Blocked, "SIGNATURE_INVALID"):
            gate.checked_authorization(envelope, self.policy, now=self.now)

    def test_duplicate_key_json_denied(self):
        with self.assertRaisesRegex(gate.Blocked, "DUPLICATE_JSON_KEY"):
            gate.parse_json_bytes(b'{"decision":"APPROVE_MERGE","decision":"REJECT"}')

    def test_oversized_json_denied(self):
        with self.assertRaisesRegex(gate.Blocked, "REQUEST_TOO_LARGE"):
            gate.parse_json_bytes(b"x" * 8193)

    def test_symlink_key_denied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real.key"
            real.write_bytes(b"not valid")
            link = root / "linked.key"
            link.symlink_to(real)
            with self.assertRaisesRegex(gate.Blocked, "REVIEWER_PUBLIC_KEY_MISSING"):
                gate.verify_detached(self.auth, b"x" * 64, link, "a" * 64)

    def test_absent_signed_envelope_cannot_activate_real_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pub = root / "public.pem"
            auth = root / "missing_envelope.json"
            policy = root / "policy.json"
            policy.write_text(json.dumps({**self.policy, "enabled": False}))
            with self.assertRaisesRegex(gate.Blocked, "INPUT_FILE_MISSING_OR_SYMLINK"):
                gate.verify_files(policy, auth, pub)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Public synthetic regression suite: no real credentials, merges or private data."""
from datetime import datetime, timedelta, timezone
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import git_release_broker_v2 as b


TEST_REPO = "synthetic/private-repository"

class SyntheticBrokerTests(unittest.TestCase):
    def setUp(self):
        self.head = "a" * 40
        self.base = "b" * 40
        self.policy = {
            "schema": "gg-git-broker-v1", "enabled": True,
            "repository_sha256": hashlib.sha256(TEST_REPO.encode()).hexdigest(), "base_branch": "main",
            "master_sha256": "c" * 64,
            "public_controller_sha": "d" * 40,
            "reviewer_public_key_sha256": "e" * 64,
            "required_checks": list(b.REQUIRED_CHECKS),
        }
        self.auth = {
            "schema": "gg-owner-reviewed-pr-v1", "repository": TEST_REPO,
            "pr_number": 19, "head_sha": self.head, "base_sha": self.base,
            "master_sha256": "c" * 64, "public_controller_sha": "d" * 40,
            "decision": "APPROVE_MERGE",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": "synthetic_review_2026_01",
        }
        self.pr = {
            "number": 19, "state": "open", "draft": False,
            "mergeable": True, "changed_files": 1,
            "head": {"sha": self.head, "repo": {"full_name": TEST_REPO}},
            "base": {"sha": self.base, "ref": "main", "repo": {"full_name": TEST_REPO}},
        }
        self.branch = {"commit": {"sha": self.base}}
        self.files = [{"filename": "governance/README.md"}]
        self.checks = {"total_count": 3, "check_runs": [
            {"name": name, "head_sha": self.head, "status": "completed",
             "conclusion": "success", "app": {"slug": "github-actions"}}
            for name in b.REQUIRED_CHECKS
        ]}

    def test_policy_defaults_block_execution(self):
        with self.assertRaisesRegex(b.Blocked, "BROKER_NOT_ARMED"):
            b.read_policy()

    def test_config_missing_review_key_fails(self):
        p = {**self.policy, "reviewer_public_key_sha256": None}
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "p.json"
            file.write_text(json.dumps(p))
            with self.assertRaisesRegex(b.Blocked, "REVIEWER_NOT_ENROLLED"):
                b.read_policy(file)

    def test_config_does_not_trust_truthy_string(self):
        p = {**self.policy, "enabled": "true"}
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "p.json"
            file.write_text(json.dumps(p))
            with self.assertRaisesRegex(b.Blocked, "BROKER_NOT_ARMED"):
                b.read_policy(file)

    def test_signature_missing_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Path(folder) / "req.json"
            f.write_text(json.dumps({"authorization": self.auth, "signature_base64": ""}))
            with self.assertRaisesRegex(b.Blocked, "BROKER_SIGNATURE_INVALID"):
                b.read_request(f)

    def test_expired_signature_rejected(self):
        auth = {**self.auth, "expires_at": "2020-01-01T00:00:00Z"}
        with tempfile.TemporaryDirectory() as folder:
            f = Path(folder) / "req.json"
            f.write_text(json.dumps({"authorization": auth, "signature_base64": base64.b64encode(b"a" * 64).decode()}))
            with self.assertRaisesRegex(b.Blocked, "BROKER_APPROVAL_EXPIRED_OR_TOO_LONG"):
                b.read_request(f)

    def test_approval_valid_for_more_than_day_blocked(self):
        auth = {**self.auth, "expires_at": "2099-01-01T00:00:00Z"}
        with tempfile.TemporaryDirectory() as folder:
            f = Path(folder) / "req.json"
            f.write_text(json.dumps({"authorization": auth, "signature_base64": base64.b64encode(b"a" * 64).decode()}))
            with self.assertRaisesRegex(b.Blocked, "BROKER_APPROVAL_EXPIRED_OR_TOO_LONG"):
                b.read_request(f)

    def test_valid_synthetic_snapshot(self):
        self.assertTrue(b.validate_snapshot(self.policy, self.auth, self.pr, self.branch, self.files, self.checks))

    def test_master_mismatch_denied(self):
        p = {**self.policy, "master_sha256": "f" * 64}
        with self.assertRaisesRegex(b.Blocked, "SIGNED_SOURCE_PINS_MISMATCH"):
            b.validate_snapshot(p, self.auth, self.pr, self.branch, self.files, self.checks)

    def test_changed_head_denied(self):
        pr = copy.deepcopy(self.pr)
        pr["head"]["sha"] = "f" * 40
        with self.assertRaisesRegex(b.Blocked, "SIGNED_PR_HEAD_OR_BASE_CHANGED"):
            b.validate_snapshot(self.policy, self.auth, pr, self.branch, self.files, self.checks)

    def test_moved_base_denied(self):
        base = {"commit": {"sha": "f" * 40}}
        with self.assertRaisesRegex(b.Blocked, "DEFAULT_BRANCH_MOVED"):
            b.validate_snapshot(self.policy, self.auth, self.pr, base, self.files, self.checks)

    def test_private_or_draft_pr_denied(self):
        pr = {**self.pr, "draft": True}
        with self.assertRaisesRegex(b.Blocked, "PR_NOT_MERGEABLE_STATE"):
            b.validate_snapshot(self.policy, self.auth, pr, self.branch, self.files, self.checks)

    def test_mergeable_unknown_fails(self):
        pr = {**self.pr, "mergeable": None}
        with self.assertRaisesRegex(b.Blocked, "PR_MERGEABILITY_NOT_CONFIRMED"):
            b.validate_snapshot(self.policy, self.auth, pr, self.branch, self.files, self.checks)

    def test_asset_paths_denied(self):
        for path in ("assets/a.py", "renders/x.png", "models/dragon.glb", "prod/a.blend",
                     "previews/test.jpg", "models.zip", "governance/preview.webp"):
            with self.subTest(path=path), self.assertRaisesRegex(b.Blocked, "ASSET_DELIVERY_IN_CHAT_ONLY"):
                b.path_allowed(path)

    def test_outside_governance_denied(self):
        for path in ("server.cfg", "any/script.py", "../../../etc/shadow", "/absolute"):
            with self.subTest(path=path), self.assertRaises(b.Blocked):
                b.path_allowed(path)

    def test_governance_paths_allowed(self):
        self.assertTrue(b.path_allowed("governance/gg_phase_guard.py"))
        self.assertTrue(b.path_allowed(".github/workflows/gg-phase-guard.yml"))

    def test_missing_required_check_denied(self):
        checks = copy.deepcopy(self.checks)
        checks["check_runs"].pop()
        checks["total_count"] = 2
        with self.assertRaisesRegex(b.Blocked, "CHECK_NOT_UNIQUE_OR_MISSING"):
            b.validate_snapshot(self.policy, self.auth, self.pr, self.branch, self.files, checks)

    def test_duplicate_status_check_denied(self):
        checks = copy.deepcopy(self.checks)
        checks["check_runs"].append(checks["check_runs"][0])
        checks["total_count"] = 4
        with self.assertRaisesRegex(b.Blocked, "CHECK_NOT_UNIQUE_OR_MISSING"):
            b.validate_snapshot(self.policy, self.auth, self.pr, self.branch, self.files, checks)

    def test_untrusted_status_app_denied(self):
        checks = copy.deepcopy(self.checks)
        checks["check_runs"][0]["app"]["slug"] = "an-untrusted-app"
        with self.assertRaisesRegex(b.Blocked, "CHECK_NOT_TRUSTED_PASS"):
            b.validate_snapshot(self.policy, self.auth, self.pr, self.branch, self.files, checks)

    def test_incomplete_status_pagination_denied(self):
        checks = copy.deepcopy(self.checks)
        checks["total_count"] = 101
        with self.assertRaisesRegex(b.Blocked, "CHECK_RUNS_INCOMPLETE"):
            b.validate_snapshot(self.policy, self.auth, self.pr, self.branch, self.files, checks)

    def test_signer_key_pinning_and_real_ed25519(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            secret = root / "TEST_ONLY_never_publish.key"
            public = root / "public.pem"
            payload = root / "payload.json"
            signature = root / "signature.bin"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(secret)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(secret), "-pubout", "-out", str(public)], check=True, capture_output=True)
            payload.write_bytes(b.canonical(self.auth))
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(secret), "-rawin",
                            "-in", str(payload), "-out", str(signature)], check=True, capture_output=True)
            sig = signature.read_bytes()
            actual_pin = hashlib.sha256(public.read_bytes()).hexdigest()
            self.assertTrue(b.verify_owner_signature(self.auth, sig, public, actual_pin))
            with self.assertRaisesRegex(b.Blocked, "REVIEWER_KEY_PIN_MISMATCH"):
                b.verify_owner_signature(self.auth, sig, public, "f" * 64)
            with self.assertRaisesRegex(b.Blocked, "REVIEWER_SIGNATURE_NOT_AUTHENTIC"):
                b.verify_owner_signature({**self.auth, "pr_number": 20}, sig, public, actual_pin)

    def test_mocked_positive_merge_does_not_call_github(self):
        class FakeAPI:
            calls = 0
            def snapshot(_, number, head):
                self.assertEqual((number, head), (19, self.head))
                return self.pr, self.branch, self.files, self.checks
            def merge(_, number, head):
                self.assertEqual((number, head), (19, self.head))
                _.calls += 1
                return {"merged": True, "sha": "f" * 40}
        api = FakeAPI()
        with patch.object(b, "verify_owner_signature", return_value=True), \
             patch.object(b, "checked_same_trusted_run", return_value=True):
            res = b.approve_and_merge(self.policy, self.auth, b"sig", "/test", api)
        self.assertEqual(res["status"], "MERGED")
        self.assertEqual(api.calls, 1)

    def test_mocked_denial_never_merges(self):
        class FakeAPI:
            calls = 0
            def snapshot(_, number, head):
                checks = copy.deepcopy(self.checks)
                checks["check_runs"][0]["conclusion"] = "failure"
                return self.pr, self.branch, self.files, checks
            def merge(_, number, head):
                _.calls += 1
        api = FakeAPI()
        with patch.object(b, "verify_owner_signature", return_value=True):
            with self.assertRaisesRegex(b.Blocked, "CHECK_NOT_TRUSTED_PASS"):
                b.approve_and_merge(self.policy, self.auth, b"sig", "/test", api)
        self.assertEqual(api.calls, 0)

    def test_missing_app_token_denied(self):
        with self.assertRaisesRegex(b.Blocked, "BROKER_GITHUB_APP_TOKEN_MISSING"):
            b.GitHubAPI("", TEST_REPO)


if __name__ == "__main__":
    unittest.main(verbosity=2)

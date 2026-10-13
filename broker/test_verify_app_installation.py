"""Fail-closed and mock-only tests for the read-only GitHub App scope proof."""
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

TARGET_NAME = "TripDep/SERVE-PER-FARTI-LAVORARE-"
ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location("app_scope", ROOT / "verify_app_installation.py")
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)
PIN = hashlib.sha256(TARGET_NAME.encode("utf-8")).hexdigest()

class GitHubAppScopeTests(unittest.TestCase):
    def test_exact_one_private_target_only(self):
        scope.verify_installation({"total_count": 1, "repositories": [{"private": True, "full_name": TARGET_NAME}]}, PIN)

    def test_reject_extra_repository_even_if_target_matches(self):
        with self.assertRaisesRegex(scope.Blocked, "INSTALLATION_SCOPE_NOT_SINGLE_REPO"):
            scope.verify_installation({"total_count": 2, "repositories": [
                {"private": True, "full_name": TARGET_NAME},
                {"private": True, "full_name": "TripDep/another"}]}, PIN)

    def test_reject_truncated_response(self):
        with self.assertRaisesRegex(scope.Blocked, "INSTALLATION_SCOPE_INCOMPLETE"):
            scope.verify_installation({"total_count": 1, "repositories": []}, PIN)

    def test_reject_wrong_repo(self):
        with self.assertRaisesRegex(scope.Blocked, "INSTALLATION_TARGET_MISMATCH"):
            scope.verify_installation({"total_count": 1, "repositories": [{"private": True, "full_name": "TripDep/wrong"}]}, PIN)

    def test_reject_public_repo(self):
        with self.assertRaisesRegex(scope.Blocked, "INSTALLATION_TARGET_NOT_PRIVATE"):
            scope.verify_installation({"total_count": 1, "repositories": [{"private": False, "full_name": TARGET_NAME}]}, PIN)

    def test_reject_non_json_data(self):
        with self.assertRaisesRegex(scope.Blocked, "INSTALLATION_RESPONSE_INVALID"):
            scope.verify_installation([], PIN)

    def test_policy_must_stay_disabled(self):
        with self.assertRaisesRegex(scope.Blocked, "BROKER_MUST_REMAIN_UNARMED_FOR_READONLY_PROOF"):
            scope.verify_policy({"schema": "gg-git-broker-v1", "enabled": True,
                                 "reviewer_public_key_sha256": None, "repository_sha256": PIN})

    def test_policy_fails_on_any_pinned_signature_key(self):
        with self.assertRaisesRegex(scope.Blocked, "BROKER_MUST_REMAIN_UNARMED_FOR_READONLY_PROOF"):
            scope.verify_policy({"schema": "gg-git-broker-v1", "enabled": False,
                                 "reviewer_public_key_sha256": "a"*64, "repository_sha256": PIN})

    def test_requires_public_main(self):
        with patch.dict(scope.os.environ, {"GITHUB_REPOSITORY":"TripDep/controller","GITHUB_REF":"refs/heads/feature"}):
            with self.assertRaisesRegex(scope.Blocked, "PROTECTED_MAIN_REQUIRED"):
                scope.verify_environment()

    def test_missing_app_token_blocks_before_network(self):
        with patch.dict(scope.os.environ, {"GITHUB_REPOSITORY":"TripDep/controller",
                                           "GITHUB_REF":"refs/heads/main",
                                           "BROKER_APP_TOKEN":""}):
            with self.assertRaisesRegex(scope.Blocked, "PROTECTED_APP_TOKEN_NOT_CONFIGURED"):
                scope.verify_readonly_access()

if __name__ == "__main__":
    unittest.main(verbosity=2)

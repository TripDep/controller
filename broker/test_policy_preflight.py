"""Unprivileged, offline, fail-closed staging assertions.

These tests DO NOT implement a GitHub merge broker, issue tokens or claim
that an independent reviewer has approved anything.
"""
import json
from pathlib import Path
import unittest

POLICY = Path(__file__).with_name("broker_policy.json")


class BrokerPolicyStagingTests(unittest.TestCase):
    def test_schema_and_exact_requirements(self):
        p = json.loads(POLICY.read_text(encoding="utf-8"))
        self.assertEqual(p.get("schema"), "gg-git-broker-v1")
        self.assertEqual(p.get("base_branch"), "main")
        self.assertEqual(p.get("required_checks"), ["guard-tests", "phase-guard", "public-controller"])

    def test_broker_not_armed_by_default(self):
        p = json.loads(POLICY.read_text(encoding="utf-8"))
        self.assertIs(p.get("enabled"), False)
        self.assertIsNone(p.get("reviewer_public_key_sha256"))

    def test_only_hashes_and_metadata_public(self):
        p = json.loads(POLICY.read_text(encoding="utf-8"))
        self.assertRegex(p["master_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(p["public_controller_sha"], r"^[0-9a-f]{40}$")
        self.assertRegex(p["repository_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(set(p), {"schema", "enabled", "repository_sha256", "base_branch", "master_sha256", "public_controller_sha", "reviewer_public_key_sha256", "required_checks"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

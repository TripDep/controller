#!/usr/bin/env python3
"""Synthetic, public-only unit tests. No user assets or private data."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import controller as guard


class SupervisorTests(unittest.TestCase):
    def test_asset_paths_fail_closed(self):
        for name in ("assets/a.md", "models/a.glb", "renders/a.png",
                     "governance/QA/render.JPG", "backup/model.BLEND",
                     "delivery.zip", "texture/file.YDR"):
            with self.subTest(name=name), self.assertRaisesRegex(guard.Blocked, "ASSET_CHAT_ONLY"):
                guard.validate_repository_path(name)

    def test_procedure_paths_allowed(self):
        for name in (".github/workflows/guard.yml", "governance/README.md",
                     "governance/test_gg_phase_guard.py"):
            guard.validate_repository_path(name)

    def test_path_traversal_and_symlink_denied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "x").write_text("synthetic")
            (root / "lnk").symlink_to(root / "x")
            with self.assertRaisesRegex(guard.Blocked, "UNSAFE_PATH"):
                guard.safe_private_file(root, "../outside")
            with self.assertRaisesRegex(guard.Blocked, "SYMLINK_FORBIDDEN"):
                guard.safe_private_file(root, "lnk")

    def test_sha256_uses_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "x"
            path.write_bytes(b"synthetic")
            self.assertEqual(guard.file_sha256(path), hashlib.sha256(b"synthetic").hexdigest())

    def test_registry_count_and_duplicate(self):
        sample = {"families": [{"id":"base", "required":["Q","MG0","A"]},
                               {"id":"other", "required":["P0","P1"]}]}
        self.assertEqual(guard.counted_rules(sample), 5)
        sample["families"][1]["required"].append("Q")
        with self.assertRaisesRegex(guard.Blocked, "DUPLICATE_RULE_ID"):
            guard.counted_rules(sample)

    def test_missing_mg0_denied(self):
        with self.assertRaisesRegex(guard.Blocked, "CRITICAL_RULE_MISSING"):
            guard.counted_rules({"families":[{"id":"base","required":["Q"]}]})

    def test_behavior_id_duplicates_denied(self):
        self.assertEqual(guard.behavior_ids("001. a\n002. b\n"), {"001","002"})
        with self.assertRaisesRegex(guard.Blocked, "DUPLICATE_BEHAVIOR_RULE"):
            guard.behavior_ids("001. a\n001. b\n")

    def test_bad_base_blocks_before_git(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(guard.Blocked, "GIT_BASE_HEAD_UNVERIFIED"):
                guard.verify_paths(Path(temp), "invalid", "wrong")

    def test_sha_pinned_public_step_variants(self):
        sha = "a" * 40
        self.assertTrue(guard.pinned_public_action("      - uses: TripDep/controller@" + sha))
        self.assertTrue(guard.pinned_public_action("      - name: Public gate\n        uses: TripDep/controller@" + sha))
        self.assertFalse(guard.pinned_public_action("      - uses: TripDep/controller@main"))
        self.assertFalse(guard.pinned_public_action("      - uses: TripDep/controller@v1"))

    def test_policy_minimums_and_hash(self):
        policy = json.loads(guard.POLICY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(policy["non_aaa_id_count"], 551)
        self.assertEqual(policy["aaa_count"], 200)
        self.assertEqual(policy["behavior_110_count"], 110)
        self.assertRegex(policy["canonical_master_sha256"], r"^[0-9a-f]{64}$")

    def test_private_gate_failure_blocks(self):
        class SimulatedResult:
            returncode = 1
        with patch.object(guard.subprocess, "run", return_value=SimulatedResult()):
            with self.assertRaisesRegex(guard.Blocked, "PRIVATE_PHASE_GUARD_FAILED"):
                guard.invoke_private_guard(Path("."), "a"*40, "b"*40)


if __name__ == "__main__":
    unittest.main(verbosity=2)

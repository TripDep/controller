"""R150 regression tests: 67 original-source family receipts and fail-closed semantics.

All fixtures are synthetic. A passing test never proves actual asset quality,
owner acceptance, production MG0, or native FiveM behavior.
"""
import copy
import json
import unittest
from collections import defaultdict
from pathlib import Path

from c07_last67_original_family_witnesses import (
    inspect, remaining, CONTRACT, EXPECTED_FAMILIES, Last67Blocked)
from c07_positive200_evidence import R122_FROZEN_IDS
from c07_positive_native_process import NativeEvidenceBlocked
from test_c07_q200_original_witnesses import Q200Witness
from test_c07_positive_native_process import sha


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")


class R150Last67(Q200Witness):
    def setUp(self):
        super().setUp()
        f = self.f

        # Preserve the actual immutable first-200 ID list; never derive a
        # replacement cohort or pretend missing rules are certified.
        for rid in R122_FROZEN_IDS:
            if rid not in f.inv["rules"]:
                clause = "Original fixed-cohort synthetic placeholder " + rid
                f.inv["rules"][rid] = {
                    "family": "FROZEN", "source": "master",
                    "source_sha256":f.work["master_sha256"],
                    "requirement":clause,
                    "requirement_sha256":sha(clause.encode("utf-8"))
                }

        for num in range(1, 201):
            rid = "AAA-200-" + chr(65 + (num-1)//10) + "-" + str(num).zfill(3)
            if rid not in f.inv["rules"]:
                clause = "Original catalogue synthetic placeholder " + rid
                f.inv["rules"][rid] = {
                    "family": "AAA-200", "source": "master",
                    "source_sha256":f.work["master_sha256"],
                    "requirement":clause,
                    "requirement_sha256":sha(clause.encode("utf-8"))
                }

        for num in range(1, 31):
            rid = "G0-" + str(num).zfill(2)
            if rid not in f.inv["rules"]:
                clause = "Original G0 synthetic placeholder " + rid
                f.inv["rules"][rid] = {
                    "family": "G0_CONTROLS", "source": "master",
                    "source_sha256":f.work["master_sha256"],
                    "requirement":clause,
                    "requirement_sha256":sha(clause.encode("utf-8"))
                }

        # Reopen original auxiliary files as physically recorded Controller
        # artifacts. Mere receipt presence is not certified full semantics.
        sources = ("master", "developer_rules", "behavior_rules",
                   "error_registry", "professional_phases", "operating_contract")
        for source in sources[1:]:
            raw = ("ORIGINAL CANONICAL SOURCE: " + source).encode("utf-8")
            role = "ORIGINAL_CANONICAL_" + source.upper()
            f.add_item(role, source + ".txt", raw)
            f.inv["source_digests"][source] = sha(raw)

        members = defaultdict(list)
        family_order = list(EXPECTED_FAMILIES)
        for family_index, (family, count) in enumerate(EXPECTED_FAMILIES.items()):
            for num in range(1, count+1):
                rid = "R150-" + family + "-" + str(num).zfill(2)
                source = sources[(family_index+num) % len(sources)]
                clause = "Exact original family source clause for " + rid
                f.inv["rules"][rid] = {
                    "family":family, "source":source,
                    "source_sha256":f.inv["source_digests"][source],
                    "requirement":clause,
                    "requirement_sha256":sha(clause.encode("utf-8")),
                    "profile":"ARCHITECTURE" if family=="ASSET_PROFILE_READINESS" else None
                }
                members[family].append(rid)
            f.inv["families"][family] = list(members[family])

        # Each family witness is tied to original registered bytes and each
        # individual canonical clause + source SHA.
        slots = {}
        for family, ids in members.items():
            rows = {}
            for rid in ids:
                item = f.inv["rules"][rid]
                rows[rid] = {
                    "original_requirement_sha256":item["requirement_sha256"],
                    "original_source_sha256":item["source_sha256"],
                    "source_rule_id":rid,
                    "evidence_class":family,
                    "claimed_result":"OBSERVATION_ONLY"
                }
            role = "C07_FAMILY_" + family
            raw = encode({"source_rule_witnesses":rows})
            f.add_item(role, "r150_" + family.lower() + ".json", raw)
            for rid in ids:
                item = f.inv["rules"][rid]
                slots[rid] = {
                    "requirement_sha256":item["requirement_sha256"],
                    "source_sha256":item["source_sha256"],
                    "witness_role":role,
                    "witness_sha256":sha(raw),
                    "observed_origin":"ORIGINAL_REGISTERED_BYTES",
                    "claim_status":"OBSERVATION_ONLY"
                }
        f.plan["last_67_source_evidence_contract"] = {
            "schema":CONTRACT,"rules":slots}
        f.rebuild()
        self.r150_ids = tuple(sorted(slots))
        self.assertEqual(len(f.inv["rules"]), 763)
        self.assertEqual(len(self.r150_ids), 67)

    def review67(self):
        f = self.f
        return inspect(f.inv, f.plan, f.controller, f.asset, f.step,
                       f.work, source_loader=lambda p: Path(p).read_bytes())

    def test_exact_67_source_members_and_no_false_full_semantics(self):
        result = self.review67()
        self.assertEqual(result["source_rule_count"], 67)
        self.assertEqual(result["source_families"], 13)
        self.assertEqual(set(result["rules"]), set(self.r150_ids))
        self.assertEqual(result["original_per_rule_witnesses_verified"],67)
        self.assertEqual(result["canonical_source_files_reopened"],67)
        self.assertEqual(result["full_semantic_passes"],0)
        self.assertEqual(result["individual_mg0_passes"],0)
        self.assertFalse(result["advancement_authorized"])
        for rid in self.r150_ids:
            with self.subTest(rid=rid):
                row=result["rules"][rid]
                self.assertTrue(row["original_current_attempt_receipt_verified"])
                self.assertEqual(row["semantic_verdict"],"UNKNOWN")
                self.assertEqual(row["individual_mg0"],"UNKNOWN")
                self.assertEqual(row["owner_approval"],"UNKNOWN")
                self.assertFalse(row["advancement_authorized"])

    def test_unknown_context_is_not_silently_not_due_or_pass(self):
        result=self.review67()
        for family in ("ASSET_PROFILE_READINESS","HISTORICAL_ASSET_GATES"):
            for rid in self.f.inv["families"][family]:
                with self.subTest(rule=rid):
                    row=result["rules"][rid]
                    self.assertEqual(row["current_asset_applicability"],"CONTEXT_UNKNOWN")
                    self.assertEqual(row["semantic_verdict"],"UNKNOWN")
                    self.assertEqual(row["individual_mg0"],"UNKNOWN")
        self.f.plan["profiles"]=["ARCHITECTURE"]
        self.f.plan["asset_build_context_verified"]=True
        self.f.rebuild()
        result=self.review67()
        for family in ("ASSET_PROFILE_READINESS","HISTORICAL_ASSET_GATES"):
            for rid in self.f.inv["families"][family]:
                self.assertEqual(result["rules"][rid]["current_asset_applicability"],"DUE")
                self.assertEqual(result["rules"][rid]["individual_mg0"],"UNKNOWN")

    def test_all_67_original_clause_tamper_blocks(self):
        for rid in self.r150_ids:
            old=self.f.inv["rules"][rid]["requirement"]
            self.f.inv["rules"][rid]["requirement"]="fake automatic PASS"
            with self.subTest(rid=rid):
                with self.assertRaisesRegex(Last67Blocked,
                                            "R150_UNVERIFIED_ORIGINAL_SOURCE_CLAUSE"):
                    self.review67()
            self.f.inv["rules"][rid]["requirement"]=old

    def test_all_67_original_source_sha_tamper_blocks(self):
        for rid in self.r150_ids:
            old=self.f.inv["rules"][rid]["source_sha256"]
            self.f.inv["rules"][rid]["source_sha256"]="f"*64
            with self.subTest(rid=rid):
                with self.assertRaisesRegex(Last67Blocked,
                                            "R150_UNVERIFIED_ORIGINAL_SOURCE_CLAUSE"):
                    self.review67()
            self.f.inv["rules"][rid]["source_sha256"]=old

    def test_fake_yes_never_becomes_original_receipt_or_mg0(self):
        rid=self.r150_ids[0]
        self.f.plan["last_67_source_evidence_contract"]["rules"][rid]["claim_status"]="YES"
        self.f.rebuild()
        result=self.review67()
        self.assertFalse(result["rules"][rid]["original_current_attempt_receipt_verified"])
        self.assertEqual(result["individual_mg0_passes"],0)
        self.assertEqual(result["rules"][rid]["semantic_verdict"],"UNKNOWN")

    def test_missing_original_witness_does_not_grant_pass(self):
        rid=self.r150_ids[0]
        del self.f.plan["last_67_source_evidence_contract"]["rules"][rid]
        self.f.rebuild()
        result=self.review67()
        self.assertFalse(result["rules"][rid]["original_current_attempt_receipt_verified"])
        self.assertEqual(result["rules"][rid]["individual_mg0"],"UNKNOWN")

    def test_unregistered_rule_in_contract_rejected(self):
        self.f.plan["last_67_source_evidence_contract"]["rules"]["Q-001"]={}
        self.f.rebuild()
        with self.assertRaisesRegex(Last67Blocked,"R150_UNRECOGNIZED_FAMILY_RULE_ID"):
            self.review67()

    def test_auxiliary_source_bytes_tamper_fails_closed(self):
        (self.f.root/"developer_rules.txt").write_bytes(b"modified original source")
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "REGISTERED_ARTIFACT_BYTES_CHANGED"):
            self.review67()

    def test_cross_attempt_replay_fails_closed(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work["attempt_id"]="e"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "EXACT_RESERVED_WORK"):
            self.review67()

    def test_incomplete_inventory_cannot_omit_a_canonical_family(self):
        del self.f.inv["rules"][self.r150_ids[0]]
        with self.assertRaisesRegex(Last67Blocked,
                                    "R150_CANONICAL_INVENTORY_763_REQUIRED"):
            remaining(self.f.inv)


if __name__=="__main__":
    unittest.main()

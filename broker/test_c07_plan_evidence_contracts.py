"""C07 production-plan contract tests: original source and adversarial cases.

These are contract tests only. They do not certify an asset, rule, or MG0.
"""
import copy
import unittest

from c07_plan_evidence_contracts import (
    validate, EvidenceContractBlocked, OPTIONAL_EVIDENCE_CONTEXT,
)
from c07_native_output_oracle import CONTRACT as GEOMETRY_CONTRACT
from c07_a10_c10_original_evidence import CONTRACT_SCHEMA, SOURCE_ROLES
from c07_q200_original_witnesses import (
    CONTRACT as Q200_CONTRACT, IDS, domain_for, file_type_for,
)

def fixture():
    inv = {"rules": {
        rid: {"requirement_sha256": ("%064x" % n)}
        for n, rid in enumerate(IDS, 1)
    }}
    inv["rules"]["AAA-200-R-171"] = {"requirement_sha256": "f" * 64}
    plan = {"operation": {"category": "GENERATION"}}
    return inv, plan

def output_spec():
    return {
        "schema": GEOMETRY_CONTRACT,
        "bbox_min": [0, 0, 0], "bbox_max": [10, 20, 5],
        "bbox_tolerance_m": 0.01, "min_meshes": 1,
        "min_triangles": 100, "max_triangles": 100000,
        "min_triangle_delta_from_baseline": 1,
    }

def q200(inv):
    return {"schema": Q200_CONTRACT, "rules": {
        rid: {
            "question_sha256": inv["rules"][rid]["requirement_sha256"],
            "source_role": file_type_for(domain_for(n)),
            "source_sha256": "a" * 64,
            "measured_fingerprint": "b" * 64,
            "claim_status": "OBSERVATION_ONLY",
        }
        for n, rid in enumerate(IDS, 1)
    }}

class Tests(unittest.TestCase):
    def setUp(self):
        self.inv, self.plan = fixture()

    def test_twelve_existing_evidence_fields_accepted_as_inputs_not_passes(self):
        for name in (
            "p1_evidence_contract", "p2_evidence_contract",
            "p345_evidence_contract", "p678_evidence_contract",
        ):
            self.plan[name] = {"original_artifact_sha256": {
                "NATIVE_EXPORT": "a" * 64,
                "SOURCE_EDITABLE": "b" * 64,
            }}
        self.plan["reference_evidence_contract"] = {
            "schema": CONTRACT_SCHEMA,
            "artifact_sha256": {SOURCE_ROLES[0]: "c" * 64},
        }
        self.plan["output_expectation"] = output_spec()
        self.plan["pre_d_control"] = {
            "piece_id": "TEST-001", "objective": "Original measurable goal",
            "phase": "C", "rule_ids": ["AAA-200-R-171"],
            "criteria": ["No collision at tested contact"],
        }
        self.plan["question_200_original_witnesses"] = q200(self.inv)
        self.plan["acceptance_criteria"] = [
            {"criterion_id": "GEOMETRY_BBOX", "oracle": "NATIVE_GLTF",
             "expected": 5},
        ]
        self.plan["mandatory_issue_ids"] = ["ISSUE-001"]
        self.plan["timebox_seconds"] = 3600
        self.plan["visual_hierarchy_contract"] = {
            "focal": ["Main pavilion", "South approach"],
        }
        result = validate(self.plan, self.inv)
        self.assertEqual(set(result["pre_enrolled_contract_keys"]),
                         OPTIONAL_EVIDENCE_CONTEXT)
        self.assertTrue(result["no_rule_or_mg0_pass_issued"])
        self.assertTrue(result["original_evidence_must_be_reread"])

    def test_missing_optional_fields_never_create_default_yes(self):
        result = validate(self.plan, self.inv)
        self.assertEqual(result["pre_enrolled_contract_keys"], [])
        self.assertNotIn("rule_passes", result)

    def test_invalid_pinned_original_bytes_rejected_for_each_phase(self):
        for key in (
            "p1_evidence_contract", "p2_evidence_contract",
            "p345_evidence_contract", "p678_evidence_contract",
        ):
            with self.subTest(contract=key):
                self.plan[key] = {
                    "original_artifact_sha256": {"NATIVE_EXPORT": "0" * 64}
                }
                validate(self.plan, self.inv)
                self.plan[key]["original_artifact_sha256"]["NATIVE_EXPORT"] = "YES"
                with self.assertRaisesRegex(EvidenceContractBlocked,
                                            "ARTIFACT_PIN_SCHEMA"):
                    validate(self.plan, self.inv)
                del self.plan[key]

    def test_original_reference_role_cannot_be_swapped(self):
        self.plan["reference_evidence_contract"] = {
            "schema": CONTRACT_SCHEMA,
            "artifact_sha256": {"FAKE_OWNER_APPROVAL": "a" * 64},
        }
        with self.assertRaisesRegex(EvidenceContractBlocked,
                                    "ARTIFACT_PIN_SCHEMA"):
            validate(self.plan, self.inv)

    def test_geometry_oracle_cannot_be_bypassed_by_success_exit(self):
        self.plan["output_expectation"] = output_spec()
        self.plan["output_expectation"]["bbox_max"][2] = float("nan")
        with self.assertRaisesRegex(EvidenceContractBlocked,
                                    "GEOMETRY_EXPECTATION_INVALID"):
            validate(self.plan, self.inv)
        self.plan["output_expectation"] = output_spec()
        self.plan["operation"]["category"] = "STATUS"
        with self.assertRaisesRegex(EvidenceContractBlocked,
                                    "NOT_AN_OUTPUT_OPERATION"):
            validate(self.plan, self.inv)

    def test_200_questions_require_each_literal_sha_and_original_role(self):
        self.plan["question_200_original_witnesses"] = q200(self.inv)
        validate(self.plan, self.inv)
        self.plan["question_200_original_witnesses"]["rules"]["Q-091"][
            "question_sha256"] = "0" * 64
        with self.assertRaisesRegex(EvidenceContractBlocked,
                                    "Q200_SOURCE_SPECIFIC:Q-091"):
            validate(self.plan, self.inv)
        self.plan["question_200_original_witnesses"] = q200(self.inv)
        self.plan["question_200_original_witnesses"]["rules"]["Q-200"][
            "claim_status"] = "YES"
        with self.assertRaisesRegex(EvidenceContractBlocked,
                                    "Q200_SOURCE_SPECIFIC:Q-200"):
            validate(self.plan, self.inv)
        self.plan["question_200_original_witnesses"] = q200(self.inv)
        del self.plan["question_200_original_witnesses"]["rules"]["Q-180"]
        # The missing original is still UNKNOWN in the native Q200 reader,
        # rather than being forged merely to satisfy a batch count.
        self.assertTrue(validate(self.plan, self.inv)[
            "original_evidence_must_be_reread"])
        self.plan["question_200_original_witnesses"]["rules"]["Q-201"] = {}
        with self.assertRaisesRegex(EvidenceContractBlocked,
                                    "Q200_CANONICAL_WITNESSES_ONLY"):
            validate(self.plan, self.inv)

    def test_pre_d_mother_control_requires_actual_known_rule(self):
        self.plan["pre_d_control"] = {
            "piece_id": "TEST", "objective": "Known source goal",
            "phase": "C", "rule_ids": ["NON_CANONICAL_RULE"],
        }
        with self.assertRaisesRegex(EvidenceContractBlocked,
                                    "MOTHER_CONTROL_INVALID"):
            validate(self.plan, self.inv)

    def test_duplicate_issue_and_oracle_ids_are_rejected(self):
        self.plan["mandatory_issue_ids"] = ["A", "A"]
        with self.assertRaisesRegex(EvidenceContractBlocked,
                                    "MANDATORY_ISSUE_IDS"):
            validate(self.plan, self.inv)
        del self.plan["mandatory_issue_ids"]
        self.plan["acceptance_criteria"] = [
            {"criterion_id": "SAME", "oracle": "GLTF", "expected": 1},
            {"criterion_id": "SAME", "oracle": "GLTF", "expected": 2},
        ]
        with self.assertRaisesRegex(EvidenceContractBlocked,
                                    "EXEC_ACCEPTANCE_ORACLES"):
            validate(self.plan, self.inv)

    def test_source_contract_cannot_be_promoted_to_owner_or_mg0_pass(self):
        self.plan["p1_evidence_contract"] = {
            "original_artifact_sha256": {"NATIVE_EXPORT": "a" * 64},
            "mg0": "PASS",
        }
        with self.assertRaisesRegex(EvidenceContractBlocked,
                                    "CONTRACT_SCHEMA"):
            validate(self.plan, self.inv)
        self.plan["p1_evidence_contract"] = {
            "original_artifact_sha256": {"NATIVE_EXPORT": "a" * 64},
        }
        result = validate(self.plan, self.inv)
        self.assertNotIn("mg0_passes", result)

if __name__ == "__main__":
    unittest.main()

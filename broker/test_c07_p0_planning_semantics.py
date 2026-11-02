"""Real original-file P0 planning oracles: positive and adversarial cases."""
import copy
import json
import unittest
from pathlib import Path

import test_c07_positive_native_process as fixture
from r173_rule_semantics import RULES
from c07_p0_planning_semantics import (
    IDS, ROLE_BY_NUMBER, inspect, OriginalPlanningBlocked,
)
from c07_positive_native_process import NativeEvidenceBlocked

class Tests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.Tests("test_genuine_positive_semantics_for_both_exact_literal_rules")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.plan["phase"] = "P0"
        self.f.work["phase"] = "P0"
        for rid in IDS:
            n, text = RULES[rid]
            self.f.inv["rules"][rid] = {
                "family": "AAA-200", "catalog_number": n,
                "catalog_section": "B", "catalog_phase": "P0",
                "requirement": text,
                "requirement_sha256": fixture.sha(text.encode()),
                "source_sha256": "c"*64,
            }
        dep = "d"*64
        self.docs = {
            11: {"asset": self.f.asset, "purpose": "Game environment",
                 "intended_use": "GTA V FiveM RP",
                 "deliverables": ["source.blend", "export.glb"]},
            13: {"engine": "GTA_V_FIVEM", "export_format": "GLB",
                 "meters_per_unit": 1.0, "world_origin_xyz": [0, 0, 0]},
            14: {"candidates": [{
                "name": "approved old bridge", "decision": "REUSE",
                "dependency_id": dep,
                "sha256": self.f.work["work_dependencies"][dep]}]},
            15: {"approved": ["old_bridge"], "mutable": ["new_path"],
                 "approved_dependencies": {"old_bridge": dep}},
            16: {"nodes": [dep], "edges": []},
            17: {"deliverables": [
                {"path": "scene.blend", "kind": "SOURCE"},
                {"path": "scene.glb", "kind": "NATIVE_EXPORT"}]},
            18: {"risks": [{"id": "RISK-001", "severity": "HIGH",
                           "trigger": "Slope exceeds target",
                           "mitigation": "Independent measured slope QA"}]},
            19: {"tasks": [
                {"task": "Geometry", "measurement_key": "bridge_count",
                 "hours_per_unit": 1.0, "estimated_hours": 2.0,
                 "evidence_basis": "Original measured bridge count"},
                {"task": "Collision", "measurement_key": "collision_surfaces",
                 "hours_per_unit": 1.0, "estimated_hours": 3.0,
                 "evidence_basis": "Original measured collision surfaces"}],
                 "total_hours": 5.0},
            20: {"criteria": [
                {"id": "TRIANGLE_LIMIT", "metric": "triangles",
                 "operator": "<=", "threshold": 10000,
                 "measurement_source": "Native GLB accessor parser",
                 "measurement_source_sha256":
                     self.f.work["work_dependencies"][dep]}]},
        }
        self.measurements = {"measurements": {
            "bridge_count": 2, "collision_surfaces": 3}}
        self.sync()

    def sync(self):
        self.f.add_item("P0_MEASUREMENTS", "p0_measurements.json",
                        json.dumps(self.measurements, sort_keys=True).encode())
        for n, doc in self.docs.items():
            raw = json.dumps(doc, sort_keys=True).encode()
            self.f.add_item(ROLE_BY_NUMBER[n],
                            ROLE_BY_NUMBER[n].lower() + ".json", raw)
        self.f.rebuild()

    def review(self):
        return inspect(self.f.inv, self.f.plan, self.f.controller,
                       self.f.asset, self.f.step, self.f.work,
                       source_loader=lambda p: Path(p).read_bytes())

    def test_nine_distinct_literal_semantics_from_original_files(self):
        result = self.review()
        self.assertEqual(result["source_rule_count"], 9)
        self.assertEqual(set(result["rules"]), set(IDS))
        self.assertEqual(result["machine_positive_obligations"], 9)
        self.assertEqual(result["original_dependency_bytes_verified"], 1)
        self.assertEqual(result["full_rule_semantic_passes"], 0)
        self.assertEqual(result["individual_mg0_passes"], 0)
        self.assertFalse(result["advancement_authorized"])
        self.assertTrue(all(row["machine_scope"] == "OBSERVED_SCOPE_PASS" and
                            row["individual_mg0"] == "UNKNOWN"
                            for row in result["rules"].values()))

    def test_each_literal_rule_has_independent_negative_case(self):
        mutations = {
            11: ("asset", "OTHER_ASSET"),
            13: ("meters_per_unit", 0),
            14: ("candidates", [{"name": "fake", "decision": "REUSE",
                                  "dependency_id": "f"*64,
                                  "sha256": "0"*64}]),
            15: ("mutable", ["old_bridge"]),
            16: ("edges", [["d"*64, "d"*64]]),
            17: ("deliverables", [{"path": "notes.md", "kind": "STUDY"}]),
            18: ("risks", [{"id": "RISK-001", "severity": "UNKNOWN",
                           "trigger": "bad", "mitigation": "none"}]),
            19: ("total_hours", 500),
            20: ("criteria", [{"id": "NO_ORACLE", "metric": "triangles",
                               "operator": "<=", "threshold": 100,
                               "measurement_source": ""}]),
        }
        for n, (key, bad) in mutations.items():
            with self.subTest(rule=n):
                old = copy.deepcopy(self.docs[n][key])
                self.docs[n][key] = bad
                self.sync()
                result = self.review()
                rid = "AAA-200-B-%03d" % n
                self.assertEqual(result["rules"][rid]["machine_scope"],
                                 "UNKNOWN")
                self.assertEqual(result["rules"][rid]["full_rule_semantics"],
                                 "UNKNOWN")
                self.docs[n][key] = old
                self.sync()

    def test_B20_measurement_source_must_match_reopened_dependency(self):
        rid = "AAA-200-B-020"
        self.docs[20]["criteria"][0]["measurement_source_sha256"] = "f"*64
        self.sync()
        result = self.review()
        self.assertEqual(result["rules"][rid]["machine_scope"], "UNKNOWN")
        self.assertFalse(result["rules"][rid]["original_machine_checks"][
            "every_criterion_names_independent_measurement_source"])

    def test_B16_deep_dag_is_iterative_and_cycles_still_rejected(self):
        from c07_p0_planning_semantics import _no_cycle
        nodes = ["N%04d" % n for n in range(2000)]
        edges = [[nodes[i], nodes[i+1]] for i in range(len(nodes)-1)]
        self.assertTrue(_no_cycle(nodes, edges))
        self.assertFalse(_no_cycle(nodes, edges + [[nodes[-1], nodes[0]]]))
        self.assertFalse(_no_cycle(nodes, edges + [[nodes[0], "UNKNOWN"]]))
        self.assertFalse(_no_cycle(nodes + [{"malformed": True}], edges))
        self.assertFalse(_no_cycle(nodes, edges + [["bad"]]))
        self.assertFalse(_no_cycle(nodes, edges * 60))

    def test_missing_original_documents_do_not_create_positive_passes(self):
        for n in self.docs:
            self.f.items.pop(ROLE_BY_NUMBER[n])
        self.f.items.pop("P0_MEASUREMENTS")
        self.f.rebuild()
        result = self.review()
        self.assertEqual(result["machine_positive_obligations"], 0)
        self.assertEqual(result["original_registered_planning_documents"], [])

    def test_estimate_without_original_measured_quantities_stays_unknown(self):
        self.f.items.pop("P0_MEASUREMENTS")
        self.f.rebuild()
        result = self.review()
        self.assertEqual(result["rules"]["AAA-200-B-019"]["machine_scope"],
                         "UNKNOWN")
        self.assertEqual(result["full_rule_semantic_passes"], 0)

    def test_json_duplicate_key_is_not_silent_override(self):
        self.f.add_item("P0_PROJECT_BRIEF", "p0_project_brief.json",
                        b'{"asset":"TEST","asset":"FORGED"}')
        self.f.rebuild()
        with self.assertRaisesRegex(OriginalPlanningBlocked,
                                    "DUPLICATE_JSON_KEY"):
            self.review()

    def test_dependency_original_bytes_changed_is_rejected(self):
        (self.f.root / "dependency.txt").write_bytes(b"changed")
        with self.assertRaisesRegex(OriginalPlanningBlocked,
                                    "DEPENDENCY_BYTES_CHANGED"):
            self.review()

    def test_original_document_tamper_is_rejected(self):
        (self.f.root / "p0_project_brief.json").write_bytes(b"tampered")
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "ARTIFACT_BYTES_CHANGED"):
            self.review()

    def test_other_attempt_cannot_replay_original_planning_evidence(self):
        self.f.work["attempt_id"] = "f"*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    "EXACT_RESERVED_WORK"):
            self.review()

    def test_literal_source_mutation_rejected(self):
        self.f.inv["rules"][IDS[0]]["requirement"] = "Different objective"
        with self.assertRaisesRegex(OriginalPlanningBlocked,
                                    "ORIGINAL_LITERAL_CHANGED"):
            self.review()

if __name__ == "__main__":
    unittest.main()

"""C07 authorized optional outcome contracts and real native measurements.

Positive evidence must come from the existing owner-authorized STATUS
plan, not a producer's unapproved acceptance criteria or a PASS label.
"""
import hashlib
import unittest
from unittest.mock import Mock
from controlled_judgment import validate_outcome_contract,PLAN_KEYS
from supervisor_judgment import Blocked
from c07_exec25_true_measurements import (
    measured_original_glb, measured_timebox)
from c07_exec25_positive_outcomes import all_transitive_dependencies
from glb_machine_qa import audit_bytes
from test_glb_machine_qa import synthetic_glb

class AuthorizedOutcomeContractTests(unittest.TestCase):
    def setUp(self):
        self.dep="a"*64
        self.criteria=[{"name":"degenerate_triangles","operator":"eq","expected":0},
                       {"name":"triangles_examined","operator":"gte","expected":1}]
        self.plan={"dependency_files":{self.dep:"geometry.glb"},
                   "outcome_contract":{
                       "dependency_graph":{self.dep:[]},
                       "acceptance_criteria":self.criteria,
                       "timebox_seconds":180,
                   }}

    def test_canonical_plan_keeps_previous_required_keys(self):
        self.assertNotIn("outcome_contract",PLAN_KEYS)

    def test_authorized_optional_original_outcome_contract_is_valid(self):
        self.assertIsNone(validate_outcome_contract(self.plan))

    def test_original_contract_numeric_metrics_can_be_independently_recomputed(self):
        validate_outcome_contract(self.plan)
        raw=synthetic_glb()
        self.assertTrue(measured_original_glb(self.plan,audit_bytes(raw)))

    def test_original_timebox_uses_approved_nested_threshold(self):
        validate_outcome_contract(self.plan)
        rows=[{"event":"RUN_STARTED","timestamp_utc":"2026-11-02T10:00:00Z"},
              {"event":"RUN_FINISHED","timestamp_utc":"2026-11-02T10:02:10Z"}]
        self.assertTrue(measured_timebox(self.plan,rows))
        self.plan["outcome_contract"]["timebox_seconds"]=60
        self.assertFalse(measured_timebox(self.plan,rows))

    def test_dependency_graph_is_usable_and_rechecks_actual_registered_bytes(self):
        from pathlib import Path
        import tempfile
        data=b"actual original dependency"
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/"geometry.glb"
            path.write_bytes(data)
            c=Mock();c.root=Path(root)
            work={"work_dependencies":{self.dep:hashlib.sha256(data).hexdigest()}}
            self.assertTrue(all_transitive_dependencies(
                self.plan,work,c,lambda f:Path(f).read_bytes()))
            path.write_bytes(b"changed")
            self.assertFalse(all_transitive_dependencies(
                self.plan,work,c,lambda f:Path(f).read_bytes()))

    def test_unknown_schema_key_blocks_not_silently_ignored(self):
        self.plan["outcome_contract"]["owner_approved"]=True
        with self.assertRaises(Blocked):
            validate_outcome_contract(self.plan)

    def test_bad_numeric_threshold_blocks_during_enrollment(self):
        self.plan["outcome_contract"]["acceptance_criteria"]=[{
            "name":"triangles_examined","operator":"gte","expected":"PASS"}]
        with self.assertRaises(Blocked):
            validate_outcome_contract(self.plan)

    def test_cyclic_dependency_graph_blocks_before_action(self):
        b="b"*64
        self.plan["dependency_files"][b]="other.glb"
        self.plan["outcome_contract"]["dependency_graph"]={
            self.dep:[b],b:[self.dep]}
        with self.assertRaisesRegex(Blocked,"DEPENDENCY_CYCLE"):
            validate_outcome_contract(self.plan)

    def test_new_outcome_contract_is_optional_for_existing_plans(self):
        self.assertIsNone(validate_outcome_contract({
            "dependency_files":{self.dep:"geometry.glb"}}))

    def test_existing_controller_enrollment_revalidates_contract(self):
        from pathlib import Path
        text=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("OPTIONAL_OUTCOME_CONTRACT",text)
        self.assertIn("validate_outcome_contract(plan)",text)
        self.assertIn("validate_outcome_contract(row['plan'])",text)
        self.assertIn("PLAN_KEYS <= set(plan)",text)

if __name__=="__main__":
    unittest.main()

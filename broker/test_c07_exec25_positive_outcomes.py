"""25 EXEC positive semantics: original-byte dependency closure and source oracles.

These tests are synthetic and do NOT certify any original work, asset or MG0.
"""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch,Mock
from c07_exec25_native_observation import IDS
from c07_exec25_positive_outcomes import (
    all_transitive_dependencies,inspect,SCHEMA,NativeExecBlocked
)

MASTER=b"original test master"
SHA=hashlib.sha256(MASTER).hexdigest()
WORK={"master_sha256":SHA,"operation_sha256":"a"*64,
      "attempt_id":"b"*64,"work_dependencies":{}}
STEP="STEP020"
STATE={"last_audit_hash":"original_tail","active_step":{"step":STEP}}
def original_base():
    return {"schema":"gg-c07-r129-exec25-native-original-process-v1",
            "source_rule_count":25,"rules":{x:{} for x in IDS},
            "original_audit_tail":"original_tail",
            "original_audit_sha256":"original_audit_sha",
            "dependency_bytes_verified":1,
            "full_rule_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False}
def controller():
    c=Mock()
    c.master.read_bytes.return_value=MASTER
    return c

class Exec25MacroPositiveTests(unittest.TestCase):
    def test_valid_real_transitive_dependency_graph_reads_all_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            left=b"real original geometry"; right=b"dependency reference original"
            (root/"a.glb").write_bytes(left)
            (root/"b.json").write_bytes(right)
            a="a"*64;b="b"*64
            plan={"dependency_files":{a:"a.glb",b:"b.json"},
                  "dependency_graph":{a:[b],b:[]}}
            work={"work_dependencies":{a:hashlib.sha256(left).hexdigest(),
                                       b:hashlib.sha256(right).hexdigest()}}
            c=Mock();c.root=root
            self.assertTrue(all_transitive_dependencies(
                plan,work,c,lambda f:Path(f).read_bytes()))
            (root/"b.json").write_bytes(b"changed after enrollment")
            self.assertFalse(all_transitive_dependencies(
                plan,work,c,lambda f:Path(f).read_bytes()))

    def test_missing_indirect_node_is_not_positive(self):
        c=Mock()
        a="a"*64;b="b"*64
        p={"dependency_files":{a:"a.glb"},
           "dependency_graph":{a:[b]}}
        w={"work_dependencies":{a:"c"*64}}
        self.assertFalse(all_transitive_dependencies(p,w,c,lambda _:b"x"))

    def test_cycle_is_not_positive(self):
        c=Mock()
        a="a"*64;b="b"*64
        p={"dependency_files":{a:"a.glb",b:"b.glb"},
           "dependency_graph":{a:[b],b:[a]}}
        w={"work_dependencies":{a:"c"*64,b:"d"*64}}
        self.assertFalse(all_transitive_dependencies(p,w,c,lambda _:b"x"))

    def test_no_graph_is_not_transitive_validation(self):
        c=Mock()
        self.assertFalse(all_transitive_dependencies(
            {"dependency_files":{"a"*64:"a.glb"}},
            {"work_dependencies":{"a"*64:"b"*64}},
            c,lambda _:b"data"))

    def test_traversal_does_not_access_outside_controller_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            key="a"*64
            p={"dependency_files":{key:"../secret"},
               "dependency_graph":{key:[]}}
            w={"work_dependencies":{key:"b"*64}}
            c=Mock();c.root=root
            self.assertFalse(all_transitive_dependencies(
                p,w,c,lambda _:b"secret"))

    def test_exact_25_positive_outcomes_stay_unknown_without_independent_proofs(self):
        c=controller()
        original=("BASELINE_SNAPSHOT","/original/baseline.blend",
                  hashlib.sha256(b"original baseline").hexdigest(),
                  b"original baseline")
        with patch("c07_exec25_positive_outcomes.original25",
                   return_value=original_base()), \
             patch("c07_exec25_positive_outcomes._original_attempt",
                   return_value=([],"original_tail",STATE,"original_audit_sha")), \
             patch("c07_exec25_positive_outcomes._registered_artifacts",
                   return_value=[original]):
            r=inspect({"rules":{rid:{
                        "source_sha256":SHA,"requirement_sha256":"f"*64}
                        for rid in IDS}},
                        {"operation":{"action":"MODEL"}},c,
                        "GOLDEN_GARDEN",STEP,WORK,
                        source_loader=lambda _:b"original baseline")
        self.assertEqual(r["schema"],SCHEMA)
        self.assertEqual(r["source_rule_count"],25)
        self.assertEqual(r["native_positive_outcome_conditions_evaluated"],50)
        self.assertEqual(len(r["rules"]),25)
        self.assertEqual(r["full_rule_semantics_passes"],0)
        self.assertEqual(r["individual_mg0_passes"],0)
        self.assertFalse(r["advancement_authorized"])
        self.assertEqual(r["rules"]["EXEC-003"]["complete_original_clause_semantics"],
                         "UNKNOWN")

    def test_unauthenticated_original_artifact_is_rejected(self):
        c=controller()
        fake=("NATIVE_EXPORT","/original/current.glb","0"*64,b"actual")
        with patch("c07_exec25_positive_outcomes.original25",
                   return_value=original_base()), \
             patch("c07_exec25_positive_outcomes._original_attempt",
                   return_value=([],"original_tail",STATE,"original_audit_sha")), \
             patch("c07_exec25_positive_outcomes._registered_artifacts",
                   return_value=[fake]):
            with self.assertRaisesRegex(NativeExecBlocked,
                                        "UNAUTHENTICATED_ORIGINAL_ARTIFACT"):
                inspect({"rules":{rid:{} for rid in IDS}},{},
                        c,"GOLDEN_GARDEN",STEP,WORK,
                        source_loader=lambda _:b"actual")

    def test_controller_close_records_full_25_macro_outcomes(self):
        code=Path(__file__).with_name("controlled_judgment.py").read_text()
        self.assertIn("from c07_exec25_positive_outcomes import inspect as inspect_exec25_positive",code)
        self.assertIn("SUPERVISOR_C07_EXEC25_ORIGINAL_POSITIVE_OUTCOMES",code)
        self.assertIn("native_positive_outcome_conditions_evaluated'] == 50",code)

    def test_unhashable_indirect_edge_returns_false_safely(self):
        c=Mock()
        key="a"*64
        p={"dependency_files":{key:"geometry.glb"},
           "outcome_contract":{"dependency_graph":{key:[{}]}}}
        w={"work_dependencies":{key:"c"*64}}
        self.assertFalse(all_transitive_dependencies(
            p,w,c,lambda _:b"actual"))

if __name__=="__main__":
    unittest.main()

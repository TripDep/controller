"""Adversarial real-byte synthetic tests; NEVER actual Garden asset approval."""
import copy
import json
import unittest
from pathlib import Path

from test_c07_positive_native_process import Tests as OriginalFixture
from c07_two_exact_process_semantics import inspect, IncompleteSemanticRule


class ProcessSemantics(unittest.TestCase):
    def setUp(self):
        self.fixture=OriginalFixture(
            'test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.persist()

    def persist(self):
        f=self.fixture
        f.controller.state_path=f.root/'original_persisted_work_state.json'
        f.controller.state_path.write_text(json.dumps({
            'assets':{f.asset: f.controller._state}},ensure_ascii=False))

    def run_review(self):
        f=self.fixture
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
                       source_loader=lambda p:Path(p).read_bytes())

    def test_both_original_literal_process_semantics_positive(self):
        doc=self.run_review()
        self.assertEqual(doc['source_rule_count'],2)
        self.assertEqual(doc['literal_process_semantics_passes'],2)
        self.assertTrue(doc['original_persisted_state_rechecked'])
        for rid in ('AAA-200-R-172','AAA-200-R-178'):
            self.assertEqual(doc['rules'][rid]['literal_process_semantics'],'PASS')
            self.assertEqual(doc['rules'][rid]['individual_mg0'],'UNKNOWN')
            self.assertFalse(doc['rules'][rid]['full_work_rule_pass'])
        self.assertEqual(doc['individual_mg0_passes'],0)
        self.assertFalse(doc['advancement_authorized'])

    def test_missing_persisted_state_downgrades_178_but_not_172(self):
        self.fixture.controller.state_path.unlink()
        doc=self.run_review()
        self.assertEqual(doc['literal_process_semantics_passes'],1)
        self.assertEqual(doc['rules']['AAA-200-R-178']['literal_process_semantics'],'UNKNOWN')
        self.assertEqual(doc['rules']['AAA-200-R-172']['literal_process_semantics'],'PASS')

    def test_persisted_state_changed_after_evidence_is_rejected(self):
        f=self.fixture
        persisted=json.loads(f.controller.state_path.read_text())
        persisted['assets'][f.asset]['active_step']['step']='TAMPER'
        f.controller.state_path.write_text(json.dumps(persisted))
        self.assertEqual(self.run_review()['rules']['AAA-200-R-178']['literal_process_semantics'],'UNKNOWN')

    def test_stale_persisted_tail_downgrades_178(self):
        f=self.fixture
        persisted=json.loads(f.controller.state_path.read_text())
        persisted['assets'][f.asset]['last_audit_hash']='0'*64
        f.controller.state_path.write_text(json.dumps(persisted))
        self.assertEqual(self.run_review()['rules']['AAA-200-R-178']['literal_process_semantics'],'UNKNOWN')

    def test_missing_dependency_downgrades_178_only(self):
        (self.fixture.root/'dependency.txt').unlink()
        # Original R123 reads dependencies via supplied source_loader and may
        # raise for missing file: failure is closed, never semantic PASS.
        with self.assertRaises((ValueError,OSError)):
            self.run_review()

    def test_changed_dependency_downgrades_178(self):
        (self.fixture.root/'dependency.txt').write_text('MUTATED')
        doc=self.run_review()
        self.assertEqual(doc['rules']['AAA-200-R-178']['literal_process_semantics'],'UNKNOWN')

    def test_changed_native_export_rejected_for_both(self):
        (self.fixture.root/'scene.glb').write_bytes(b'MUTATED')
        with self.assertRaisesRegex(ValueError,'ARTIFACT_BYTES_CHANGED'):
            self.run_review()

    def test_wrong_delivery_manifest_downgrades_172_only(self):
        f=self.fixture
        f.add_item('DELIVERY_PACKAGE','scene.zip',f.make_zip(wrong_attempt=True))
        f.rebuild();self.persist()
        doc=self.run_review()
        self.assertEqual(doc['rules']['AAA-200-R-172']['literal_process_semantics'],'UNKNOWN')
        self.assertEqual(doc['rules']['AAA-200-R-178']['literal_process_semantics'],'PASS')

    def test_missing_delivery_downgrades_172_only(self):
        f=self.fixture
        del f.items['DELIVERY_PACKAGE'];f.rebuild();self.persist()
        doc=self.run_review()
        self.assertEqual(doc['rules']['AAA-200-R-172']['literal_process_semantics'],'UNKNOWN')
        self.assertEqual(doc['rules']['AAA-200-R-178']['literal_process_semantics'],'PASS')

    def test_cross_attempt_replay_rejected(self):
        f=self.fixture
        f.work=copy.deepcopy(f.work)
        f.work['attempt_id']='d'*64
        with self.assertRaisesRegex(ValueError,'EXACT_RESERVED_WORK'):
            self.run_review()

    def test_rule_text_drift_rejected(self):
        self.fixture.inv['rules']['AAA-200-R-178']['requirement']='fake pass'
        with self.assertRaisesRegex(ValueError,'LITERAL_RULE'):
            self.run_review()

    def test_changing_audit_original_rejected(self):
        f=self.fixture
        p=f.controller.audit_path(f.asset)
        p.write_bytes(p.read_bytes().replace(b'ARTIFACT_RECORDED',b'ARTIFACT_CHANGED'))
        with self.assertRaises(ValueError):self.run_review()


if __name__=='__main__':unittest.main()

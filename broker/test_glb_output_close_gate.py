"""C07 registered-output closure gate tests: synthetic assets, no work PASS."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from glb_output_close_gate import inspect, OutputGateBlocked, canonical_hash
from test_glb_machine_qa import synthetic_glb
from test_glb_pbr_evidence import fixture,pack

WORK={'attempt_id':'a'*64,'operation_sha256':'b'*64,'master_sha256':'c'*64}

class OutputCloseGateTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.p=self.root/'registered.glb'
        self.p.write_bytes(synthetic_glb())
    def item(self):
        return {'step':'0001','path':str(self.p.resolve()),
                'sha256':hashlib.sha256(self.p.read_bytes()).hexdigest(),
                'size_bytes':self.p.stat().st_size}
    def probe(self,items=None,work=None):
        return inspect([self.item()] if items is None else items,
                       WORK if work is None else work,'TEST','0001')
    def test_structurally_clean_can_only_go_to_independent_native(self):
        v=self.probe()
        self.assertTrue(v['may_continue_to_independent_native_post_review'])
        self.assertEqual(v['glb_outputs_scanned'],1)
        self.assertEqual(v['semantic_result'],'UNKNOWN')
        self.assertEqual(v['individual_mg0'],'UNKNOWN')
        self.assertFalse(v['advancement_authorized'])
        self.assertEqual(v['asset_acceptance'],'NOT_AUTHORIZED')
        self.assertEqual(v['evidence_sha256'],canonical_hash(
            {k:val for k,val in v.items() if k!='evidence_sha256'}))
    def test_actual_degenerate_geometry_forbids_close(self):
        self.p.write_bytes(synthetic_glb(triangles=[(0,0,0),(1,1,1),(2,2,2)]))
        v=self.probe()
        self.assertFalse(v['may_continue_to_independent_native_post_review'])
        self.assertEqual(v['machine_blockers'][0]['reason'],
                         'GLB_FATAL_GEOMETRY_OR_PBR_FINDING')
        self.assertEqual(v['semantic_result'],'UNKNOWN')
    def test_mat_uv_missing_forbids_close(self):
        g,blob,_=fixture(texcoord=False)
        g.update(nodes=[{'mesh':0}],scenes=[{'nodes':[0]}],scene=0)
        self.p.write_bytes(pack(g,blob))
        v=self.probe()
        self.assertFalse(v['may_continue_to_independent_native_post_review'])
        self.assertEqual(v['machine_blockers'][0]['reason'],
                         'GLB_FATAL_GEOMETRY_OR_PBR_FINDING')
        self.assertIn('USED_TEXCOORD_MISSING',v['machine_blockers'][0]['detail'])
    def test_malformed_glb_with_valid_sha_still_blocks(self):
        self.p.write_bytes(b'glTF'+b'0'*44)
        v=self.probe()
        self.assertFalse(v['may_continue_to_independent_native_post_review'])
        self.assertEqual(v['machine_blockers'][0]['reason'],
                         'GLB_UNREADABLE_OR_UNSUPPORTED')
    def test_changed_bytes_with_old_authenticated_sha_block(self):
        original=self.item()
        self.p.write_bytes(self.p.read_bytes()+b'changed')
        original['size_bytes']=self.p.stat().st_size
        v=self.probe([original])
        self.assertFalse(v['may_continue_to_independent_native_post_review'])
        self.assertEqual(v['machine_blockers'][0]['reason'],
                         'GLB_UNREADABLE_OR_UNSUPPORTED')
    def test_path_outside_registered_step_denied(self):
        item=self.item();item['step']='9999'
        with self.assertRaisesRegex(OutputGateBlocked,'OUTPUT_GATE_STEP_OR_ARTIFACT_INVALID'):
            self.probe([item])
    def test_symlink_source_denied(self):
        p=self.root/'symlink.glb'
        p.symlink_to(self.p)
        item=self.item();item['path']=str(p.resolve().parent/'symlink.glb')
        with self.assertRaisesRegex(OutputGateBlocked,'OUTPUT_GATE_GLTF_PATH_INVALID'):
            self.probe([item])
    def test_duplicate_artifact_digest_denied(self):
        a=self.item()
        with self.assertRaisesRegex(OutputGateBlocked,'OUTPUT_GATE_DUPLICATE_GLTF_SOURCE'):
            self.probe([a,a])
    def test_non_glb_never_declared_verified(self):
        other=self.root/'native-export.ydr';other.write_bytes(b'temporary synthetic bytes')
        item={'step':'0001','path':str(other.resolve()),'sha256':'0'*64,
              'size_bytes':other.stat().st_size}
        v=self.probe([item])
        self.assertEqual(v['glb_outputs_scanned'],0)
        self.assertIn('.ydr',v['other_formats_not_verified'])
        self.assertFalse(v['may_continue_to_independent_native_post_review'])
        self.assertIn('OUTPUT_FORMAT_NO_INDEPENDENT_MACHINE_VERIFIER',
                      [b['reason'] for b in v['machine_blockers']])
        self.assertIn('OUTPUT_GATE_NO_VERIFIED_GLB',
                      [b['reason'] for b in v['machine_blockers']])
        self.assertEqual(v['semantic_result'],'UNKNOWN')
        self.assertFalse(v['advancement_authorized'])
    def test_mixed_good_glb_and_unreviewed_ydr_still_stops(self):
        other=self.root/'unreviewed.ydr'
        other.write_bytes(b'synthetic-output-not-a-validated-model')
        item={'step':'0001','path':str(other.resolve()),
              'sha256':hashlib.sha256(other.read_bytes()).hexdigest(),
              'size_bytes':other.stat().st_size}
        v=self.probe([self.item(),item])
        self.assertEqual(v['glb_outputs_scanned'],1)
        self.assertFalse(v['may_continue_to_independent_native_post_review'])
        self.assertIn('OUTPUT_FORMAT_NO_INDEPENDENT_MACHINE_VERIFIER',
                      [x['reason'] for x in v['machine_blockers']])
        self.assertEqual(v['individual_mg0'],'UNKNOWN')
    def test_absent_model_cannot_be_called_complete(self):
        v=self.probe(items=[])
        self.assertFalse(v['may_continue_to_independent_native_post_review'])
        self.assertIn('OUTPUT_GATE_NO_REGISTERED_ARTIFACTS',
                      [x['reason'] for x in v['machine_blockers']])
    def test_incomplete_triangle_scan_is_blocking_even_when_geometry_is_clean(self):
        from glb_machine_qa import examine
        measured=examine(self.p,hashlib.sha256(self.p.read_bytes()).hexdigest())
        measured['triangle_surface_crossing_evidence'][
            'all_requested_pairs_fully_scanned']=False
        measured['triangle_surface_crossing_evidence']['unresolved_pairs']=[
            {'reason':'CROSSING_PAIR_TEST_BUDGET_EXCEEDED'}]
        self.assertEqual(measured['machine_evidence_status'],
                         'NO_FATAL_STRUCTURAL_DEFECT_DETECTED')
        with patch('glb_output_close_gate.examine',return_value=measured):
            v=self.probe()
        self.assertFalse(v['may_continue_to_independent_native_post_review'])
        self.assertIn('GLB_TRIANGLE_INTERSECTION_SCAN_INCOMPLETE',
                      [x['reason'] for x in v['machine_blockers']])
    def test_producer_cannot_claim_material_coverage_if_scanner_reports_unknown(self):
        from glb_machine_qa import examine
        measured=examine(self.p,hashlib.sha256(self.p.read_bytes()).hexdigest())
        measured['machine_evidence_status']='UNKNOWN_UNSUPPORTED_INPUT'
        with patch('glb_output_close_gate.examine',return_value=measured):
            v=self.probe()
        self.assertFalse(v['may_continue_to_independent_native_post_review'])
        self.assertIn('GLB_MACHINE_VERIFICATION_INCOMPLETE',
                      [x['reason'] for x in v['machine_blockers']])

    def test_missing_attempt_binding_denied(self):
        with self.assertRaisesRegex(OutputGateBlocked,'OUTPUT_GATE_EXACT_ATTEMPT_REQUIRED'):
            self.probe(work={**WORK,'attempt_id':'not-a-sha'})

if __name__=='__main__':unittest.main()

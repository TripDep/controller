"""Local C07 bridge regression; synthetic GLBs only, no asset authorizations."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from glb_rule_bridge import verify_live, GLBBridgeBlocked, canonical_sha
from glb_machine_qa import GLBError
from test_glb_machine_qa import synthetic_glb

CONTEXT={'asset_id':'TEST', 'attempt_id':'a'*64,
         'operation_sha256':'b'*64, 'master_sha256':'c'*64,
         'phase':'P8', 'rule_id':'MACHINE_QA'}

class BridgeTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.path=Path(t.name)/'fixture.glb'
        self.path.write_bytes(synthetic_glb())
        self.sha=hashlib.sha256(self.path.read_bytes()).hexdigest()
    def test_healthy_source_remains_semantically_unknown(self):
        v=verify_live(self.path,self.sha,CONTEXT)
        self.assertEqual(v['machine_status'],'NO_FATAL_STRUCTURAL_DEFECT_DETECTED')
        self.assertEqual(v['semantic_verdict'],'UNKNOWN')
        self.assertEqual(v['individual_mg0'],'UNKNOWN')
        self.assertFalse(v['acceptance_authorized'])
        self.assertEqual(v['artifact_sha256'],self.sha)
        self.assertIn('material_source_evidence',v)
        self.assertEqual(v['material_source_evidence']['visual_material_quality'],'UNKNOWN')
        self.assertEqual(v['material_source_evidence']['individual_mg0'],'UNKNOWN')
        self.assertEqual(v['evidence_sha256'],canonical_sha({k:x for k,x in v.items() if k!='evidence_sha256'}))
    def test_degenerate_triangle_blocks_its_machine_obligation(self):
        self.path.write_bytes(synthetic_glb(triangles=[(0,0,0),(1,1,1),(2,2,2)]))
        digest=hashlib.sha256(self.path.read_bytes()).hexdigest()
        v=verify_live(self.path,digest,CONTEXT)
        self.assertEqual(v['semantic_verdict'],'FAIL')
        self.assertEqual(v['geometry']['degenerate_triangles'],1)
        self.assertFalse(v['acceptance_authorized'])
    def test_source_changes_after_approval(self):
        self.path.write_bytes(self.path.read_bytes()+b'unapproved change')
        with self.assertRaisesRegex(GLBError,'SOURCE_GLB_SHA256_MISMATCH'):
            verify_live(self.path,self.sha,CONTEXT)
    def test_untrusted_report_is_not_accepted(self):
        claimed={'schema':'fake','semantic_verdict':'PASS'}
        with self.assertRaisesRegex(GLBBridgeBlocked,'PRODUCER_REPORT_DIFFERS_FROM_BYTES'):
            verify_live(self.path,self.sha,CONTEXT,claimed_report=claimed)
    def test_context_missing_or_forged(self):
        for change in ({'attempt_id':'wrong'}, {'master_sha256':'0'*63},
                       {'asset_id':'test'}, {'rule_id':'UNKNOWN'},
                       {'approval':'PASS'}):
            c={**CONTEXT,**change}
            with self.assertRaises(GLBBridgeBlocked):verify_live(self.path,self.sha,c)
    def test_same_file_different_attempt_binds_distinct_evidence(self):
        a=verify_live(self.path,self.sha,CONTEXT)
        b=verify_live(self.path,self.sha,{**CONTEXT,'attempt_id':'d'*64})
        self.assertNotEqual(a['evidence_sha256'],b['evidence_sha256'])
    def test_wrong_scanner_must_not_inject_pass(self):
        with patch('glb_rule_bridge.examine',return_value={
                'schema':'gg-c07-glb-readonly-machine-audit-v1',
                'source_sha256':self.sha,'machine_evidence_status':'PASS',
                'overall_rule_semantics':'PASS','asset_acceptance':'AUTHORIZED',
                'mg0':'PASS','overlaps_confirmed':True}):
            with self.assertRaisesRegex(GLBBridgeBlocked,'CANNOT_AUTHORIZE'):
                verify_live(self.path,self.sha,CONTEXT)

if __name__ == '__main__':unittest.main()
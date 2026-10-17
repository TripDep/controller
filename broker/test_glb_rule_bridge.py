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
        self.assertEqual(v['indexed_winding_evidence']['orientation_conflict_meshes'],0)
        self.assertEqual(v['indexed_winding_evidence']['boundary_edges'],3)
        self.assertEqual(v['render_side_source_evidence']['explicit_NORMAL_primitive_count'],0)
        self.assertEqual(v['render_side_source_evidence']['single_sided_primitive_count'],1)
        self.assertEqual(v['render_side_source_evidence']['native_blender_visual'],'UNKNOWN')
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
    def test_orientation_conflict_is_an_explicit_machine_fail_not_asset_pass(self):
        vertices=[(0.,0.,0.),(1.,0.,0.),(0.,1.,0.),(1.,1.,0.)]
        self.path.write_bytes(synthetic_glb(
            triangles=vertices,indexes=[0,1,2,1,2,3]))
        digest=hashlib.sha256(self.path.read_bytes()).hexdigest()
        report=verify_live(self.path,digest,CONTEXT)
        self.assertEqual(report['machine_status'],'NO_FATAL_STRUCTURAL_DEFECT_DETECTED')
        self.assertEqual(report['semantic_verdict'],'FAIL')
        self.assertEqual(report['indexed_winding_evidence']['orientation_conflict_meshes'],1)
        self.assertEqual(report['indexed_winding_evidence']['same_direction_shared_edges'],1)
        self.assertEqual(report['individual_mg0'],'UNKNOWN')
        self.assertFalse(report['acceptance_authorized'])
        self.assertTrue(any('GLB_INDEX_WINDING_OR_NONMANIFOLD_OBSERVED' in s
                            for s in report['fatal_machine_findings']))

    def test_open_geometry_not_misidentified_as_wrong_winding(self):
        report=verify_live(self.path,self.sha,CONTEXT)
        self.assertEqual(report['indexed_winding_evidence']['boundary_edges'],3)
        self.assertEqual(report['indexed_winding_evidence']['orientation_conflict_meshes'],0)
        self.assertEqual(report['semantic_verdict'],'UNKNOWN')
        self.assertFalse(report['acceptance_authorized'])

    def test_missing_texture_uv_detected_on_exact_registered_bytes(self):
        import json, struct
        source=synthetic_glb()
        n=struct.unpack_from('<I',source,12)[0]
        d=json.loads(source[20:20+n])
        d['materials']=[{'pbrMetallicRoughness':{
           'baseColorTexture':{'index':0}}}]
        d['meshes'][0]['primitives'][0]['material']=0
        enc=json.dumps(d,separators=(',',':')).encode()
        enc+=b' '*(-len(enc)%4)
        rest=source[20+n:]
        raw=struct.pack('<4sII',b'glTF',2,20+len(enc)+len(rest))
        raw+=struct.pack('<I4s',len(enc),b'JSON')+enc+rest
        self.path.write_bytes(raw)
        digest=hashlib.sha256(raw).hexdigest()
        report=verify_live(self.path,digest,CONTEXT)
        self.assertEqual(report['semantic_verdict'],'FAIL')
        self.assertEqual(report['render_side_source_evidence']
                         ['missing_required_texcoord_attributes_count'],1)
        self.assertIn('GLB_TEXTURE_REQUIRED_TEXCOORD_MISSING:1',
                      report['fatal_machine_findings'])
        self.assertFalse(report['acceptance_authorized'])

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


    def test_canonical_rule_id_is_accepted_only_as_native_negative_scope(self):
        scope={**CONTEXT,'rule_id':'AAA-200-G-065'}
        report=verify_live(self.path,self.sha,scope)
        self.assertEqual(report['semantic_verdict'],'UNKNOWN')
        self.assertEqual(report['canonical_rule_observation']
                         ['evidence_kind'],'WINDING_AND_NORMAL_ORIENTATION')
        self.assertEqual(report['individual_mg0'],'UNKNOWN')
        self.assertFalse(report['acceptance_authorized'])

    def test_batch_200_rule_ids_one_real_glb_scan_unknown_not_pass(self):
        from glb_rule_bridge import verify_live_batch
        ctx={k:v for k,v in CONTEXT.items() if k!='rule_id'}
        # Real canonical ID names + unrelated Q bank IDs are all processed
        # from one verified byte-bound readback, with no pass inflation.
        rules=sorted(['AAA-200-G-065','AAA-200-L-113',
                      'AAA-200-M-123']+['Q-%03d'%i for i in range(1,198)])
        with patch('glb_rule_bridge.examine', wraps=__import__(
                   'glb_rule_bridge').examine) as scan:
            report=verify_live_batch(self.path,self.sha,ctx,rules)
            self.assertEqual(scan.call_count,1)
        self.assertEqual(report['rule_count'],200)
        self.assertEqual(report['native_observation_counts']['UNKNOWN'],200)
        self.assertEqual(report['work_rule_passes'],0)
        self.assertFalse(report['advancement_authorized'])
        self.assertEqual(report['rules']['AAA-200-L-113']
                         ['independent_native_rule_observation'],'UNKNOWN')
        self.assertNotEqual(report['rules']['AAA-200-L-113']['evidence_sha256'],
                            report['rules']['AAA-200-M-123']['evidence_sha256'])

    def test_batch_one_degenerate_fails_only_related_canonical_predicates(self):
        from glb_rule_bridge import verify_live_batch
        self.path.write_bytes(synthetic_glb(
            triangles=[(0.,0.,0.),(1.,1.,1.),(2.,2.,2.)]))
        correct=hashlib.sha256(self.path.read_bytes()).hexdigest()
        ctx={k:v for k,v in CONTEXT.items() if k!='rule_id'}
        rules=sorted(['AAA-200-L-111','AAA-200-L-113',
                      'AAA-200-M-123','Q-075'])
        report=verify_live_batch(self.path,correct,ctx,rules)
        self.assertEqual(report['native_observation_counts'],{'FAIL':2,'UNKNOWN':2})
        self.assertEqual(report['rules']['AAA-200-L-113']
                         ['native_negative_findings'],['DEGENERATE_TRIANGLES'])
        self.assertEqual(report['rules']['AAA-200-M-123']
                         ['independent_native_rule_observation'],'UNKNOWN')
        self.assertFalse(report['advancement_authorized'])

    def test_batch_exact_digest_and_rule_membership_fail_closed(self):
        from glb_rule_bridge import verify_live_batch
        ctx={k:v for k,v in CONTEXT.items() if k!='rule_id'}
        for keys in ([],['Q-075','Q-075'],['Q-999','Q-001']):
            with self.assertRaisesRegex(GLBBridgeBlocked,'BATCH_RULE_IDS_INVALID'):
                verify_live_batch(self.path,self.sha,ctx,keys)
        with self.assertRaises(GLBError):
            verify_live_batch(self.path,'0'*64,ctx,['AAA-200-G-065'])
        with self.assertRaisesRegex(GLBBridgeBlocked,'BATCH_CONTEXT_SCHEMA'):
            verify_live_batch(self.path,self.sha,
                              {**ctx,'producer_pass':True},['AAA-200-G-065'])


    def test_machine_positive_subpredicates_never_promote_full_rule_or_mg0(self):
        from glb_rule_bridge import verify_live_batch, MACHINE_POSITIVE_SCOPES
        ctx={k:v for k,v in CONTEXT.items() if k!='rule_id'}
        ids=sorted(MACHINE_POSITIVE_SCOPES)
        r=verify_live_batch(self.path,self.sha,ctx,ids)
        observed=[rid for rid,row in r['rules'].items() if
            row['scoped_positive_machine_observation']['result']=='OBSERVED_SCOPE_PASS']
        self.assertGreaterEqual(len(observed),7)
        self.assertEqual(r['native_observation_counts']['FAIL'],0)
        self.assertEqual(r['work_rule_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        self.assertTrue(all(not row['scoped_positive_machine_observation']
            ['complete_semantic_rule_pass'] for row in r['rules'].values()))

    def test_degenerate_geometry_not_qualified_as_positive_geometry_proof(self):
        from glb_rule_bridge import verify_live_batch
        self.path.write_bytes(synthetic_glb(triangles=[
            (0.,0.,0.),(1.,1.,1.),(2.,2.,2.)]))
        sha=hashlib.sha256(self.path.read_bytes()).hexdigest()
        ctx={k:v for k,v in CONTEXT.items() if k!='rule_id'}
        r=verify_live_batch(self.path,sha,ctx,sorted([
            'AAA-200-L-111','AAA-200-L-113','AAA-200-S-184']))
        self.assertEqual(r['native_observation_counts']['FAIL'],3)
        self.assertTrue(all(row['scoped_positive_machine_observation']['result']
            !='OBSERVED_SCOPE_PASS' for row in r['rules'].values()))
        self.assertEqual(r['individual_mg0_passes'],0)

if __name__ == '__main__':unittest.main()
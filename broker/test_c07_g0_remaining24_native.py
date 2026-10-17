"""R143: 24 exact canonical G0 clauses, original-byte adversarial tests."""
import copy
import unittest
from pathlib import Path
from c07_g0_remaining24_native import inspect, IDS, G0Blocked
from c07_positive_native_process import NativeEvidenceBlocked
from test_c07_positive_native_process import Tests as NativeFixture, sha
from test_c07_r124_positive_process import test_glb
from test_c07_a10_c10_original_evidence import png
from c07_positive200_evidence import R122_FROZEN_IDS

class OriginalG024(unittest.TestCase):
    def setUp(self):
        self.fx=NativeFixture('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f=self.fx
        clauses=['Exact ORIGINAL synthetic G0 criterion %d'%n for n in range(1,31)]
        master=('### Exact recovered 30-control source list\n\n' +
            '\n'.join('%d. %s'%(n,t) for n,t in enumerate(clauses,1)) +
            '\n\n### G0 canonical role\n\nG0 requires genuine evidence.\n').encode()
        self.f.master=master
        (self.f.root/'MASTER.md').write_bytes(master)
        h=sha(master)
        self.f.inv['canonical_master_sha256']=h
        self.f.inv['families']={'G0_CONTROLS':list(IDS)}
        self.f.plan['master_sha256']=h
        self.f.work['master_sha256']=h
        for n in range(7,31):
            rid='G0-'+str(n).zfill(2)
            t=clauses[n-1]
            self.f.inv['rules'][rid]={
                'family':'G0_CONTROLS','source':'master',
                'source_sha256':h,'requirement':t,
                'requirement_sha256':sha(t.encode())}
        self.f.plan['pre_d_control']={
          'time_budget_seconds':3600,
          'triangle_budget':12000,
          'player_reference_height_m':1.8,
          'protected_source_sha256':self.f.items['SOURCE_EDITABLE']['sha256'],
          'construction_policy':'ARCHITECTURE_1TO1',
          'defect_ids':['PAV-011'],
          'new_features':[],
          'reference_image_sha256':sha(png(21)),
          'palette_sha256':sha(b'palette native'),
          'fixed_cameras':{'underside':'CAM_B'},
          'deliverable_scope_levels':{
              'LOCAL_REFINEMENT':'PARTIAL','FIVEM_COMPLETE':'NOT_VERIFIED'},
        }
        self.f.rebuild()
    def read(self):
        f=self.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
                       source_loader=lambda p:Path(p).read_bytes())
    def test_all_24_original_G0_rules_and_72_distinct_checks(self):
        x=self.read()
        self.assertEqual(x['source_rules_examined'],24)
        self.assertEqual(x['domain_conditions'],72)
        self.assertEqual(set(x['rules']),set(IDS))
        self.assertTrue(set(IDS).isdisjoint(set(R122_FROZEN_IDS)))
        self.assertEqual(x['full_semantics_passes'],0)
        self.assertEqual(x['individual_mg0_passes'],0)
        self.assertFalse(x['advancement_authorized'])
        names=[]
        for rid,item in x['rules'].items():
            with self.subTest(id=rid):
                self.assertEqual(item['full_semantics'],'UNKNOWN')
                self.assertEqual(item['individual_mg0'],'UNKNOWN')
                self.assertEqual(item['owner_acceptance'],'UNKNOWN')
                criteria=item['original_native_evidence_predicates']
                self.assertEqual(len(criteria),3)
                self.assertTrue(all(type(v) is bool for v in criteria.values()))
                names+=list(criteria)
        self.assertEqual(len(set(names)),72)
    def test_each_of_24_clauses_changed_rejected(self):
        for rid in IDS:
            old=self.f.inv['rules'][rid]['requirement']
            self.f.inv['rules'][rid]['requirement']='faked approved source'
            with self.subTest(id=rid):
                with self.assertRaisesRegex(G0Blocked,'R143_ORIGINAL_G0_LITERAL_CLAUSE_DRIFT'):
                    self.read()
            self.f.inv['rules'][rid]['requirement']=old
    def test_each_of_24_source_sha_changed_rejected(self):
        for rid in IDS:
            old=self.f.inv['rules'][rid]['source_sha256']
            self.f.inv['rules'][rid]['source_sha256']='e'*64
            with self.subTest(id=rid):
                with self.assertRaisesRegex(G0Blocked,'R143_ORIGINAL_G0_LITERAL_CLAUSE_DRIFT'):
                    self.read()
            self.f.inv['rules'][rid]['source_sha256']=old
    def test_binary_geometry_positive_native_reimport_not_mg0(self):
        native=test_glb()
        self.f.add_item('NATIVE_EXPORT','scene.glb',native)
        self.f.add_item('NATIVE_REIMPORT','reimport.glb',native)
        self.f.rebuild()
        x=self.read()
        check=x['rules']['G0-23']['original_native_evidence_predicates']
        self.assertTrue(all(check.values()))
        self.assertEqual(x['rules']['G0-23']['full_semantics'],'UNKNOWN')
        self.assertEqual(x['rules']['G0-23']['individual_mg0'],'UNKNOWN')
    def test_wrong_reimport_geometry_still_unknown(self):
        self.f.add_item('NATIVE_EXPORT','scene.glb',test_glb())
        self.f.add_item('NATIVE_REIMPORT','reimport.glb',b'fake user claimed reimport')
        self.f.rebuild()
        check=self.read()['rules']['G0-23']['original_native_evidence_predicates']
        self.assertFalse(check['original_export_and_reimport_binary_BOTH_reopened'])
    def test_cross_attempt_replay_rejected(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='f'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.read()
    def test_original_G0_MASTER_changed_not_ignored(self):
        (self.f.root/'MASTER.md').write_text('Not original master')
        with self.assertRaisesRegex(G0Blocked,'R143_LIBRARY_CANONICAL_MASTER_DRIFT'):
            self.read()
    def test_current_registered_source_tamper_fails_closed(self):
        (self.f.root/'scene.blend').write_bytes(b'new changed file')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.read()
    def test_original_png_missing_evidence_not_turned_into_pass(self):
        self.assertFalse(self.read()['rules']['G0-25'][
            'original_native_evidence_predicates'][
            'original_current_underneath_view_image_decoded'])

if __name__=='__main__':unittest.main()

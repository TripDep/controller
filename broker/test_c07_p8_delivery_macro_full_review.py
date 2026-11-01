"""T-phase source-native semantic macro: five original-byte and adversarial tests.

These are synthetic execution fixtures, not a live Blender, FiveM or MG0 pass.
"""
import copy
import io
import json
import unittest
from pathlib import Path
from zipfile import ZipFile

import supervisor_judgment as judgment
from c07_p8_delivery_macro_full_review import (
    RULES,inspect,blender_blocks)
from c07_native_source_rule_replayers import (
    build_packet,NATIVE_RULES,FULL_LITERAL_REVIEWED)
from test_c07_p8_closure_semantics import Tests as ClosureFixture
from test_c07_p3_geometry_semantics import glb
from test_c07_p678_forty_native_domain import TEXT
from test_c07_positive_native_process import sha

def blender_envelope():
    """Well-formed miniature BHead/DNA1 fixture; not a real artist's .blend."""
    header=b'BLENDER-v300'
    def pack16(n):return n.to_bytes(2,'little')
    def pack32(n):return n.to_bytes(4,'little')
    def pad(raw):return raw+bytes((-len(raw))%4)
    dna=(b'SDNA'+b'NAME'+pack32(1)+pad(b'field'+bytes((0,)))+
         b'TYPE'+pack32(1)+pad(b'Thing'+bytes((0,)))+
         b'TLEN'+pack16(4)+bytes(2)+b'STRC'+pack32(1)+
         pack16(0)+pack16(1)+pack16(0)+pack16(0))
    def block(tag,payload=b''):
        return (tag+pack32(len(payload))+bytes(8)+
                pack32(0)+pack32(1)+payload)
    return (header+block(b'OB'+bytes(2),b'abcd')+
            block(b'DNA1',dna)+block(b'ENDB'))


def archive(members):
    out=io.BytesIO()
    with ZipFile(out,'w') as z:
        for name,contents in members.items():z.writestr(name,contents)
    return out.getvalue()

class DeliveryFamilyFiveOriginalTests(unittest.TestCase):
    def setUp(self):
        self.fixture=ClosureFixture('test_five_scoped_observations_and_final_rule_unknown')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture.f
        for n in range(191,195):
            rid='AAA-200-T-'+str(n).zfill(3)
            literal,phase=TEXT[str(n)]
            self.f.inv['rules'][rid]={
                'family':'AAA-200','catalog_number':n,
                'catalog_section':'T','catalog_phase':phase,
                'requirement':literal,
                'requirement_sha256':sha(literal.encode()),
                'source_sha256':'c'*64}
        self.source=blender_envelope()
        self.export=glb([(0,0,0),(1,0,0),(0,1,0)],
                        [(0,1,2)])
        self.before=glb([(0.5,0,0),(1.5,0,0),(0.5,1,0)],
                        [(0,1,2)])
        self.case_b=glb([(0.5,0,0),(0.5,1.5,0),(1.5,0,0)],
                        [(0,1,2)])
        self.fixed_b=glb([(0,0,0),(0,1.5,0),(1,0,0)],
                        [(0,1,2)])
        self.f.add_item('SOURCE_EDITABLE','scene.blend',self.source)
        self.f.add_item('NATIVE_EXPORT','scene.glb',self.export)
        self.f.add_item('BASELINE_SNAPSHOT','before.glb',self.before)
        self.delivery_plan={
            'asset':self.f.asset,'version':'v1',
            'source_member':'scene.blend','export_member':'scene.glb',
            'required_members':['scene.blend','scene.glb','DELIVERY_MANIFEST.json'],
            'source_sha256':sha(self.source),'export_sha256':sha(self.export)}
        self.fixture.docs['P8_MAINTENANCE_GUIDE']={
            'asset':self.f.asset, 'source_sha256':sha(self.source),
            'export_sha256':sha(self.export),
            'install_paths':['scene.blend','scene.glb'],
            'maintenance_steps':['Retain editable source for revisions',
                                 'Record exact source version on every update',
                                 'Revalidate native geometry and hashes'],
            'status':'CANDIDATE','owner_approved':False}
        self.fixture.docs['P8_DEFECT_HISTORY']={'issues':[
            {'id':'case-A','root_cause':'ORIGIN_DEVIATION',
             'corrective_action':'restore canonical pivot',
             'before_sha256':sha(self.before),'after_sha256':sha(self.export)},
            {'id':'case-B','root_cause':'ORIGIN_DEVIATION',
             'corrective_action':'reapply transformed export',
             'before_sha256':sha(self.case_b),'after_sha256':sha(self.fixed_b)},
        ]}
        # Original method bytes are deterministic, source-only translations;
        # the consumer will interpret their AST but never execute user code.
        self.before_script=(b'def correct_origin(vertices):\n'
            b'    return [[p[0],p[1],p[2]] for p in vertices]\n')
        self.after_script=(b'def correct_origin(vertices):\n'
            b'    return [[p[0]-0.5,p[1],p[2]] for p in vertices]\n')
        self.f.add_item('P8_METHOD_BEFORE','method_before.py',
                        self.before_script)
        self.f.add_item('P8_METHOD_AFTER','method_after.py',
                        self.after_script)
        self.fixture.docs['P8_METHOD_CHANGE']={
            'before_sha256':sha(self.before_script),
            'after_sha256':sha(self.after_script),
            'root_cause':'ORIGIN_DEVIATION',
            'verification_method':'independent_bbox_origin_measurement'}
        self.root_policy={
            'schema':'c07-p8-origin-defect-pre-d-v1',
            'asset':self.f.asset,'target_bbox_min':[0,0,0],
            'max_origin_error_m':0.05}
        self.f.work.update(work_item_sha256='e'*64,
                           attempt_number=1,previous_attempt_id=None)
        # Use the actual canonical MG0 section required by native readback.
        # This fixture never grants independent process correction or PASS.
        from c07_mg0_individual import TRIGGERS
        master=('## MG0 — PROCESS FALSIFICATION\\n' +
            ''.join('- '+trigger+'\\n' for trigger in TRIGGERS) +
            'The response is not limited to fixing the asset.\\n'
            'invalidate affected states and reapply the corrected process\\n'
        ).replace('\\n','\n').encode()
        self.f.master=master
        self.f.controller.master.write_bytes(master)
        new_sha=sha(master)
        self.f.work['master_sha256']=new_sha
        self.f.plan['master_sha256']=new_sha
        self.f.inv['canonical_master_sha256']=new_sha
        self.refresh()

    def refresh(self):
        self.f.add_item('SOURCE_EDITABLE','scene.blend',self.source)
        self.f.add_item('NATIVE_EXPORT','scene.glb',self.export)
        self.f.add_item('BASELINE_SNAPSHOT','before.glb',self.before)
        self.f.add_item('P8_DEFECT_CASE_A','before_case_a.glb',self.before)
        self.f.add_item('P8_DEFECT_CASE_B','before_case_b.glb',self.case_b)
        self.f.add_item('P8_DEFECT_FIXED_A','fixed_case_a.glb',self.export)
        self.f.add_item('P8_DEFECT_FIXED_B','fixed_case_b.glb',self.fixed_b)
        self.f.add_item('P8_METHOD_BEFORE','method_before.py',self.before_script)
        self.f.add_item('P8_METHOD_AFTER','method_after.py',self.after_script)
        self.f.add_item('P8_DELIVERY_PLAN','p8_delivery.json',
                        json.dumps(self.delivery_plan,sort_keys=True).encode())
        manifest={key:self.delivery_plan[key] for key in
                  ('asset','version','source_member','export_member',
                   'source_sha256','export_sha256')}
        members={'scene.blend':self.source,'scene.glb':self.export,
                 'DELIVERY_MANIFEST.json':json.dumps(manifest).encode()}
        self.f.add_item('DELIVERY_PACKAGE','delivery.zip',archive(members))
        self.f.add_item('P8_ROOT_CAUSE_POLICY','pre_d_origin.json',
                        json.dumps(self.root_policy).encode())
        for role,doc in self.fixture.docs.items():
            self.f.add_item(role,role.lower()+'.json',
                            json.dumps(doc).encode())
        self.f.plan['p678_evidence_contract']={
            'original_artifact_sha256':{
                role:meta['sha256'] for role,meta in self.f.items.items()}}
        self.f.rebuild()
        # In the original Controller chain, each observed recurrent defect
        # must have its own current-attempt finding after the reservation.
        from test_c07_positive_native_process import canonical
        for issue in self.fixture.docs['P8_DEFECT_HISTORY']['issues']:
            event={'asset':self.f.asset,'event':'QUALITY_FINDING',
                'prev_hash':self.f.records[-1]['record_hash'],
                'step':self.f.step,'attempt_id':self.f.work['attempt_id'],
                'operation_sha256':self.f.work['operation_sha256'],
                'severity':'HIGH','status':'OPEN',
                'issue_id':issue['id'],
                'root_cause':issue['root_cause'],
                'before_sha256':issue['before_sha256'],
                'after_sha256':issue['after_sha256']}
            event['record_hash']=sha(canonical(event))
            self.f.records.append(event)
        self.f.controller.audit_path(self.f.asset).write_bytes(
            b''.join(canonical(row)+b'\n' for row in self.f.records))
        # Rechecks are separately authenticated and ordered after the
        # associated original negative findings in this exact operation.
        for issue in self.fixture.docs['P8_DEFECT_HISTORY']['issues']:
            event={'asset':self.f.asset,'event':'QUALITY_RECHECK',
                'prev_hash':self.f.records[-1]['record_hash'],
                'step':self.f.step,'attempt_id':self.f.work['attempt_id'],
                'operation_sha256':self.f.work['operation_sha256'],
                'status':'PASS','issue_id':issue['id'],
                'root_cause':issue['root_cause'],
                'before_sha256':issue['before_sha256'],
                'after_sha256':issue['after_sha256']}
            event['record_hash']=sha(canonical(event))
            self.f.records.append(event)
        self.f.controller.audit_path(self.f.asset).write_bytes(
            b''.join(canonical(row)+bytes([10]) for row in self.f.records))
        self.f.controller._state['last_audit_hash']=self.f.records[-1]['record_hash']

    def context(self):
        return {'inventory':self.f.inv,'plan':self.f.plan,
                'controller':self.f.controller,'asset':self.f.asset,
                'step':self.f.step,'work':self.f.work,
                'source_loader':lambda path:Path(path).read_bytes()}

    def row(self,rid):
        return inspect(self.context(),rid)

    def test_five_source_literal_oracles_and_no_false_operational_pass(self):
        self.assertEqual(len(RULES),5)
        for rid in RULES:
            with self.subTest(rid=rid):
                result=self.row(rid)
                self.assertTrue(result['evidence_complete'],rid)
                self.assertEqual(set(result['checks']),set(RULES[rid]))
                self.assertTrue(all(result['checks'].values()),
                                (rid,result['checks']))
                self.assertFalse(result['advancement_authorized'])
                self.assertEqual(result['fivem_runtime'],'UNVERIFIED')
                packet=build_packet(self.context(),rid)
                self.assertEqual(packet['mg0']['result'],'UNKNOWN')
                if rid in ('AAA-200-T-198','AAA-200-T-199'):
                    self.assertIn(rid,FULL_LITERAL_REVIEWED)
                    self.assertEqual(packet['rule']['result'],'PASS')
                else:
                    self.assertEqual(packet['rule']['result'],'UNKNOWN')
                    self.assertNotIn(rid,FULL_LITERAL_REVIEWED)

    def test_original_blender_envelope_not_just_magic(self):
        self.assertTrue(blender_blocks(blender_envelope()))
        for bad in (b'BLENDER',b'BLENDER-v300',
                    b'BLENDER-v300'+b'DATA'+b'\xff'*30,
                    blender_envelope()[:-2]):
            self.assertFalse(blender_blocks(bad))
        self.source=b'BLENDER-fake-corrupt-body'
        self.delivery_plan['source_sha256']=sha(self.source)
        self.fixture.docs['P8_MAINTENANCE_GUIDE']['source_sha256']=sha(self.source)
        self.refresh()
        self.assertFalse(self.row('AAA-200-T-193')['checks'][
            'editable_source_has_blender_block_structure_not_just_magic_header'])
        self.assertFalse(self.row('AAA-200-T-191')['checks'][
            'independently_parsed_real_native_geometry_and_original_manifest_consistent'])

    def test_blender_dna1_structure_rejects_spoofed_metadata_and_bad_blocks(self):
        original=blender_envelope()
        self.assertTrue(blender_blocks(original))
        for forged in (
            original.replace(b'DNA1',b'DZZ1',1),
            original.replace(b'SDNA',b'FAKE',1),
            original.replace(b'STRC',b'FAIL',1),
            original.replace(b'TLEN',b'FAKE',1),
            original.replace(b'NAME',b'FAIL',1),
            original.replace(b'OB'+bytes(2),b'!!'+bytes(2),1),
            original.replace(b'Thing',b'Thing'+bytes((0,)),1),
            original+b'extraneous',
        ):
            with self.subTest(sample=forged[:25]):
                self.assertFalse(blender_blocks(forged))

    def test_t198_producer_claim_does_not_override_missing_method_fix(self):
        self.after_script=b'def correct_origin(vertices):\n    return vertices\n'
        self.fixture.docs['P8_METHOD_CHANGE']['after_sha256']=sha(self.after_script)
        self.refresh()
        row=self.row('AAA-200-T-198')
        self.assertFalse(row['checks'][
            'original_after_geometry_corrects_same_recurring_cause_within_source_limit'])
        self.assertEqual(build_packet(self.context(),'AAA-200-T-198')[
            'rule']['result'],'FAIL')
        self.assertFalse(build_packet(self.context(),'AAA-200-T-198')[
            'mg0']['result']=='PASS')

    def test_wrong_manifest_hash_refuses_T191(self):
        self.delivery_plan['export_sha256']='f'*64
        self.refresh()
        self.assertFalse(self.row('AAA-200-T-191')['checks'][
            'independently_parsed_real_native_geometry_and_original_manifest_consistent'])

    def test_guide_with_extraneous_claims_refuses_T195(self):
        self.fixture.docs['P8_MAINTENANCE_GUIDE']['fivem_verified']=True
        self.refresh()
        self.assertFalse(self.row('AAA-200-T-195')['checks'][
            'original_guide_binds_exact_editable_and_native_source_sha'])

    def test_repeated_labels_without_original_geometry_correction_refuse_T198(self):
        self.root_policy['target_bbox_min']=[0.5,0,0]
        self.refresh()
        self.assertFalse(self.row('AAA-200-T-198')['checks'][
            'original_after_geometry_corrects_same_recurring_cause_within_source_limit'])

    def test_method_labels_without_measured_fix_refuse_T199(self):
        self.fixture.docs['P8_METHOD_CHANGE']['verification_method']='unverified screenshot'
        self.refresh()
        self.assertFalse(self.row('AAA-200-T-199')['checks'][
            'changed_method_and_corrected_original_geometry_bound_to_same_current_operation'])

    def test_history_without_current_original_audit_findings_is_not_recurrence(self):
        self.f.rebuild()
        self.assertFalse(self.row('AAA-200-T-198')['checks'][
            'recurrent_original_defect_events_and_precorrection_geometry_authenticated'])

    def test_audit_recheck_not_substitutable_with_producer_json(self):
        rows=[r for r in self.f.records if r.get('event')!='QUALITY_RECHECK']
        self.f.records=rows
        from test_c07_positive_native_process import canonical
        self.f.controller.audit_path(self.f.asset).write_bytes(
            b''.join(canonical(r)+bytes([10]) for r in rows))
        self.f.controller._state['last_audit_hash']=rows[-1]['record_hash']
        self.assertFalse(self.row('AAA-200-T-198')['checks'][
            'original_after_geometry_corrects_same_recurring_cause_within_source_limit'])

    def test_second_case_method_replay_must_match_original_triangles(self):
        self.fixed_b=glb([(0,0,0),(0,1,0),(1,0,0)],[(0,1,2)])
        self.fixture.docs['P8_DEFECT_HISTORY']['issues'][1]['after_sha256']=sha(self.fixed_b)
        self.refresh()
        self.assertFalse(self.row('AAA-200-T-198')['checks'][
            'original_after_geometry_corrects_same_recurring_cause_within_source_limit'])

    def test_duplicate_history_rows_same_original_cannot_prove_recurrence(self):
        self.fixture.docs['P8_DEFECT_HISTORY']['issues'][1]['before_sha256']=sha(self.before)
        self.refresh()
        row=self.row('AAA-200-T-198')
        self.assertFalse(row['checks'][
            'recurrent_original_defect_events_and_precorrection_geometry_authenticated'])
        self.assertFalse(row['checks'][
            'original_after_geometry_corrects_same_recurring_cause_within_source_limit'])

    def test_second_original_case_geometry_without_defect_rejects_recurrence(self):
        self.case_b=self.export
        self.fixture.docs['P8_DEFECT_HISTORY']['issues'][1]['before_sha256']=sha(self.case_b)
        self.refresh()
        self.assertFalse(self.row('AAA-200-T-198')['checks'][
            'recurrent_original_defect_events_and_precorrection_geometry_authenticated'])

    def test_historical_claim_without_original_case_artifact_rejected(self):
        self.f.plan['p678_evidence_contract']['original_artifact_sha256'].pop(
            'P8_DEFECT_CASE_B')
        self.f.rebuild()
        self.assertFalse(self.row('AAA-200-T-198')['checks'][
            'recurrent_original_defect_events_and_precorrection_geometry_authenticated'])

    def test_cosmetic_ast_change_is_not_a_causal_method_fix(self):
        self.after_script=b'def run(): return 1\\n'
        self.fixture.docs['P8_METHOD_CHANGE']['after_sha256']=sha(self.after_script)
        self.refresh()
        self.assertFalse(self.row('AAA-200-T-199')['checks'][
            'original_before_and_after_method_code_sha_and_valid_python_ast_reopened'])

    def test_wrong_offset_against_real_triangles_fails(self):
        self.after_script=(b'def correct_origin(vertices):\n'
            b'    return [[p[0]-0.4,p[1],p[2]] for p in vertices]\n')
        self.fixture.docs['P8_METHOD_CHANGE']['after_sha256']=sha(self.after_script)
        self.refresh()
        self.assertFalse(self.row('AAA-200-T-199')['checks'][
            'changed_method_and_corrected_original_geometry_bound_to_same_current_operation'])

    def test_arbitrary_or_malicious_python_not_executed(self):
        from c07_p8_delivery_macro_full_review import _safe_origin_formula
        bad=(b'import os\\ndef correct_origin(vertices): return vertices\\n',
             b'def correct_origin(vertices): return __import__("os").system("id")\\n',
             b'def correct_origin(vertices):\n'
             b'  return [[evil(p[0]),p[1],p[2]] for p in vertices]\\n')
        for script in bad:
            with self.subTest(script=script):
                self.assertIsNone(_safe_origin_formula(script))

    def test_changed_vertex_topology_not_proof_of_method_effect(self):
        self.export=glb([(0,0,0),(1,0,0),(0,1,0),(0,0,1)],
                        [(0,1,3)])
        self.delivery_plan['export_sha256']=sha(self.export)
        self.fixture.docs['P8_MAINTENANCE_GUIDE']['export_sha256']=sha(self.export)
        for issue in self.fixture.docs['P8_DEFECT_HISTORY']['issues']:
            issue['after_sha256']=sha(self.export)
        self.refresh()
        self.assertFalse(self.row('AAA-200-T-199')['checks'][
            'changed_method_and_corrected_original_geometry_bound_to_same_current_operation'])

    def test_untampered_exact_current_operation_source_sha_required(self):
        (self.f.root/'delivery.zip').write_bytes(b'fake archive')
        with self.assertRaises((ValueError,OSError,AssertionError)):
            build_packet(self.context(),'AAA-200-T-191')

if __name__=='__main__':
    unittest.main()

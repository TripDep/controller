"""R140 synthetic adversarial fixtures. Tests cannot approve a real asset or MG0."""
import copy
import json
import struct
import unittest
import zlib
from pathlib import Path
from c07_a10_c10_original_evidence import (
    inspect, original_image, IDS, TEXT, NOTE_SCHEMA, CONTRACT_SCHEMA, ResearchBlocked)
from c07_positive_native_process import NativeEvidenceBlocked
from test_c07_positive_native_process import Tests as Fixture, sha

def png(seed):
    w=h=2
    raw=b''.join(bytes([0])+bytes([seed%200,seed%200+1,seed%200+2])*w
                 for _ in range(h))
    def c(kind,payload):
        return struct.pack('>I',len(payload))+kind+payload+struct.pack('>I',
               zlib.crc32(kind+payload)&0xffffffff)
    ihdr=struct.pack('>IIBBBBB',w,h,8,2,0,0,0)
    return bytes((137,80,78,71,13,10,26,10))+c(b'IHDR',ihdr)+c(b'IDAT',zlib.compress(raw))+c(b'IEND',b'')

def note(**fields):
    return json.dumps(dict(fields,schema=NOTE_SCHEMA),ensure_ascii=False).encode()

class R140Test(unittest.TestCase):
    def setUp(self):
        self.fx=Fixture('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f=self.fx
        self.f.plan['operation']['action']='Construct native asset'
        for n,t in TEXT.items():
            rid=f"AAA-200-{'A' if n<=10 else 'C'}-{n:03}"
            self.f.inv['rules'][rid]={
              'family':'AAA-200','catalog_number':n,
              'catalog_section':'A' if n<=10 else 'C',
              'catalog_phase':'P0','requirement':t,
              'requirement_sha256':sha(t.encode()),'source_sha256':'c'*64}
        self.contents={
          'PHOTO_FRONT':png(15),
          'PHOTO_SIDE':png(55),
          'PHOTO_REAR':png(95),
          'DOC_PLAN':b'%PDF-1.7\ntechnical plan\n%%EOF',
          'DOC_SECTION':b'%PDF-1.7\ncross section\n%%EOF',
          'DOC_CONSTRUCTION':b'%PDF-1.7\nconstruction sections\n%%EOF',
          'IMAGE_MATERIAL':png(125),
          'NOTE_OBJECTIVE':note(
              goal='Model the exact garden gate',asset='TEST',
              action='Construct native asset',deliverables=['scene.glb'],
              tasks=['model','export'],constraints=['preserve protected geometry'],
              protected_assets=['R98 original'],scope_changed=False,
              claim_status='WIP',fact_source_hashes=['d'*64],
              inferences=['approx ratio'],unverified_assumptions=['world z'],
              alternative_costs={'minimal':1,'complex':12},
              selected_method='minimal'),
          'NOTE_PROPORTIONS':note(width_m=2,height_m=1,depth_m=2,ratio_wh=2),
          'NOTE_CONSTRUCTION':note(members=['truss','pillar'],connections=['pillar-to-beam']),
          'NOTE_MATERIALS':note(physical_classes=['wood','stone'],
                                   image_sha256=sha(png(125))),
          'NOTE_HISTORY':note(period='Ming',place='Suzhou',culture='Chinese',
                              architectural_identity='classical garden'),
          'NOTE_LICENSE':note(license='CC BY 4.0',author='Example author',
                               license_url='https://example.com/cc-license',
                               covered_sha256=[sha(png(15))]),
          'NOTE_QA':note(status='PENDING',failure_classes=['intersection'],
                         independent_evidence_shas=['b'*64],reviewer='scanner',
                         production_delta=2,completion_metric='DELIVERABLE_ORIGINAL_BYTES'),
        }
        self.index()
        self.save_files()

    def index(self):
        self.contents['NOTE_REFERENCE_INDEX']=note(
           photo_source_url='https://example.com/reference',work_asset='TEST',
           technical_drawings_availability='PRESENT',
           structural_roles=['DOC_PLAN','DOC_SECTION'],
           aesthetic_roles=['PHOTO_FRONT','PHOTO_SIDE'],
           indexed_sha256={
             'PHOTO_FRONT':sha(self.contents['PHOTO_FRONT']),
             'DOC_PLAN':sha(self.contents['DOC_PLAN']),
             'DOC_SECTION':sha(self.contents['DOC_SECTION']),
           })

    def save_files(self):
        for role,data in self.contents.items():
            ext='.png' if role.startswith('PHOTO') or role=='IMAGE_MATERIAL' else (
                '.pdf' if role.startswith('DOC') else '.json')
            self.f.add_item(role,role.lower()+ext,data)
        self.contract()
    
    def contract(self):
        self.f.plan['reference_evidence_contract']={
            'schema':CONTRACT_SCHEMA,
            'artifact_sha256':{role:sha(v) for role,v in self.contents.items()}}
        self.f.rebuild()

    def read(self):
        return inspect(self.f.inv,self.f.plan,self.f.controller,
                       self.f.asset,self.f.step,self.f.work,
                       source_loader=lambda name:Path(name).read_bytes())

    def test_all_twenty_source_ids_have_three_distinct_factual_checks(self):
        r=self.read()
        self.assertEqual(r['source_rules_examined'],20)
        self.assertEqual(r['native_conditions_evaluated'],60)
        self.assertEqual(set(r['rules']),set(IDS))
        self.assertEqual(r['full_rule_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        names=[]
        for rid,x in r['rules'].items():
            with self.subTest(rid=rid):
                self.assertEqual(len(x['native_original_file_criteria']),3)
                self.assertEqual(x['full_rule_pass'],False)
                self.assertEqual(x['individual_mg0'],'UNKNOWN')
                self.assertEqual(x['owner_approval'],'UNKNOWN')
                names+=list(x['native_original_file_criteria'])
        self.assertEqual(len(names),len(set(names)))

    def test_every_original_literal_rule_changed_fails_closed(self):
        for rid in IDS:
            old=self.f.inv['rules'][rid]['requirement']
            self.f.inv['rules'][rid]['requirement']='FAKE PASS'
            with self.subTest(rid=rid):
                with self.assertRaisesRegex(ResearchBlocked,'R140_ORIGINAL_RULE_CHANGED'):
                    self.read()
            self.f.inv['rules'][rid]['requirement']=old

    def test_raw_photo_mutation_without_audit_fails_closed(self):
        (self.f.root/'photo_front.png').write_bytes(b'FAKE IMAGE')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.read()

    def test_genuine_png_crc_corruption_is_not_valid_image(self):
        raw=bytearray(png(4))
        raw[25]^=7
        self.assertIsNone(original_image(bytes(raw)))

    def test_new_image_bytes_without_pre_D_contract_is_unverified(self):
        self.f.plan['reference_evidence_contract']['artifact_sha256'].pop('PHOTO_REAR')
        self.f.rebuild()
        r=self.read()['rules']['AAA-200-C-026']
        self.assertFalse(r['native_original_file_criteria']['three_distinct_angular_original_images'])
        self.assertFalse(r['native_original_file_criteria']['photo_shas_explicit_in_pre_d_contract'])

    def test_pre_d_license_record_not_an_external_license_verification(self):
        x=self.read()['rules']['AAA-200-C-029']
        self.assertTrue(all(x['native_original_file_criteria'].values()))
        self.assertEqual(x['independent_provenance_or_artistic_verification'],'UNKNOWN')
        self.assertEqual(x['full_rule_pass'],False)

    def test_no_drawing_prevents_technical_source_positive(self):
        del self.f.items['DOC_PLAN']
        self.f.rebuild()
        x=self.read()['rules']['AAA-200-C-022']
        self.assertFalse(x['native_original_file_criteria']['original_plan_pdf_bytes_present'])

    def test_false_complete_label_does_not_pass_rule_9(self):
        d=json.loads(self.contents['NOTE_OBJECTIVE'])
        d['claim_status']='DONE'
        self.contents['NOTE_OBJECTIVE']=json.dumps(d).encode()
        self.f.add_item('NOTE_OBJECTIVE','note_objective.json',self.contents['NOTE_OBJECTIVE'])
        self.contract()
        x=self.read()['rules']['AAA-200-A-009']
        self.assertFalse(x['native_original_file_criteria']['explicit_full_completion_test_not_forged'])

    def test_license_reference_sha_must_match_actual_original_file(self):
        d=json.loads(self.contents['NOTE_LICENSE'])
        d['covered_sha256']=['e'*64]
        self.contents['NOTE_LICENSE']=json.dumps(d).encode()
        self.f.add_item('NOTE_LICENSE','note_license.json',self.contents['NOTE_LICENSE'])
        self.contract()
        row=self.read()['rules']['AAA-200-C-029']
        self.assertFalse(row['native_original_file_criteria']['specific_original_reference_sha_listed'])
        self.assertFalse(row['full_rule_pass'])

    def test_reference_index_cannot_claim_unregistered_image(self):
        d=json.loads(self.contents['NOTE_REFERENCE_INDEX'])
        d['indexed_sha256']['GHOST_REFERENCE']='a'*64
        self.contents['NOTE_REFERENCE_INDEX']=json.dumps(d).encode()
        self.f.add_item('NOTE_REFERENCE_INDEX','note_reference_index.json',
                        self.contents['NOTE_REFERENCE_INDEX'])
        self.contract()
        row=self.read()['rules']['AAA-200-C-030']
        self.assertFalse(row['native_original_file_criteria']['source_index_sha_matches_original_artifact_bytes'])

    def test_self_reported_production_delta_is_not_measured_output(self):
        row=self.read()['rules']['AAA-200-A-003']
        self.assertFalse(row['native_original_file_criteria'][
            'original_baseline_export_byte_delta_observed'])

    def test_qa_evidence_digest_not_present_in_original_files_is_not_independent(self):
        row=self.read()['rules']['AAA-200-A-007']
        self.assertFalse(row['native_original_file_criteria'][
            'defect_reproduction_evidence_original_bytes'])

    def test_cross_attempt_controller_reservation_replay_fails(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='f'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.read()

if __name__=='__main__':unittest.main()

"""R149: all 100 late canonical Qs and immutable non-excludable G2/G3/G4 gates."""
import copy
import json
import unittest
from pathlib import Path
from c07_q100_closing_original_witnesses import (
    inspect,IDS,ROLES,topic,CONTRACT,Blocked)
from c07_q200_original_witnesses import digest
from test_c07_q200_original_witnesses import Q200Witness, bjson
from test_c07_a10_c10_original_evidence import png
from test_c07_positive_native_process import sha
from c07_positive_native_process import NativeEvidenceBlocked

class Closing100(Q200Witness):
    def setUp(self):
        super().setUp()
        self.add('Q100_REGRESSION_AUDIT','late_regression.json',
                 bjson({'failure_cases':['bad-surface','overlap']}))
        self.add('Q100_OWNER_DECISIONS','owner_pending.json',
                 bjson({'pending_decision_ids':['final look','garden acceptance']}))
        self.add('Q100_DYNAMIC_DISCOVERY','late_dynamic.json',
                 bjson({'new_material_questions':['how does leaf sway in FiveM?']}))
        for i,role in enumerate(('FRONT','REAR','LEFT','RIGHT','TOP','UNDERSIDE'),1):
            self.add('VISUAL_VIEW_'+role,role.lower()+'.png',png(i*23))
        self.make_late_slots()
    def make_late_slots(self):
        views={kind:sha(self.data['VISUAL_VIEW_'+kind])
               for kind in ('FRONT','REAR','LEFT','RIGHT','TOP','UNDERSIDE')}
        regression=json.loads(self.data['Q100_REGRESSION_AUDIT'])
        fingerprints={
            'REGRESSION':digest(regression),
            'VISUAL':digest(views),
            'ADVERSARIAL':digest({'images':views,'regression':regression}),
            'OWNER':digest(json.loads(self.data['Q100_OWNER_DECISIONS'])),
            'DISCOVERY':digest(json.loads(self.data['Q100_DYNAMIC_DISCOVERY']))
        }
        slots={}
        for n in range(201,301):
            rid='Q-'+str(n).zfill(3)
            domain=topic(n);role=ROLES[domain]
            slots[rid]={
                'question_sha256':self.f.inv['rules'][rid]['requirement_sha256'],
                'source_role':role,'source_sha256':self.f.items[role]['sha256'],
                'measured_fingerprint':fingerprints[domain],
                'claim_status':'OBSERVATION_ONLY'
            }
        self.f.plan['question_100_original_witnesses']={
            'schema':CONTRACT,'rules':slots}
        self.f.rebuild()
    def late(self):
        f=self.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
            source_loader=lambda p:Path(p).read_bytes())
    def test_all_100_original_questions_have_source_native_receipts(self):
        d=self.late()
        self.assertEqual(d['source_question_count'],100)
        self.assertEqual(set(d['rules']),set(IDS))
        self.assertEqual(d['source_witnesses_observed'],100)
        self.assertEqual(d['semantic_passes'],0)
        self.assertEqual(d['individual_mg0_passes'],0)
        self.assertFalse(d['advancement_authorized'])
        for rid in IDS:
            x=d['rules'][rid]
            self.assertTrue(x['native_original_source_witness'])
            self.assertEqual(x['individual_mg0'],'UNKNOWN')
            self.assertEqual(x['semantic_verdict'],'UNKNOWN')
            self.assertFalse(x['advancement_authorized'])
    def test_dynamic_280_285_and_close_286_300_are_never_automatically_approved(self):
        d=self.late()
        self.assertEqual(d['additional_dynamic_questions_required'],6)
        self.assertEqual(d['closing_questions_required'],15)
        for n in range(280,286):
            self.assertTrue(d['rules']['Q-'+str(n).zfill(3)]['dynamic_discovery_mandatory'])
        for n in range(286,301):
            item=d['rules']['Q-'+str(n).zfill(3)]
            self.assertTrue(item['closing_gate_mandatory'])
            self.assertEqual(item['individual_mg0'],'UNKNOWN')
            self.assertEqual(item['owner_approval'],'UNKNOWN')
    def test_each_of_100_source_question_tamper_is_blocked(self):
        for rid in IDS:
            original=self.f.inv['rules'][rid]['requirement']
            self.f.inv['rules'][rid]['requirement']='fake owner PASS'
            with self.subTest(question=rid):
                with self.assertRaisesRegex(Blocked,'R149_CHANGED_ORIGINAL_Q_SOURCE'):
                    self.late()
            self.f.inv['rules'][rid]['requirement']=original
    def test_each_of_100_question_source_sha_tamper_is_blocked(self):
        for rid in IDS:
            original=self.f.inv['rules'][rid]['source_sha256']
            self.f.inv['rules'][rid]['source_sha256']='f'*64
            with self.subTest(question=rid):
                with self.assertRaisesRegex(Blocked,'R149_CHANGED_ORIGINAL_Q_SOURCE'):
                    self.late()
            self.f.inv['rules'][rid]['source_sha256']=original
    def test_fake_yes_is_not_witness_or_semantic_pass(self):
        self.f.plan['question_100_original_witnesses']['rules']['Q-299']['claim_status']='YES'
        self.f.rebuild()
        d=self.late()
        self.assertFalse(d['rules']['Q-299']['native_original_source_witness'])
        self.assertEqual(d['semantic_passes'],0)
        self.assertEqual(d['rules']['Q-299']['semantic_verdict'],'UNKNOWN')
    def test_missing_dynamic_discovery_source_keeps_unknown(self):
        del self.f.items['Q100_DYNAMIC_DISCOVERY']
        self.f.rebuild()
        d=self.late()
        self.assertFalse(d['rules']['Q-280']['native_original_source_witness'])
        self.assertEqual(d['rules']['Q-300']['individual_mg0'],'UNKNOWN')
    def test_actual_raster_byte_tamper_is_blocked(self):
        (self.f.root/'front.png').write_bytes(b'fake view')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.late()
    def test_replay_different_original_operation_is_blocked(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='f'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.late()
    def test_unenrolled_extra_Q1_requires_previous_cohort_gate(self):
        self.f.plan['question_100_original_witnesses']['rules']['Q-001']={
             'claim_status':'OBSERVATION_ONLY'}
        self.f.rebuild()
        with self.assertRaisesRegex(Blocked,'R149_EXTRA_UNREGISTERED_QUESTION'):
            self.late()
if __name__=='__main__':unittest.main()

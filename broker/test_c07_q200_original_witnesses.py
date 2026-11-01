"""R148: 200 question-specific original-source witness gates, anti-replay tests."""
import copy
import json
import unittest
from pathlib import Path
from c07_q200_original_witnesses import (
    inspect, IDS, DOMAINS, ROLES, SCHEMA, CONTRACT, digest, OriginalQuestionBlocked)
from test_c07_questions_300 import sample
from test_c07_positive_native_process import Tests as Fixture,sha
from test_c07_native_output_oracle import two_triangles
from test_c07_a10_c10_original_evidence import png
from c07_native_output_oracle import read_mesh_geometry
from c07_positive_native_process import NativeEvidenceBlocked

def bjson(obj):return json.dumps(obj,sort_keys=True,ensure_ascii=False).encode()
class Q200Witness(unittest.TestCase):
    def setUp(self):
        self.fx=Fixture('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f=self.fx
        _,_,master=sample()
        self.f.master=master
        (self.f.root/'MASTER.md').write_bytes(master)
        self.f.inv['canonical_master_sha256']=sha(master)
        self.f.inv['source_digests']['master']=sha(master)
        self.f.work['master_sha256']=sha(master)
        self.f.plan['master_sha256']=sha(master)
        self.f.inv['families']={'QUESTIONS_300':['Q-'+str(n).zfill(3)
                                     for n in range(1,301)]}
        self.qbank={}
        for n in range(1,301):
            rid='Q-'+str(n).zfill(3)
            original='What must be checked in question '+str(n)+'?'
            self.qbank[rid]=original
            self.f.inv['rules'][rid]={
                'family':'QUESTIONS_300','source':'master',
                'requirement':original,
                'source_sha256':sha(master),
                'requirement_sha256':sha(original.encode()),
                'required_mg0':True}
        self.f.add_item('NATIVE_EXPORT','scene.glb',two_triangles())
        self.data={}
        self.add('Q200_GOAL_BRIEF','goal.json',bjson({
            'asset':'TEST','deliverables':['geometry export','editable source']}))
        self.add('REFERENCE_IMAGE','reference.png',png(5))
        self.add('Q200_DEPENDENCY_REGISTER','deps.json',bjson({
            'dependency_sha256':{k:sha(b'dependency-original')
                  for k in self.f.plan['dependency_files']}}))
        self.add('Q200_STRUCTURAL_QA','structure.json',bjson({
            'component_ids':['column 01','beam 01']}))
        self.add('Q200_PLAYER_QA','player.json',bjson({
            'player_height_m':1.75}))
        self.add('P8_REQUIRED_FILES','required.json',bjson({
            'files':['SOURCE_EDITABLE','NATIVE_EXPORT']}))
        self.add('MATERIAL_REFERENCE_IMAGE','material.png',png(15))
        self.add('Q200_REGRESSION_REPORT','regressions.json',
                 bjson({'failure_modes':['missing collision']}))
        self.rebuild()
    def add(self,role,path,data):
        self.data[role]=data
        self.f.add_item(role,path,data)
    def rebuild(self):
        fingerprint={
         'GOAL':digest(json.loads(self.data['Q200_GOAL_BRIEF'])),
         'REFERENCE':sha(self.data['REFERENCE_IMAGE']),
         'DEPENDENCIES':digest(json.loads(self.data['Q200_DEPENDENCY_REGISTER'])),
         'GEOMETRY':digest(read_mesh_geometry(two_triangles())),
         'STRUCTURAL':digest({'source':json.loads(self.data['Q200_STRUCTURAL_QA']),
                   'geometry':read_mesh_geometry(two_triangles())}),
         'PLAYER':digest({'source':json.loads(self.data['Q200_PLAYER_QA']),
                   'geometry':read_mesh_geometry(two_triangles())}),
         'COMPLETENESS':digest(json.loads(self.data['P8_REQUIRED_FILES'])),
         'MATERIAL':sha(self.data['MATERIAL_REFERENCE_IMAGE']),
         'PACKAGE':self.f.items['DELIVERY_PACKAGE']['sha256'],
         'FAILURE':digest({'source':json.loads(self.data['Q200_REGRESSION_REPORT']),
                            'original_current_attempt_failures':[]})
        }
        witnesses={}
        for n,rid in enumerate(IDS,1):
            role=ROLES[DOMAINS[(n-1)//20]]
            witness=self.f.items.get(role)
            self.assertIsNotNone(witness)
            witnesses[rid]={
                'question_sha256':self.f.inv['rules'][rid]['requirement_sha256'],
                'source_role':role,'source_sha256':witness['sha256'],
                'measured_fingerprint':fingerprint[DOMAINS[(n-1)//20]],
                'claim_status':'OBSERVATION_ONLY'
            }
        self.f.plan['question_200_original_witnesses']={
            'schema':CONTRACT,'rules':witnesses}
        self.f.rebuild()
    def scan(self):
        f=self.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
              source_loader=lambda p:Path(p).read_bytes())
    def test_every_200_source_question_has_distinct_original_byte_witness(self):
        r=self.scan()
        self.assertEqual(r['source_question_count'],200)
        self.assertEqual(r['independent_source_categories'],10)
        self.assertEqual(r['authentic_witnesses'],200)
        self.assertEqual(len(r['rules']),200)
        self.assertEqual(set(r['rules']),set(IDS))
        self.assertEqual(r['verified_semantic_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
        self.assertFalse(r['advancement_authorized'])
        for rid in IDS:
            with self.subTest(question=rid):
                row=r['rules'][rid]
                self.assertTrue(row['original_file_readback_bound'])
                self.assertTrue(row['domain_machine_fingerprint_matches'])
                self.assertEqual(row['semantic_verdict'],'UNKNOWN')
                self.assertEqual(row['individual_mg0'],'UNKNOWN')
                self.assertEqual(row['owner_approval'],'UNKNOWN')
    def test_each_of_200_canonical_questions_tamper_fails_closed(self):
        for rid in IDS:
            old=self.f.inv['rules'][rid]['requirement']
            self.f.inv['rules'][rid]['requirement']='fake canonical requirement?'
            with self.subTest(question=rid):
                with self.assertRaisesRegex(OriginalQuestionBlocked,
                    'R148_CHANGED_ORIGINAL_QUESTION'):
                    self.scan()
            self.f.inv['rules'][rid]['requirement']=old
    def test_each_of_200_original_sha_tamper_fails_closed(self):
        for rid in IDS:
            old=self.f.inv['rules'][rid]['source_sha256']
            self.f.inv['rules'][rid]['source_sha256']='f'*64
            with self.subTest(question=rid):
                with self.assertRaisesRegex(OriginalQuestionBlocked,
                    'R148_CHANGED_ORIGINAL_QUESTION'):
                    self.scan()
            self.f.inv['rules'][rid]['source_sha256']=old
    def test_altered_original_GLTF_binary_blocks_all_replay(self):
        (self.f.root/'scene.glb').write_bytes(b'altered')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.scan()
    def test_producer_yes_claim_cannot_certify_semantic(self):
        self.f.plan['question_200_original_witnesses']['rules']['Q-001']['claim_status']='YES'
        self.f.rebuild()
        r=self.scan()
        self.assertFalse(r['rules']['Q-001']['domain_machine_fingerprint_matches'])
        self.assertEqual(r['rules']['Q-001']['semantic_verdict'],'UNKNOWN')
    def test_undeclared_witness_role_not_accepted(self):
        self.f.plan['question_200_original_witnesses']['rules']['Q-100']['source_role']='SOURCE_EDITABLE'
        self.f.rebuild()
        r=self.scan()
        self.assertFalse(r['rules']['Q-100']['original_file_readback_bound'])
        self.assertEqual(r['verified_semantic_passes'],0)
    def test_missing_original_contract_produces_no_false_positive(self):
        del self.f.plan['question_200_original_witnesses']
        self.f.rebuild()
        r=self.scan()
        self.assertEqual(r['authentic_witnesses'],0)
        self.assertEqual(r['verified_semantic_passes'],0)
        self.assertEqual(r['individual_mg0_passes'],0)
    def test_unknown_extra_question_prevented(self):
        self.f.plan['question_200_original_witnesses']['rules']['Q-201']={
           'claim_status':'OBSERVATION_ONLY'}
        self.f.rebuild()
        with self.assertRaisesRegex(OriginalQuestionBlocked,
             'R148_UNREGISTERED_QUESTION_EVIDENCE_ID'):
            self.scan()
    def test_old_attempt_evidence_reuse_blocks(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='f'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.scan()
    def test_master_byte_edit_detected(self):
        (self.f.root/'MASTER.md').write_bytes(b'not actual source')
        with self.assertRaisesRegex(OriginalQuestionBlocked,'R148_LIBRARY_MASTER_CURRENT_SHA_CHANGED'):
            self.scan()
if __name__=='__main__':unittest.main()

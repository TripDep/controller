"""R151 frozen 200 / all 72 composite source-byte and original-proof attacks.

Synthetic fixtures only: never count these tests as 3D QA or individual MG0.
"""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

import c07_r151_original_clause_proofs as r

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

class OriginalLineEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.ids = [f'AAA-200-{chr(65+(n-1)//10)}-{n:03}'
                    for n in range(1,201)]
        self.master = b'canonical-test-master'
        self.work = {'master_sha256':sha(self.master),
                     'attempt_id':'b'*64,'operation_sha256':'c'*64}
        self.plan = {'master_sha256':self.work['master_sha256']}
        rules = {}
        for n, rid in enumerate(self.ids):
            src = ('Check the objective.\n- Verify original bytes.\n'
                   if n == 0 else 'Rule text for '+rid)
            rules[rid] = {'family':'AAA-200', 'requirement':src,
                          'source_sha256':'a'*64,
                          'requirement_sha256':sha(src.encode())}
        for n in range(563):
            rid=f'EXTRA-{n:03}'
            src='Extra source '+rid
            rules[rid]={'family':'GOVERNANCE','requirement':src,
                        'source_sha256':'a'*64,
                        'requirement_sha256':sha(src.encode())}
        self.inventory = {'schema':'gg-effective-family-inventory-v1',
                          'rule_count':763,'rules':rules,
                          'canonical_master_sha256':self.work['master_sha256']}
        self.composites = set(self.ids[:72])
        self.comp_report = {
            'canonical_composite_count':72,
            'independently_verified_count':0,
            'advancement_authorized':False,
            'due_composites':{
                rid:{'source_sha256':rules[rid]['source_sha256'],
                     'requirement_sha256':rules[rid]['requirement_sha256'],
                     'independent_verifier_ready':False,
                     'subchecks':[{'subcheck_id':rid+':SC001'}],
                     'source_decomposition':'SOURCE_LIST_CANDIDATES_REVIEW_PENDING'}
                for rid in self.composites}}
        self.patches=[
            patch.object(r,'select',return_value=(self.ids,{})),
            patch.object(r,'composite_ids',return_value=self.composites),
            patch.object(r,'composite_inspect',return_value=self.comp_report)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.contract = r.compile_contract(self.inventory,self.plan)
        self.original = b'{"verified":true,"object":"sample"}'
        self.path = '/original/artifact/proof.json'
        self.registered = [('PROOF_JSON',self.path,sha(self.original),self.original)]
        self.reader = lambda path:self.original if path==self.path else b''
        self.line = self.contract['rows'][self.ids[0]]['lines'][0]

    def packet(self, **changes):
        base={'rule_id':self.ids[0],
              'line_id':self.line['line_id'],
              'line_sha256':self.line['line_sha256'],
              'requirement_sha256':self.inventory['rules'][self.ids[0]]['requirement_sha256'],
              'master_sha256':self.work['master_sha256'],
              'attempt_id':self.work['attempt_id'],
              'operation_sha256':self.work['operation_sha256'],
              'source_lane':'CONTROLLER_PROCESS',
              'evidence_role':'PROOF_JSON',
              'evidence_path':self.path,
              'evidence_sha256':sha(self.original),
              'answer':'YES'}
        return {**base,**changes}

    def assess(self,packets,reader=None,registered=None):
        return r.assess(self.contract,self.work,packets,
                        self.registered if registered is None else registered,
                        self.reader if reader is None else reader)

    def test_200_rule_sources_and_all_72_composites_have_lossless_spans(self):
        self.assertEqual(self.contract['source_rule_count'],200)
        self.assertEqual(self.contract['all_composite_source_rules'],72)
        self.assertEqual(len(self.contract['rows']),200)
        self.assertTrue(self.contract['all_source_bytes_accounted_for'])
        self.assertFalse(self.contract['all_semantic_obligations_reviewed'])
        self.assertEqual(self.contract['rows'][self.ids[0]]['source_line_count'],2)
        self.assertEqual(self.contract['rows'][self.ids[0]]['lines'][1]['start_byte'],
                         len('Check the objective.\n'.encode()))
        self.assertEqual(sum(x['composite_flag'] for x in self.contract['rows'].values()),72)

    def test_all_200_stay_unknown_when_original_evidence_absent(self):
        report=self.assess([])
        self.assertEqual(report['missing_source_line_witnesses'],
                         sum(self.contract['rows'][rid]['source_line_count']
                             for rid in self.ids))
        self.assertEqual(set(report['rule_status']),set(self.ids))
        self.assertEqual(set(report['rule_status'].values()),{'UNKNOWN'})
        self.assertEqual(report['full_rule_semantic_passes'],0)
        self.assertEqual(report['individual_mg0_passes'],0)
        self.assertFalse(report['advancement_authorized'])

    def test_genuine_original_byte_readback_is_not_full_semantic_pass(self):
        report=self.assess([self.packet()])
        self.assertEqual(report['original_proof_packets_reopened'],1)
        self.assertEqual(report['machine_format_probes_positive_not_semantic'],1)
        self.assertEqual(report['rule_status'][self.ids[0]],'UNKNOWN')
        self.assertEqual(report['full_rule_semantic_passes'],0)
        self.assertFalse(report['owner_approval_verified'])

    def test_no_is_fail_even_with_real_bytes(self):
        report=self.assess([self.packet(answer='NO')])
        self.assertEqual(report['result'],'FAIL')
        self.assertEqual(report['rule_status'][self.ids[0]],'FAIL')
        self.assertFalse(report['advancement_authorized'])

    def test_replay_wrong_attempt_and_operation_rejected(self):
        for changed in ({'attempt_id':'d'*64},
                        {'operation_sha256':'d'*64},
                        {'master_sha256':'d'*64},
                        {'line_sha256':'d'*64},
                        {'requirement_sha256':'d'*64}):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(r.UnverifiedLineEvidence,
                                            'SOURCE_LINE_OR_ATTEMPT_REPLAY'):
                    self.assess([self.packet(**changed)])

    def test_unregistered_path_and_rewritten_original_rejected(self):
        with self.assertRaisesRegex(r.UnverifiedLineEvidence,'NOT_REGISTERED'):
            self.assess([self.packet(evidence_path='/fake.json')])
        with self.assertRaisesRegex(r.UnverifiedLineEvidence,'REHASH'):
            self.assess([self.packet()],reader=lambda _:b'changed')
        with self.assertRaisesRegex(r.UnverifiedLineEvidence,'REHASH'):
            self.assess([self.packet(evidence_sha256='f'*64)])
        with self.assertRaisesRegex(r.UnverifiedLineEvidence,'REHASH'):
            self.assess([self.packet(evidence_role='OTHER')])

    def test_duplicate_unrelated_domain_and_fake_positive_rejected(self):
        with self.assertRaisesRegex(r.UnverifiedLineEvidence,'DUPLICATE'):
            self.assess([self.packet(),self.packet()])
        with self.assertRaisesRegex(r.UnverifiedLineEvidence,'UNRELATED_EVIDENCE_DOMAIN'):
            self.assess([self.packet(source_lane='GLB_GEOMETRY')])
        with self.assertRaisesRegex(r.UnverifiedLineEvidence,'ANSWER_ENUM'):
            self.assess([self.packet(answer='PASS')])
        with self.assertRaisesRegex(r.UnverifiedLineEvidence,'LINE_PACKET_SCHEMA'):
            self.assess([{**self.packet(),'work_pass':True}])

    def test_mutated_canonical_source_and_composite_binding_rejected(self):
        inv=copy.deepcopy(self.inventory)
        inv['rules'][self.ids[0]]['requirement']+=' forged'
        with self.assertRaisesRegex(r.UnverifiedLineEvidence,'CANONICAL_SOURCE_CHANGED'):
            r.compile_contract(inv,self.plan)
        self.comp_report['due_composites'][self.ids[0]]['requirement_sha256']='f'*64
        with self.assertRaisesRegex(r.UnverifiedLineEvidence,'COMPOSITE_CANONICAL_DRIFT'):
            r.compile_contract(self.inventory,self.plan)

    def test_all_72_composites_outside_first200_are_individually_enforced(self):
        # Regression: R151 formerly indexed external composite clauses but
        # silently omitted them from the expected source-line evidence.
        extras={f'EXTRA-{n:03}' for n in range(72)}
        self.composites.clear()
        self.composites.update(extras)
        self.comp_report['due_composites']={
            rid:{'source_sha256':self.inventory['rules'][rid]['source_sha256'],
                 'requirement_sha256':self.inventory['rules'][rid]['requirement_sha256'],
                 'independent_verifier_ready':False,
                 'subchecks':[{'subcheck_id':rid+':SC001'}],
                 'source_decomposition':'SOURCE_LIST_CANDIDATES_REVIEW_PENDING'}
            for rid in extras}
        contract=r.compile_contract(self.inventory,self.plan)
        self.assertEqual(len(contract['rows']),272)
        self.assertEqual(set(extras)-set(self.ids),extras)
        missing=r.assess(contract,self.work,[],self.registered,self.reader)
        self.assertEqual(missing['missing_source_line_witnesses'],
                         sum(x['source_line_count'] for x in contract['rows'].values()))
        self.assertEqual(set(missing['rule_status']),set(contract['rows']))
        rid=sorted(extras)[0]
        row=contract['rows'][rid]
        packet=self.packet(rule_id=rid,
            line_id=row['lines'][0]['line_id'],
            line_sha256=row['lines'][0]['line_sha256'],
            requirement_sha256=row['requirement_sha256'],
            source_lane=row['required_independent_lanes'][0],
            answer='NO')
        result=r.assess(contract,self.work,[packet],self.registered,self.reader)
        self.assertEqual(result['result'],'FAIL')
        self.assertEqual(result['rule_status'][rid],'FAIL')
        self.assertEqual(result['full_rule_semantic_passes'],0)
        self.assertFalse(result['advancement_authorized'])

    def test_original_controller_inspect_without_manifest_never_passes(self):
        controller=type('Controller',(),{})()
        controller.master=type('Master',(),{'read_bytes':lambda _:self.master})()
        state={'last_audit_hash':'a'*64,'active_step':{'step':'STEP0001'}}
        with patch.object(r,'_original_attempt',return_value=([], 'a'*64,state,'e'*64)),\
             patch.object(r,'_registered_artifacts',return_value=self.registered):
            report=r.inspect(self.inventory,self.plan,controller,'GARDEN','STEP0001',
                             self.work,source_loader=self.reader)
        self.assertEqual(report['source_rule_count'],200)
        self.assertEqual(report['all_composite_source_rules'],72)
        self.assertEqual(report['original_proof_packets_reopened'],0)
        self.assertFalse(report['manifest_present'])
        self.assertEqual(report['result'],'UNKNOWN')

    def test_registered_manifest_cross_attempt_replay_rejected(self):
        manifest={'schema':r.MANIFEST,'master_sha256':self.work['master_sha256'],
                  'attempt_id':'f'*64,
                  'operation_sha256':self.work['operation_sha256'],
                  'source_rule_ids_sha256':self.contract['source_rule_ids_sha256'],
                  'packets':[self.packet()]}
        raw=json.dumps(manifest).encode()
        entries=self.registered+[(r.ROLE,'/original/manifest.json',sha(raw),raw)]
        controller=type('Controller',(),{})()
        controller.master=type('Master',(),{'read_bytes':lambda _:self.master})()
        state={'last_audit_hash':'a'*64,'active_step':{'step':'STEP0001'}}
        with patch.object(r,'_original_attempt',return_value=([], 'a'*64,state,'e'*64)),\
             patch.object(r,'_registered_artifacts',return_value=entries):
            with self.assertRaisesRegex(r.UnverifiedLineEvidence,
                                        'MANIFEST_NOT_EXACT_CURRENT_ATTEMPT'):
                r.inspect(self.inventory,self.plan,controller,'GARDEN','STEP0001',
                          self.work,source_loader=self.reader)

if __name__=='__main__':
    unittest.main()

"""C07 R152: all 563 remaining canonical rules; exact-attempt source proof tests.

These tests establish source/proof integrity only: no live asset or individual
MG0, visual QA, owner approval, or full semantic PASS is claimed.
"""
import copy
import json
import unittest
from pathlib import Path

import c07_r152_remaining563_line_proofs as r
from c07_positive200_evidence import R122_FROZEN_IDS
from test_c07_positive_native_process import Tests as Fixture, sha

def data(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False).encode('utf-8')

class Remaining563(unittest.TestCase):
    def setUp(self):
        self.fx=Fixture('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        f=self.f=self.fx
        src=f.work['master_sha256']
        all_ids=list(sorted(R122_FROZEN_IDS))
        all_ids += [f'REMAIN-{n:03}' for n in range(1,564)]
        self.assertEqual(len(all_ids),763)
        self.assertEqual(len(set(all_ids)),763)
        f.inv['rules']={}
        f.inv['families']={'GOVERNANCE':all_ids}
        f.inv['family_count']=1
        for rid in all_ids:
            clause='Original source clause for '+rid
            f.inv['rules'][rid]={
                'family':'GOVERNANCE','source':'master',
                'requirement':clause,
                'requirement_sha256':sha(clause.encode('utf-8')),
                'source_sha256':src}
        f.inv['rule_count']=763
        f.rebuild()
        self.batches=r.cohorts(f.inv)
        self.assertEqual([len(x) for x in self.batches],[200,200,163])

    def check(self):
        f=self.f
        return r.inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
                         source_loader=lambda p:Path(p).read_bytes())

    def add_proof(self,index=0,answer='YES',rule_id=None,attempt=None):
        f=self.f
        contract=r.compile_contract(f.inv,f.plan,index)
        rid=rule_id or contract['selected'][0]
        original=f.inv['rules'][rid]
        first=contract['rows'][rid]['lines'][0] if rid in contract['rows'] else {
             'line_id':rid+':L00001','line_sha256':sha(
                 (original['requirement']).encode('utf-8'))}
        proof=data({'original':'measured','status':'UNREVIEWED'})
        f.add_item('R152_TEST_PROOF_'+str(index),'r152_proof_'+str(index)+'.json',proof)
        path=f.items['R152_TEST_PROOF_'+str(index)]
        lane=contract['rows'][contract['selected'][0]]['required_independent_lanes'][0]
        packet={'rule_id':rid,'line_id':first['line_id'],
                'line_sha256':first['line_sha256'],
                'requirement_sha256':original['requirement_sha256'],
                'master_sha256':f.work['master_sha256'],
                'attempt_id':f.work['attempt_id'],
                'operation_sha256':f.work['operation_sha256'],
                'source_lane':lane,
                'evidence_role':path['role'],
                'evidence_path':path['path'],
                'evidence_sha256':path['sha256'],
                'answer':answer}
        manifest={
            'schema':r.MANIFEST,'batch':index+1,
            'master_sha256':f.work['master_sha256'],
            'attempt_id':attempt or f.work['attempt_id'],
            'operation_sha256':f.work['operation_sha256'],
            'source_rule_ids_sha256':contract['source_rule_ids_sha256'],
            'packets':[packet],
        }
        f.add_item(r.BATCH_ROLES[index],
                   'r152_batch_'+str(index)+'.json',data(manifest))
        f.rebuild()
        return rid

    def test_remaining_200_200_163_are_exact_disjoint_and_exhaustive(self):
        c=[r.compile_contract(self.f.inv,self.f.plan,i) for i in range(3)]
        self.assertEqual([x['source_rule_count'] for x in c],[200,200,163])
        self.assertEqual(len(set().union(*(set(x['rows']) for x in c))),563)
        self.assertTrue(all(x['all_source_bytes_accounted_for'] for x in c))
        self.assertFalse(any(x['all_semantic_obligations_reviewed'] for x in c))
        self.assertEqual(set().union(*(set(x['rows']) for x in c)) |
                         set(R122_FROZEN_IDS),set(self.f.inv['rules']))

    def test_all_563_rules_start_unknown_without_registered_source_evidence(self):
        report=self.check()
        self.assertEqual(report['source_rule_count'],563)
        self.assertEqual(report['remaining_source_batches'],[200,200,163])
        self.assertEqual(report['result'],'UNKNOWN')
        self.assertEqual(report['manifest_batches_present'],0)
        self.assertEqual(report['original_proof_packets_reopened'],0)
        self.assertEqual(report['missing_source_line_witnesses'],563)
        self.assertEqual(report['full_rule_semantic_passes'],0)
        self.assertEqual(report['individual_mg0_passes'],0)
        self.assertFalse(report['advancement_authorized'])
        self.assertTrue(all(v=='UNKNOWN' for batch in report['batch_reports']
                            for v in batch['rule_status'].values()))

    def test_original_proofs_in_each_batch_observe_bytes_not_full_semantics(self):
        for index in range(3):
            self.add_proof(index)
        report=self.check()
        self.assertEqual(report['manifest_batches_present'],3)
        self.assertEqual(report['original_proof_packets_reopened'],3)
        self.assertEqual(report['missing_source_line_witnesses'],560)
        self.assertEqual(report['result'],'UNKNOWN')
        self.assertEqual(report['full_rule_semantic_passes'],0)
        self.assertEqual(report['individual_mg0_passes'],0)

    def test_real_admitted_no_in_last_batch_propagates_fail(self):
        rid=self.add_proof(2,answer='NO')
        report=self.check()
        self.assertEqual(report['result'],'FAIL')
        self.assertEqual(report['batch_reports'][2]['rule_status'][rid],'FAIL')
        self.assertFalse(report['advancement_authorized'])

    def test_false_positive_producer_pass_label_is_not_accepted(self):
        self.add_proof(0,answer='PASS')
        from c07_r151_original_clause_proofs import UnverifiedLineEvidence
        with self.assertRaisesRegex(UnverifiedLineEvidence,'ANSWER_ENUM'):
            self.check()

    def test_wrong_original_attempt_manifest_is_blocked(self):
        self.add_proof(1,attempt='f'*64)
        with self.assertRaisesRegex(r.InvalidRemainingCohort,
                                    'R152_MANIFEST_BATCH_ORIGINAL_ATTEMPT_REPLAY'):
            self.check()

    def test_registered_artifact_bytes_mutation_is_rejected(self):
        self.add_proof()
        path=Path(self.f.items['R152_TEST_PROOF_0']['path'])
        path.write_bytes(b'fake producer evidence')
        from c07_positive_native_process import NativeEvidenceBlocked
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.check()

    def test_all_563_canonical_original_requirement_tampering_blocks(self):
        from c07_r151_original_clause_proofs import UnverifiedLineEvidence
        for i,batch in enumerate(self.batches):
            for rid in batch:
                row=self.f.inv['rules'][rid]
                old=row['requirement']
                row['requirement']='forged verification success'
                with self.subTest(rule=rid):
                    with self.assertRaisesRegex(UnverifiedLineEvidence,
                                                'CANONICAL_SOURCE_CHANGED'):
                        r.compile_contract(self.f.inv,self.f.plan,i)
                row['requirement']=old

    def test_frozen_cohort_membership_and_overlapping_ids_are_rejected(self):
        rid=self.batches[0][0]
        self.f.inv['rules'].pop(rid)
        with self.assertRaisesRegex(r.InvalidRemainingCohort,
                                    'CANONICAL_SOURCE_763_REQUIRED'):
            r.cohorts(self.f.inv)

    def test_completely_unchanged_controller_attempt_only(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='f'*64
        from c07_positive_native_process import NativeEvidenceBlocked
        with self.assertRaisesRegex(NativeEvidenceBlocked,
                                    'EXACT_RESERVED_WORK'):
            self.check()

    def test_master_tamper_never_passes_source_batch(self):
        (self.f.root/'MASTER.md').write_bytes(b'changed master')
        with self.assertRaisesRegex(r.InvalidRemainingCohort,
                                    'MASTER_OR_ORIGINAL_CONTROLLER_DRIFT'):
            self.check()

if __name__=='__main__':
    unittest.main()

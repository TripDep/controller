"""Adversarial independent unit tests for 37 individually named R142 sources."""
import copy
import unittest
from pathlib import Path
from c07_frozen37_mother_native import inspect, IDS, SCHEMA, EvidenceBlocked
from c07_positive200_evidence import R122_FROZEN_IDS
from c07_positive_native_process import NativeEvidenceBlocked
from test_c07_positive_native_process import Tests as NativeFixture, sha

class Frozen37(unittest.TestCase):
    def setUp(self):
        self.fixture=NativeFixture('test_genuine_positive_semantics_for_both_exact_literal_rules')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture
        self.f.inv['families']={'MOTHER':list(IDS)}
        self.f.inv['source_digests'].update({
            'error_registry':'1'*64,'behavior_rules':'2'*64,'developer_rules':'3'*64})
        sources={
            '110_ERROR_REGISTRY':'error_registry',
            'ASSISTANT_BEHAVIOR_PROTOCOL':'behavior_rules',
            'DEVELOPER_RULES_CANONICAL':'developer_rules'}
        for rid in IDS:
            label='Synthetic canonical source clause for '+rid
            name=sources.get(rid,'master')
            self.f.inv['rules'][rid]={
                'family':'MOTHER','source':name,'requirement':label,
                'source_sha256':self.f.work['master_sha256']
                     if name=='master' else self.f.inv['source_digests'][name],
                'requirement_sha256':sha(label.encode())}
        self.f.plan['pre_d_control']={
          'piece_id':'PAV-001','objective':'Check original protected model',
          'phase':'C','criteria':['No overlap at actual player scale'],
          'assertions':['Geometry is aligned'],
          'assumptions':['Terrain is unknown'],
          'rule_ids':list(IDS),'target_engine':'FiveM',
          'selected_method':'Original geometry comparison',
          'time_budget_seconds':3600,
          'defect_ids':['PAV-011'],'defect_to_piece':{'PAV-011':'PAV-001'},
          'expected_measurements':{'width_m':3.1},'predecessors':['PAV-000']}
        self.f.rebuild()
    def check(self):
        f=self.f
        return inspect(f.inv,f.plan,f.controller,f.asset,f.step,f.work,
            source_loader=lambda p:Path(p).read_bytes())
    def test_exact_200_covering_37_one_to_one(self):
        from c07_exec25_native_observation import IDS as ex
        from c07_a10_c10_original_evidence import IDS as ac
        from c07_positive_native_process import RULES as p2
        from c07_r124_positive_process import TEXT as p8
        reviewed=set((
            'AAA-200-A-008','AAA-200-A-009'))
        current=set(IDS)|set(ex)|set(ac)|set(p2)|{
            'AAA-200-R-'+str(n).zfill(3) for n in p8} | {
            'BEHAVIOR-'+str(i).zfill(3) for i in range(1,111)}
        self.assertEqual(len(set(IDS)),37)
        self.assertEqual(len(current),202)
        self.assertEqual(current-set(R122_FROZEN_IDS),reviewed)
        self.assertEqual(set(R122_FROZEN_IDS),current-reviewed)
    def test_37_original_domain_probes_and_no_false_pass(self):
        result=self.check()
        self.assertEqual(result['schema'],SCHEMA)
        self.assertEqual(result['source_rules_examined'],37)
        self.assertEqual(result['named_domain_predicates'],74)
        self.assertEqual(set(result['rules']),set(IDS))
        self.assertEqual(result['full_rule_semantic_passes'],0)
        self.assertEqual(result['individual_mg0_passes'],0)
        self.assertFalse(result['advancement_authorized'])
        all_labels=[]
        for rid,row in result['rules'].items():
            with self.subTest(rid=rid):
                self.assertEqual(row['full_rule_semantics'],'UNKNOWN')
                self.assertEqual(row['individual_mg0'],'UNKNOWN')
                self.assertFalse(row['advancement_authorized'])
                self.assertEqual(len(row['original_machine_predicates']),2)
                self.assertTrue(all(type(v) is bool for v in
                     row['original_machine_predicates'].values()))
                all_labels.extend(row['original_machine_predicates'])
        self.assertEqual(len(all_labels),len(set(all_labels)))
    def test_each_of_37_source_requirement_mutations_is_blocked(self):
        for rid in IDS:
            old=self.f.inv['rules'][rid]['requirement']
            self.f.inv['rules'][rid]['requirement']='FAKE SOURCE PASS'
            with self.subTest(rid=rid):
                with self.assertRaisesRegex(EvidenceBlocked,'R142_LITERAL_ORIGINAL_RULE_SOURCE_CHANGED'):
                    self.check()
            self.f.inv['rules'][rid]['requirement']=old
    def test_each_of_37_source_sha_mutations_is_blocked(self):
        for rid in IDS:
            original=self.f.inv['rules'][rid]['source_sha256']
            self.f.inv['rules'][rid]['source_sha256']='f'*64
            with self.subTest(rid=rid):
                with self.assertRaisesRegex(EvidenceBlocked,'R142_LITERAL_ORIGINAL_RULE_SOURCE_CHANGED'):
                    self.check()
            self.f.inv['rules'][rid]['source_sha256']=original
    def test_audit_bytes_mutation_rejected(self):
        p=self.f.controller.audit_path(self.f.asset)
        p.write_bytes(p.read_bytes().replace(b'ARTIFACT_RECORDED',b'ARTIFACT_FALSIFIED'))
        with self.assertRaises(ValueError):
            self.check()
    def test_original_source_bytes_mutation_rejected(self):
        (self.f.root/'scene.blend').write_bytes(b'fake changed model')
        with self.assertRaisesRegex(NativeEvidenceBlocked,'REGISTERED_ARTIFACT_BYTES_CHANGED'):
            self.check()
    def test_current_work_attempt_replay_rejected(self):
        self.f.work=copy.deepcopy(self.f.work)
        self.f.work['attempt_id']='d'*64
        with self.assertRaisesRegex(NativeEvidenceBlocked,'EXACT_RESERVED_WORK'):
            self.check()
    def test_original_missing_mg0_does_not_become_positive(self):
        report=self.check()
        self.assertEqual(report['rules']['G0-01']['original_machine_predicates'][
            'original_complete_300_question_set_verification_not_inferred'],False)
        self.assertEqual(report['rules']['D0']['full_rule_semantics'],'UNKNOWN')
        self.assertEqual(report['rules']['FIVEM_TARGET']['individual_mg0'],'UNKNOWN')

if __name__=='__main__':unittest.main()

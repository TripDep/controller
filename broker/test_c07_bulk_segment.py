"""Source-window and live audit regression tests; mocks never certify assets."""
import hashlib,json,sys,unittest
from unittest.mock import patch
from pathlib import Path
import c07_bulk_segment as sut

class Tests(unittest.TestCase):
    def setUp(self):
        allids=['AAA-200-T-199','AAA-200-T-200','ADVERSARIAL_QA','APPEND_ONLY_AUDIT',
        'ARCHITECTURAL_QUALITY_FLOOR','ARCHITECTURE_1TO1','ASSISTANT_BEHAVIOR_PROTOCOL',
        'AUTONOMOUS_PRE_PASS_QUESTION','B']
        allids+=['BEHAVIOR-%03d'%i for i in range(1,111)]
        # Instead of synthesizing a catalog and then blessing it, this fixture
        # copies actual externally pinned sorted ID membership from R106 data.
        root=Path(__file__).with_name('c07_r106_rule_ids_fixture.json')
        allids=json.loads(root.read_text())
        self.ids=allids
        self.master='a'*64
        self.inv={'schema':'gg-effective-family-inventory-v1','rule_count':763,'family_count':2,
                  'canonical_master_sha256':self.master,
                  'families':{'EVERY':[r for r in allids if not r.startswith('Q-')],
                              'QUESTIONS_300':[r for r in allids if r.startswith('Q-')]},
                  'rules':{r:{'family':'QUESTIONS_300' if r.startswith('Q-') else 'EVERY','requirement_sha256':hashlib.sha256(r.encode()).hexdigest(),
                          'source_sha256':'b'*64,'requirement':r} for r in allids}}
        self.plan={'master_sha256':self.master,'phase':'P0','enrolled':{}}
        self.due=set(allids[200:250])
        scope={'by_rule':{r:{'disposition':'DUE' if r in self.due else 'FUTURE_PHASE'}
                          for r in allids},'due':sorted(self.due)}
        entries={r:{'requirement_sha256':self.inv['rules'][r]['requirement_sha256'],
                    'source_sha256':'b'*64,'questions':[{'id':r+':Q'}]} for r in allids}
        ledger={'rule_count':763,'entries':entries}
        self.patches=[patch.object(sut.scope,'inspect',return_value=scope),
                      patch.object(sut.answer_contract,'build',return_value=ledger),
                      patch.object(sut.composite,'inspect',return_value={'due_composites':{}})]
        for p in self.patches:p.start()
        self.addCleanup(lambda:[p.stop() for p in self.patches])
    def test_all_three_segment_boundaries(self):
        for stage,size in [(2,200),(3,200),(4,163)]:
            got=sut.inspect(self.inv,self.plan,segment=stage)
            self.assertEqual(got['source_rule_count'],size)
            self.assertEqual(len(got['rules']),size)
            self.assertEqual(sum(x['count'] for x in got['chunks']),size)
            self.assertFalse(got['positive_200_rule_certification'])
    def test_native_positive_proofs_are_never_fabricated(self):
        got=sut.inspect(self.inv,self.plan,segment=2)
        self.assertEqual(got['counts']['DUE'],50)
        self.assertEqual(got['independent_current_asset_pass_count'],0)
        self.assertEqual(got['counts']['MISSING_REVIEWED_POSITIVE_VERIFIER'],50)
        self.assertEqual(got['rules']['APPEND_ONLY_AUDIT']['machine_process_observation'],'UNOBSERVED')
    def test_missing_or_duplicate_canonical_ids_stop(self):
        self.inv['families']['EVERY'][-1]=self.inv['families']['EVERY'][0]
        with self.assertRaisesRegex(sut.SourceBlocked,'CANONICAL_MEMBERSHIP'):
            sut.inspect(self.inv,self.plan,segment=2)
    def test_no_fake_readback_if_partial_audit(self):
        with self.assertRaisesRegex(sut.SourceBlocked,'ALL_OR_NOTHING'):
            sut.inspect(self.inv,self.plan,segment=2,audit_raw=b'fake')
    def test_audited_fail_binds_only_current_due_rule(self):
        target=self.ids[207]
        def verified(*args,**kwargs):
            data={rid:{'semantic_negative_verdict':'FAIL' if rid==target else 'UNKNOWN',
                      'native_negative_evidence':[{'source':'NATIVE','record_hash':'d'*64}] if rid==target else []}
                  for rid in self.ids}
            return {'rule_count':763,'batch_counts':[200,200,200,163],
                    'individual_mg0_passes':0,'advancement_authorized':False,
                    'batches':[{'rules':dict(list(data.items())[i:i+200])} for i in (0,200,400,600)]}
        with patch.object(sut,'audit_readback',return_value=([{'record_hash':'e'*64}],'e'*64)),\
             patch.object(sut,'replay_negatives',side_effect=verified):
            got=sut.inspect(self.inv,self.plan,segment=2,audit_raw=b'audit',asset='TEST',
                            attempt_id='a'*64,operation_sha256='b'*64)
        self.assertEqual(got['failed_due_rule_ids'],[target]);self.assertEqual(got['counts']['FAIL'],1)
        self.assertEqual(got['rules'][target]['individual_mg0'],'UNKNOWN')
        self.assertEqual(got['counts']['PROCESS_INTEGRITY_PREDICATE_EXECUTED'],1)

    def test_third_segment_audits_real_question_id_without_positive_verdict(self):
        q='Q-001'
        self.due.add(q)
        scope={'by_rule':{rid:{'disposition':'DUE' if rid in self.due else 'FUTURE_PHASE'}
                          for rid in self.ids},'due':sorted(self.due)}
        fake=[{'event':'SUPERVISOR_ASSISTANT_ANSWER_GATE','record_hash':'e'*64,
               'report':{'attempt_id':'a'*64,'operation_sha256':'b'*64,
                         'master_sha256':self.master,'advancement_authorized':False,
                         'answered':{q+':Q':{'status':'UNKNOWN','answer':'YES'}}}}]
        def verified(*a,**kw):
            return {'rule_count':763,'batch_counts':[200,200,200,163],
                'individual_mg0_passes':0,'advancement_authorized':False,
                'batches':[{'rules':{rid:{'semantic_negative_verdict':'UNKNOWN',
                                     'native_negative_evidence':[]}
                                      for rid in self.ids[i:i+200]}}
                           for i in (0,200,400,600)]}
        with patch.object(sut.scope,'inspect',return_value=scope),\
             patch.object(sut,'audit_readback',return_value=(fake,'e'*64)),\
             patch.object(sut,'replay_negatives',side_effect=verified):
            got=sut.inspect(self.inv,self.plan,segment=3,audit_raw=b'chain',
                asset='TEST',attempt_id='a'*64,operation_sha256='b'*64)
        self.assertEqual(got['counts']['QUESTION_SOURCE_RESPONSES_AUDITED'],1)
        self.assertEqual(got['rules'][q]['real_current_attempt_semantic_result'],'UNKNOWN')
        self.assertFalse(got['advancement_authorized'])
    def test_third_segment_rejects_forged_question_id(self):
        q='Q-001';self.due.add(q)
        scope={'by_rule':{rid:{'disposition':'DUE' if rid in self.due else 'FUTURE_PHASE'}
                          for rid in self.ids},'due':sorted(self.due)}
        bad=[{'event':'SUPERVISOR_ASSISTANT_ANSWER_GATE','record_hash':'f'*64,
              'report':{'attempt_id':'a'*64,'operation_sha256':'b'*64,
                        'master_sha256':self.master,'advancement_authorized':False,
                        'answered':{'Q-999:Q':{'status':'PASS'}}}}]
        with patch.object(sut.scope,'inspect',return_value=scope),\
             patch.object(sut,'audit_readback',return_value=(bad,'f'*64)):
            with self.assertRaisesRegex(sut.SourceBlocked,'UNREVIEWED_OR_FALSE_PASS'):
                sut.inspect(self.inv,self.plan,segment=3,audit_raw=b'chain',
                    asset='TEST',attempt_id='a'*64,operation_sha256='b'*64)

    def test_fourth_verifies_original_controller_state_tail_not_self_reported_pass(self):
        audit=[{'event':'WORK_INIT','record_hash':'e'*64}]
        def verified(*a,**kw):
            return {'rule_count':763,'batch_counts':[200,200,200,163],
                'individual_mg0_passes':0,'advancement_authorized':False,
                'batches':[{'rules':{rid:{'semantic_negative_verdict':'UNKNOWN',
                         'native_negative_evidence':[]} for rid in self.ids[i:i+200]}}
                          for i in (0,200,400,600)]}
        state={'assets':{'TEST':{'last_audit_hash':'e'*64,
                'd_authorized':False,'d_authorization_evidence':None}}}
        with patch.object(sut,'audit_readback',return_value=(audit,'e'*64)),\
             patch.object(sut,'replay_negatives',side_effect=verified):
            done=sut.inspect(self.inv,self.plan,segment=4,audit_raw=b'chain',
                    asset='TEST',attempt_id='a'*64,operation_sha256='b'*64,
                    controller_state=state)
            self.assertEqual(done['source_rule_count'],163)
            self.assertTrue(done['controller_state_observation']
                            ['controller_state_tail_matches_original_audit'])
            self.assertFalse(done['advancement_authorized'])
            state['assets']['TEST']['last_audit_hash']='x'*64
            with self.assertRaisesRegex(sut.SourceBlocked,'STATE_AUDIT_DISCONNECTED'):
                sut.inspect(self.inv,self.plan,segment=4,audit_raw=b'chain',
                    asset='TEST',attempt_id='a'*64,operation_sha256='b'*64,
                    controller_state=state)
    def test_fourth_prevents_mutating_operation_without_real_d0(self):
        audit=[{'event':'WORK_INIT','record_hash':'e'*64}]
        state={'assets':{'TEST':{'last_audit_hash':'e'*64,
                 'd_authorized':False,'d_authorization_evidence':None}}}
        plan={**self.plan,'operation':{'category':'MUTATION'}}
        replay={'rule_count':763,'batch_counts':[200,200,200,163],
                'individual_mg0_passes':0,'advancement_authorized':False,
                'batches':[{'rules':{rid:{'semantic_negative_verdict':'UNKNOWN',
                    'native_negative_evidence':[]} for rid in self.ids[i:i+200]}}
                    for i in (0,200,400,600)]}
        with patch.object(sut,'audit_readback',return_value=(audit,'e'*64)),\
             patch.object(sut,'replay_negatives',return_value=replay):
            with self.assertRaisesRegex(sut.SourceBlocked,'MUTATION_WITHOUT_ORIGINAL_D0_AUDIT'):
                sut.inspect(self.inv,plan,segment=4,audit_raw=b'chain',
                    asset='TEST',attempt_id='a'*64,operation_sha256='b'*64,
                    controller_state=state)

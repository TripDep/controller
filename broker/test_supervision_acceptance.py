"""Unit fixtures only; the installed acceptance CLI uses real native Git APIs."""
import copy
import json
import unittest
from unittest.mock import patch

import supervision_acceptance as a
import supervisor_judgment as j
import planning_semantics as p
from test_planning_semantics import fixture
from test_rule_evidence import API
from test_supervisor_judgment import contexts
from test_supervisor_context import seal


class Tests(unittest.TestCase):
    def setUp(self):
        self.inv,self.work,self.docs,engine=fixture()
        self.inv['rules'][p.ENGINE_RULE]['asset_type']='all'
        self.inv['rules']['UNIT_PROFILE'].update(family='ASSET_PROFILE_READINESS',source_sha256='a'*64,requirement_sha256='d'*64)
        self.inv['families']['ASSET_PROFILE_READINESS']=['UNIT_PROFILE']
        self.inv.update(family_count=2,rule_count=2)
        self.policy={'work':self.work,'engine':engine}
        self.packet,_=p.documented_engine(self.inv,self.work,self.docs,engine)
        self.api=API();self.api.jobs['jobs'][0]['steps'][0]['name']=j.SEMANTIC_STEP
        self.api.job_logs=lambda _: '2020-10-13T18:00:00Z '+j.PREFIX+json.dumps(self.packet)
        self.spec={'validator_id':p.VALIDATOR,'criteria':p.CRITERIA,'issuer':self.api.issuer,
                   'requirement_sha256':engine['requirement_sha256'],'source_ref':'c'*40}
        # This suite verifies C08/C09 transport and denial with synthetic
        # fixtures. Real consumer source replay is adversarially tested in
        # test_planning_semantics and test_c07_reviewed_native_readback.
        native_fixture = patch('planning_semantics.native_rule_readback',
                               return_value={'individual_rule_mg0':'UNKNOWN',
                                             'advancement_authorized':False})
        native_fixture.start()
        self.addCleanup(native_fixture.stop)
        self.backend=j.NativeRuleBackend(self.api,{p.ENGINE_RULE:self.spec})
        self.offers={p.ENGINE_RULE:{'native_origin':self.api.origin,'expected_packet_sha256':j.digest(self.packet)}}
        self.contexts=contexts()
        for value in self.contexts.values():value['master']['sha256']=self.work['master_sha256'];seal(value)

    def test_all_adverse_cases_and_transport_recovery(self):
        report=a.point8(self.inv,self.policy,self.docs,self.packet,self.spec,self.backend,self.offers,self.contexts)
        self.assertEqual(report['tests_passed'],9)
        self.assertFalse(report['eligible_work_correction_proven'])
        self.assertFalse(report['advancement_authorized'])
        self.assertEqual({r['case'] for r in report['cases']},
                         {'missing_family','missing_rule','missing_individual_mg0','missing_proof',
                          'explicit_fail','relevant_context_changed','old_evidence_other_attempt',
                          'corrected_native_request','unrelated_context_no_added_block'})

    def matrix(self):
        return j.judge(self.inv,self.work,self.offers,self.backend,current_contexts=self.contexts)

    def test_c09_refuses_actual_unknown_matrix_without_consuming(self):
        matrix=self.matrix();native=j.evidence.native
        def logs(api,origin,issuer,step):
            if origin==a.DECISION:
                return '2020-10-13T18:00:00Z C07_NATIVE_PROCESS_JUDGMENT:'+json.dumps(matrix)
            return native(api,origin,issuer,step)
        with patch.object(j.evidence,'native',side_effect=logs):
            report=a.point9(self.inv,self.policy,self.backend,self.offers,self.contexts)
        self.assertEqual(report['gate_denial'],'JUDGMENT_ADVANCEMENT_DENIED')
        self.assertFalse(report['controlled_asset_cycle_started'])
        self.assertFalse(report['advancement_authorized'])

    def test_c09_tampered_matrix_is_not_used(self):
        matrix=self.matrix();matrix['operation_sha256']='0'*64
        native=j.evidence.native
        def logs(api,origin,issuer,step):
            if origin==a.DECISION:return '2020-10-13T18:00:00Z C07_NATIVE_PROCESS_JUDGMENT:'+json.dumps(matrix)
            return native(api,origin,issuer,step)
        with patch.object(j.evidence,'native',side_effect=logs):
            with self.assertRaisesRegex(j.Blocked,'C09_NATIVE_DECISION_CHANGED'):
                a.point9(self.inv,self.policy,self.backend,self.offers,self.contexts)

    def test_duplicate_native_packet_rejected(self):
        line='2020-10-13T18:00:00Z TEST:'+json.dumps({'a':1})
        with self.assertRaisesRegex(j.Blocked,'NATIVE_PACKET_UNIQUE'):a.one_packet(line+'\n'+line,'TEST:')

    def test_unstamped_output_cannot_be_native_packet(self):
        with self.assertRaisesRegex(j.Blocked,'NATIVE_PACKET_UNIQUE'):a.one_packet('TEST:{"a":1}','TEST:')

    def test_wrong_rejection_is_a_failed_test(self):
        with self.assertRaisesRegex(j.Blocked,'WRONG_REJECTION'):
            a.expected_rejection(lambda:(_ for _ in ()).throw(ValueError('different')),'required')


if __name__=='__main__':unittest.main()

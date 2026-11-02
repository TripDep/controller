"""Adversarial F059 original structural correction and detail chronology tests."""
import copy
import unittest
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p1_thirty_native_domain import P1Thirty,encode
from test_c07_native_output_oracle import two_triangles
from test_c07_r124_positive_process import test_glb
from test_c07_positive_native_process import sha,canonical
from c07_p1_structural_correction_full_review import RULE,CRITERIA
from c07_native_source_rule_replayers import (
    NATIVE_RULES,FULL_LITERAL_REVIEWED,VALIDATORS,build_packet,
    native_rule_readback,NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding,semantic_packet

POLICY={
 'issues':{'ALIGN-1':{'before_role':'BASELINE_SNAPSHOT',
                      'after_role':'NATIVE_EXPORT'}},
 'required_checks':['nondegenerate','no_duplicate_faces',
                    'minimum_triangles','bbox_shift_within_tolerance'],
 'max_bbox_shift_m':2,'minimum_final_triangles':2,
}

class StructuralFixFullReviewTests(unittest.TestCase):
    def context(self,policy=None,*,omit_recheck=False,detail_early=False,
                bad_geometry=False):
        test,ctx=NativeOriginalReplayerTests.context(
            self,P1Thirty,'test_exact_30_individual_P1_and_90_unique_predicates')
        test.put('BASELINE_SNAPSHOT','before.glb',test_glb())
        test.put('P1_QA_REPORT','qa.json',
                 encode({'open_findings':[],'passed_checks':['structural']}))
        test.put('P1_STRUCTURAL_FIX_POLICY','p1_structural_fix_policy.json',
                 encode(POLICY if policy is None else policy))
        if bad_geometry:
            from test_c07_p3_geometry_semantics import glb
            test.put('NATIVE_EXPORT','scene.glb',
                     glb([(0,0,0),(1,0,0),(2,0,0)],[(0,1,2)],
                         [(0,0,1)]*3))
        else:
            test.put('NATIVE_EXPORT','scene.glb',two_triangles())
        test.rebuild()
        ctx['controller']=test.f.controller
        self.events(test,omit_recheck=omit_recheck,detail_early=detail_early)
        return test,ctx

    def events(self,test,*,omit_recheck=False,detail_early=False):
        f=test.f
        before=f.items['BASELINE_SNAPSHOT']['sha256']
        after=f.items['NATIVE_EXPORT']['sha256']
        def event(name,**extra):
            row=dict(asset=f.asset,event=name,step=f.step,
                     attempt_id=f.work['attempt_id'],
                     operation_sha256=f.work['operation_sha256'],
                     prev_hash=f.records[-1]['record_hash'],**extra)
            row['record_hash']=sha(canonical(row))
            f.records.append(row)
        event('STRUCTURAL_FINDING',issue_id='ALIGN-1',
              status='OPEN',severity='MAJOR')
        if detail_early:event('DETAIL_PHASE_STARTED')
        event('STRUCTURAL_FIX_APPLIED',issue_id='ALIGN-1',
              before_role='BASELINE_SNAPSHOT',after_role='NATIVE_EXPORT',
              before_sha256=before,after_sha256=after)
        if not omit_recheck:
            event('STRUCTURAL_RECHECK',issue_id='ALIGN-1',result='PASS',
                  after_sha256=after,check_ids=list(POLICY['required_checks']))
        if not detail_early:event('DETAIL_PHASE_STARTED')
        f.controller.audit_path(f.asset).write_bytes(
            b''.join(canonical(row)+b'\n' for row in f.records))
        f.controller._state['last_audit_hash']=f.records[-1]['record_hash']

    def packet(self,ctx):
        expected=binding(ctx['work'],ctx['inventory']['rules'][RULE],RULE)
        packet=build_packet(ctx,RULE,expected=expected)
        spec={'validator_id':VALIDATORS[RULE],
              'criteria':list(NATIVE_RULES[RULE][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40,
              'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        return packet,expected,spec

    def test_full_original_structural_correction_positive_unknown_mg0(self):
        _,ctx=self.context()
        self.assertIn(RULE,FULL_LITERAL_REVIEWED)
        self.assertEqual(NATIVE_RULES[RULE][1],CRITERIA)
        packet,expected,spec=self.packet(ctx)
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertTrue(all(packet['rule']['checks'].values()))
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        self.assertEqual(replay(None,packet,expected,spec,
            source_context=lambda _:ctx)['documentary_result'],'PASS')
        self.assertEqual(semantic_packet(packet,expected,spec)['result'],'UNKNOWN')
        forged=copy.deepcopy(packet)
        forged['rule']['proof_digest']='f'*64
        with self.assertRaisesRegex(
            NativeRuleEvidenceBlocked,'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)

    def test_detail_started_before_recheck_never_passes(self):
        _,ctx=self.context(detail_early=True)
        self.assertEqual(self.packet(ctx)[0]['rule']['result'],'FAIL')

    def test_missing_original_structural_recheck_never_passes(self):
        _,ctx=self.context(omit_recheck=True)
        self.assertNotEqual(self.packet(ctx)[0]['rule']['result'],'PASS')

    def test_wrong_pre_d_scope_never_passes(self):
        policy=copy.deepcopy(POLICY)
        policy['required_checks']=['nondegenerate']
        _,ctx=self.context(policy=policy)
        self.assertNotEqual(self.packet(ctx)[0]['rule']['result'],'PASS')

    def test_actual_degenerate_final_geometry_fails(self):
        _,ctx=self.context(bad_geometry=True)
        self.assertNotEqual(self.packet(ctx)[0]['rule']['result'],'PASS')

    def test_unpinned_policy_and_wrong_attempt_rejected(self):
        test,ctx=self.context()
        test.f.plan['p1_evidence_contract']['original_artifact_sha256'].pop(
            'P1_STRUCTURAL_FIX_POLICY')
        test.f.rebuild()
        ctx['controller']=test.f.controller
        self.assertNotEqual(self.packet(ctx)[0]['rule']['result'],'PASS')
        test,ctx=self.context()
        ctx['work']['attempt_id']='f'*64
        with self.assertRaises(ValueError):build_packet(ctx,RULE)

    def test_original_source_tamper_blocked(self):
        test,ctx=self.context()
        (test.f.root/'scene.glb').write_bytes(b'forged')
        with self.assertRaises(ValueError):build_packet(ctx,RULE)

if __name__=='__main__':
    unittest.main()

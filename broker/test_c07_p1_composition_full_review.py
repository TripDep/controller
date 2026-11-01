"""F057 original GLB composition QA, source-bound and ordering adversaries."""
import copy
import json
import unittest

import supervisor_judgment as judgment
from c07_p1_composition_full_review import (
    inspect as inspect_composition, CRITERIA, RULE)
from c07_native_source_rule_replayers import (
    build_packet, native_rule_readback, NATIVE_RULES, VALIDATORS)
from c07_native_replayer_dispatch import replay
from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p1_thirty_native_domain import P1Thirty, encode
from test_c07_positive_native_process import canonical, sha


class OriginalCompositionQAFullTests(unittest.TestCase):
    def setUp(self):
        self.t,self.ctx=NativeOriginalReplayerTests.context(
            self,P1Thirty,'test_exact_30_individual_P1_and_90_unique_predicates')
        f=self.t.f
        self.scene=json.loads(self.t.contents['P1_SCENE_CONTRACT'][1])
        self.scene['expected_bbox_local']['max'][2]=1.5
        self.policy={
            'schema':'c07-p1-visual-metrics-pre-d-v1',
            'max_composition_bbox_height_error_m':0.1,
        }
        self.report={
            'schema':'c07-p1-composition-native-qa-v1',
            'asset':f.asset, 'step':f.step,
            'attempt_id':f.work['attempt_id'],
            'operation_sha256':f.work['operation_sha256'],
            'open_findings':[{
                'code':'COMPOSITION_BBOX_HEIGHT_MISMATCH',
                'observed_height_m':1.0,'target_height_m':1.5,
                'tolerance_m':0.1,
            }],
        }
        self.refresh()

    def refresh(self,detail_before=False,omit_qa=False):
        f=self.t.f
        self.t.put('P1_SCENE_CONTRACT','p1_scene.json',
                   encode(self.scene))
        self.t.put('P1_VISUAL_METRICS_POLICY','p1_visual_metrics.json',
                   encode(self.policy))
        self.t.put('P1_QA_REPORT','qa.json',encode(self.report))
        self.t.rebuild()
        self.ctx['controller']=f.controller
        if detail_before:
            self.append('DETAIL_STARTED')
        if not omit_qa:
            self.append('BLOCKOUT_QA',
                        qa_report_sha256=sha(encode(self.report)),
                        issue_code='COMPOSITION_BBOX_HEIGHT_MISMATCH')

    def append(self,event,**extra):
        f=self.t.f
        row={'asset':f.asset,'event':event,
             'prev_hash':f.records[-1]['record_hash'],
             'step':f.step,'attempt_id':f.work['attempt_id'],
             'operation_sha256':f.work['operation_sha256'],
             **extra}
        row['record_hash']=sha(canonical(row))
        f.records.append(row)
        f.controller.audit_path(f.asset).write_bytes(
            b''.join(canonical(x)+b'\n' for x in f.records))
        f.controller._state['last_audit_hash']=row['record_hash']

    def spec(self):
        return {'validator_id':VALIDATORS[RULE],
            'criteria':list(NATIVE_RULES[RULE][1]),
            'requirement_sha256':
                self.ctx['inventory']['rules'][RULE]['requirement_sha256'],
            'source_ref':'1'*40}

    def expect_failed(self,index):
        r=inspect_composition(self.ctx,RULE)
        self.assertTrue(r['evidence_complete'])
        self.assertFalse(r['checks'][CRITERIA[index]],r['checks'])
        packet=build_packet(self.ctx,RULE)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        self.assertFalse(packet['rule']['result']=='PASS')

    def test_current_original_native_defect_and_pre_detail_audit_are_replayed(self):
        result=inspect_composition(self.ctx,RULE)
        self.assertTrue(result['evidence_complete'])
        self.assertTrue(all(result['checks'].values()),result['checks'])
        packet=build_packet(self.ctx,RULE)
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        expected=judgment.binding(
            self.ctx['work'],self.ctx['inventory']['rules'][RULE],RULE)
        response=replay(None,packet,expected,self.spec(),
                        source_context=lambda _:self.ctx)
        self.assertEqual(response['documentary_result'],'PASS')
        self.assertFalse(response['advancement_authorized'])
        forged=copy.deepcopy(packet)
        forged['rule']['checks'][CRITERIA[1]]=False
        with self.assertRaisesRegex(ValueError,
                                    'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,self.spec(),
                                 source_context=lambda _:self.ctx)

    def test_claimed_height_not_equal_to_reopened_original_glb_fails(self):
        self.report['open_findings'][0]['observed_height_m']=1.4
        self.refresh()
        self.expect_failed(1)

    def test_no_native_error_cannot_be_claimed_as_found_composition_defect(self):
        self.scene['expected_bbox_local']['max'][2]=1.0
        self.report['open_findings'][0]['target_height_m']=1.0
        self.refresh()
        self.expect_failed(1)

    def test_detail_work_starts_before_qa_review_fails(self):
        self.refresh(detail_before=True)
        self.expect_failed(2)

    def test_no_actual_qa_event_or_report_link_cannot_pass(self):
        self.refresh(omit_qa=True)
        self.expect_failed(2)

    def test_unsupported_qa_description_without_measured_original_fails(self):
        self.report['open_findings']=['BAD_ALIGNMENT']
        self.refresh()
        self.expect_failed(1)

    def test_invalid_pre_d_original_tolerance_never_counts(self):
        self.policy['max_composition_bbox_height_error_m']=0
        self.refresh()
        self.expect_failed(0)

    def test_original_report_byte_tamper_is_not_accepted(self):
        (self.t.f.root/'qa.json').write_bytes(b'{"result":"PASS"}')
        with self.assertRaises((ValueError,OSError,AssertionError)):
            build_packet(self.ctx,RULE)


if __name__=='__main__':
    unittest.main()

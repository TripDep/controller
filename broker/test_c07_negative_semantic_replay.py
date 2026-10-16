"""Integration of 200-rule negative judgments; signed JSON audit, no mock verdicts."""
import copy
import hashlib
import json
import sys
import types
import unittest

import c07_negative_semantic_replay as gate

fake=types.ModuleType('family_coverage')
fake.PHASES=('P0','P1','P2','P3','P4','P5','P6','P7','P8')
fake.ASSET_TYPES=('architecture','organic','vegetation','terrain')
def expected_result(row,phase,asset_type,profiles):
    return 'PASS' if row.get('catalog_phase','P0') == phase else 'FUTURE_PHASE'
fake.expected_result=expected_result
scopemod=types.ModuleType('c07_operation_scope')
def inspect_scope(inv,plan):
    report={rid:{'disposition':'DUE' if fake.expected_result(row,
            plan['phase'],plan['asset_type'],plan['profiles'])=='PASS'
            else 'FUTURE_PHASE'} for rid,row in inv['rules'].items()}
    return {'rule_count':763,'by_rule':report}
scopemod.inspect=inspect_scope
qcontract=types.ModuleType('c07_answer_semantics')
def source_questions(inv):
    return {'rule_count':763,'entries':{rid:{
        'requirement_sha256':row['requirement_sha256'],
        'questions':[{'id':rid+':REQUIREMENT','type':'REQUIREMENT_SATISFIED'}]
    } for rid,row in inv['rules'].items()}}
qcontract.build=source_questions
compositecontract=types.ModuleType('c07_compound_subchecks')
def canonical_composites(inv,due):
    return {'due_composites':{ANSWER:{'subchecks':[
        {'subcheck_id':ANSWER+':SC001','clause_sha256':'d'*64}
    ]}} if ANSWER in due else {}}
compositecontract.inspect=canonical_composites

MASTER='a'*64
ATTEMPT='b'*64
ASSET='GARDEN'
NATIVE='AAA-200-G-065'
ANSWER='AAA-200-A-004'

class Tests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        source_scope_patch=patch.dict(sys.modules,{'c07_operation_scope':scopemod})
        source_scope_patch.start()
        self.addCleanup(source_scope_patch.stop)
        semantic_patch=patch.dict(sys.modules,{
            'c07_answer_semantics':qcontract,
            'c07_compound_subchecks':compositecontract})
        semantic_patch.start()
        self.addCleanup(semantic_patch.stop)
        ids=['AAA-200-'+str(i).zfill(3) for i in range(1,201)] + [
            'Q-'+str(i).zfill(3) for i in range(1,564)]
        ids[64]=NATIVE
        ids[3]=ANSWER
        ids=sorted(ids)
        self.inv={'schema':'gg-effective-family-inventory-v1','rule_count':763,
            'canonical_master_sha256':MASTER,
            'families':{'AAA':ids[:200],'QUESTION':ids[200:]},
            'rules':{rid:{'family':'AAA' if n<200 else 'QUESTION',
                          'source_sha256':'d'*64,
                          'requirement_sha256':hashlib.sha256(rid.encode()).hexdigest(),
                          'catalog_phase':'P0', 'requirement':rid} for n,rid in enumerate(ids)}}
        self.plan={'master_sha256':MASTER,'phase':'P0','asset_type':'architecture',
                   'profiles':['ARCHITECTURE_PROFILE']}
        self.audit=[]
        self.add('WORK_INIT')

    def add(self,event,**kw):
        row={'event':event,'asset':ASSET,'prev_hash':
                self.audit[-1]['record_hash'] if self.audit else 'GENESIS',**kw}
        row['record_hash']=gate.sha(gate.canonical(row))
        self.audit.append(row)
        return row

    def raw(self):
        return b'\n'.join(gate.canonical(x) for x in self.audit)+b'\n'

    def check(self,**kw):
        return gate.inspect(self.inv,self.plan,self.raw(),ASSET,ATTEMPT,**kw)

    def row(self, report, rid):
        return next(part['rules'][rid] for part in report['batches']
                    if rid in part['rules'])

    def test_full_763_rules_four_chunks_remain_unknown_not_pass(self):
        result=self.check()
        self.assertEqual(result['rule_count'],763)
        self.assertEqual(result['batch_counts'],[200,200,200,163])
        self.assertEqual(result['positive_semantic_passes'],0)
        self.assertEqual(result['individual_mg0_passes'],0)
        self.assertEqual(result['semantic_negative_fail_rule_ids'],[])
        self.assertEqual(self.row(result,ANSWER)['semantic_negative_verdict'],'UNKNOWN')
        self.assertFalse(result['advancement_authorized'])

    def test_admitted_due_failure_stops_even_without_native_scan(self):
        self.add('SUPERVISOR_ASSISTANT_ANSWER_GATE',report={
            'attempt_id':ATTEMPT,'master_sha256':MASTER,
            'advancement_authorized':False,
            'failed_subchecks':[],
            'failed':[{'rule_id':ANSWER,'question_id':ANSWER+':REQUIREMENT','answer':'NO'}]})
        result=self.check()
        self.assertEqual(result['semantic_negative_fail_rule_ids'],[ANSWER])
        self.assertEqual(result['next_action'],'STOP_CORRECT_REVIEW')
        self.assertEqual(self.row(result,ANSWER)['native_negative_evidence'][0]['source'],
                         'ANSWER_ADMITTED_DEFECT')
        self.assertEqual(result['positive_semantic_passes'],0)


    def test_composite_admitted_no_blocks_its_canonical_parent_rule(self):
        self.add('SUPERVISOR_ASSISTANT_ANSWER_GATE',report={
            'attempt_id':ATTEMPT,'master_sha256':MASTER,
            'advancement_authorized':False,'failed':[],
            'failed_subchecks':[{'rule_id':ANSWER,
                                 'subcheck_id':ANSWER+':SC001',
                                 'required_correction':'COMPLETE_THIS_CANONICAL_SUBCONTROL'}]})
        r=self.check()
        self.assertEqual(r['semantic_negative_fail_rule_ids'],[ANSWER])
        self.assertEqual(self.row(r,ANSWER)['native_negative_evidence'][0]['source'],
                         'COMPOSITE_SUBCHECK_ADMITTED_DEFECT')

    def test_native_confirmed_winding_failure_is_bound_to_one_rule(self):
        native={'schema':'gg-c07-real-glb-rule-observations-batch-v1',
            'binding':{'asset_id':ASSET,'attempt_id':ATTEMPT,'master_sha256':MASTER},
            'rule_count':1,'rules':{NATIVE:{
                'individual_mg0':'UNKNOWN',
                'independent_native_rule_observation':'FAIL',
                'native_negative_findings':['INCONSISTENT_INDEXED_WINDING']}},
            'advancement_authorized':False,
            'work_rule_passes':0,'individual_mg0_passes':0}
        self.add('SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE',
            attempt_id=ATTEMPT,master_sha256=MASTER,
            native_reports=[native],native_reports_sha256=gate.supervisor_digest([native]),
            native_rule_ids=[NATIVE],result='FAIL_NATIVE_FINDINGS')
        result=self.check()
        self.assertEqual(result['semantic_negative_fail_rule_ids'],[NATIVE])
        self.assertEqual(self.row(result,NATIVE)['semantic_negative_verdict'],'FAIL')
        self.assertEqual(self.row(result,ANSWER)['semantic_negative_verdict'],'UNKNOWN')

    def test_native_forged_report_digest_cannot_be_trusted(self):
        self.add('SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE',
            attempt_id=ATTEMPT,master_sha256=MASTER,
            native_reports=[{'fabricated':True}],native_reports_sha256='0'*64,
            native_rule_ids=[NATIVE],result='FAIL_NATIVE_FINDINGS')
        with self.assertRaisesRegex(gate.ReplayBlocked,'R112_NATIVE_GATE_INTEGRITY'):
            self.check()

    def test_owner_claim_is_not_authenticated_rule_pass_or_fail(self):
        self.add('USER_REVIEW',attempt_id=ATTEMPT,
                 rule_id=NATIVE,result='FAIL',detected_by='OWNER',
                 owner_evidence_sha256='e'*64)
        result=self.check()
        self.assertEqual(result['semantic_negative_fail_rule_ids'],[])
        self.assertEqual(result['unverified_owner_review_rule_ids'],[NATIVE])
        self.assertEqual(self.row(result,NATIVE)['semantic_negative_verdict'],
                         'UNKNOWN_REVIEW_NOT_AUTHENTICATED')
        self.assertEqual(result['next_action'],'STOP_CORRECT_REVIEW')

    def test_previous_attempt_failure_not_replayed_to_new_attempt(self):
        self.add('SUPERVISOR_ASSISTANT_ANSWER_GATE',report={
            'attempt_id':'f'*64,'master_sha256':MASTER,
            'advancement_authorized':False,
            'failed_subchecks':[],
            'failed':[{'rule_id':ANSWER,'question_id':ANSWER+':REQUIREMENT'}]})
        self.assertEqual(self.check()['semantic_negative_fail_rule_ids'],[])

    def test_not_due_rule_does_not_block(self):
        self.inv['rules'][ANSWER]['catalog_phase']='P8'
        self.add('SUPERVISOR_ASSISTANT_ANSWER_GATE',report={
            'attempt_id':ATTEMPT,'master_sha256':MASTER,
            'advancement_authorized':False,
            'failed_subchecks':[],
            'failed':[{'rule_id':ANSWER,'question_id':ANSWER+':REQUIREMENT'}]})
        result=self.check()
        self.assertEqual(result['semantic_negative_fail_rule_ids'],[])
        self.assertEqual(self.row(result,ANSWER)['semantic_negative_verdict'],'NOT_DUE')

    def test_invalid_audit_and_source_fail_closed(self):
        self.add('SUPERVISOR_ASSISTANT_ANSWER_GATE',report={
            'attempt_id':ATTEMPT,'master_sha256':MASTER,
            'advancement_authorized':False,
            'failed_subchecks':[],
            'failed':[{'rule_id':ANSWER,'question_id':'foo'}]})
        self.audit[-1]['report']['failed'][0]['rule_id']='FAKE'
        with self.assertRaisesRegex(gate.ReplayBlocked,'R112_AUDIT_HASH'):
            self.check()
        self.audit[-1]['record_hash']=gate.sha(gate.canonical({
            k:v for k,v in self.audit[-1].items() if k!='record_hash'}))
        with self.assertRaisesRegex(gate.ReplayBlocked,'R112_ANSWER_FAIL_UNKNOWN_RULE'):
            self.check()

    def test_invalid_known_question_id_rejected_even_in_valid_audit(self):
        self.add('SUPERVISOR_ASSISTANT_ANSWER_GATE',report={
            'attempt_id':ATTEMPT,'master_sha256':MASTER,
            'advancement_authorized':False,'failed_subchecks':[],
            'failed':[{'rule_id':ANSWER,'question_id':ANSWER+':FAKE',
                       'answer':'NO'}]})
        with self.assertRaisesRegex(gate.ReplayBlocked,'NONCANONICAL_QUESTION_ID'):
            self.check()

    def test_reversed_answer_polarity_does_not_invent_fail(self):
        self.add('SUPERVISOR_ASSISTANT_ANSWER_GATE',report={
            'attempt_id':ATTEMPT,'master_sha256':MASTER,
            'advancement_authorized':False,'failed_subchecks':[],
            'failed':[{'rule_id':ANSWER,'question_id':ANSWER+':REQUIREMENT',
                       'answer':'YES'}]})
        with self.assertRaisesRegex(gate.ReplayBlocked,'FALSE_ADMITTED_FAILURE_POLARITY'):
            self.check()

    def test_false_composite_clause_is_rejected(self):
        self.add('SUPERVISOR_ASSISTANT_ANSWER_GATE',report={
            'attempt_id':ATTEMPT,'master_sha256':MASTER,
            'advancement_authorized':False,'failed':[],
            'failed_subchecks':[{'rule_id':ANSWER,
                                 'subcheck_id':ANSWER+':SC999',
                                 'required_correction':'COMPLETE_THIS_CANONICAL_SUBCONTROL'}]})
        with self.assertRaisesRegex(gate.ReplayBlocked,'NONCANONICAL_COMPOSITE_SUBCHECK'):
            self.check()

    def test_cross_operation_replay_is_rejected_even_when_attempt_matches(self):
        op='c'*64
        self.add('SUPERVISOR_ASSISTANT_ANSWER_GATE',report={
            'attempt_id':ATTEMPT,'master_sha256':MASTER,
            'operation_sha256':'d'*64,
            'advancement_authorized':False,'failed_subchecks':[],
            'failed':[{'rule_id':ANSWER,'question_id':ANSWER+':REQUIREMENT',
                       'answer':'NO'}]})
        with self.assertRaisesRegex(gate.ReplayBlocked,'ANSWER_OPERATION_REPLAY'):
            self.check(operation_sha256=op)

    def test_well_bound_negative_admission_passes_strict_operation_replay(self):
        op='c'*64
        self.add('SUPERVISOR_ASSISTANT_ANSWER_GATE',report={
            'attempt_id':ATTEMPT,'master_sha256':MASTER,
            'operation_sha256':op,
            'advancement_authorized':False,'failed_subchecks':[],
            'failed':[{'rule_id':ANSWER,'question_id':ANSWER+':REQUIREMENT',
                       'answer':'NO',
                       'requirement_sha256':self.inv['rules'][ANSWER]['requirement_sha256']}]})
        v=self.check(operation_sha256=op)
        self.assertEqual(v['semantic_negative_fail_rule_ids'],[ANSWER])
        self.assertFalse(v['advancement_authorized'])

    def test_100_batch_mode(self):
        self.assertEqual(self.check(batch_size=100)['batch_counts'],[100]*7+[63])

    def test_real_sha_rejects_duplicate_json_keys_and_nan(self):
        raw=b'{"asset":"GARDEN","asset":"GARDEN","prev_hash":"GENESIS"}\n'
        with self.assertRaisesRegex(gate.ReplayBlocked,'DUPLICATE_JSON_KEY'):
            gate.audit_readback(raw,ASSET)
        raw=b'{"asset":"GARDEN","prev_hash":"GENESIS","value":NaN}\n'
        with self.assertRaisesRegex(gate.ReplayBlocked,'NONFINITE'):
            gate.audit_readback(raw,ASSET)

if __name__=='__main__':
    unittest.main()

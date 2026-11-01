"""C07 100-ID replay orchestration adversarial fixtures (not real MG0 PASS)."""
import copy
import hashlib
import unittest
from unittest.mock import patch

import c07_batch100_native_replay as batch


MASTER=b'current canonical master fixture'
AUDIT=b'original hash-chained audit fixture'
M_SHA=hashlib.sha256(MASTER).hexdigest()
A_SHA=hashlib.sha256(AUDIT).hexdigest()
TAIL='f'*64
ATTEMPT='a'*64
OPERATION='b'*64


class File:
    def __init__(self, raw):
        self.raw=raw
    def read_bytes(self):
        return self.raw


class Controller:
    master=File(MASTER)
    def audit_path(self, asset):
        return File(AUDIT)


class Tests(unittest.TestCase):
    def setUp(self):
        self.work={
            'phase':'P8','asset_type':'architecture',
            'master_sha256':M_SHA,'attempt_id':ATTEMPT,
            'operation_sha256':OPERATION,
        }
        self.plan=dict(self.work)
        self.inv={
            'rule_count':763,'canonical_master_sha256':M_SHA,
            'rules':{rid:{
                'source_sha256':'c'*64,
                'requirement_sha256':'d'*64,
            } for rid in batch.COHORT},
        }
        self.reports=[]
        for label,ids,field,n in (
            ('P1',batch.p1.IDS,'original_native_measured_criteria',3),
            ('P345',batch.p345.IDS,'machine_observations',2),
            ('P678',batch.p678.IDS,'native_original_machine_evidence',2),
        ):
            rules={}
            for rid in ids:
                rules[rid]={
                    'source_sha256':'c'*64,'requirement_sha256':'d'*64,
                    field:{label+'_criterion_'+str(i):True for i in range(n)},
                    'full_rule_semantics':'UNKNOWN',
                    'individual_mg0':'UNKNOWN','advancement_authorized':False,
                }
            self.reports.append({
                'master_sha256':M_SHA,'attempt_id':ATTEMPT,
                'operation_sha256':OPERATION,
                'original_audit_sha256':A_SHA,'original_audit_tail':TAIL,
                'advancement_authorized':False,'rules':rules,
            })
        from c07_p1_design_source_review import IDS as DESIGN_IDS
        self.p1_design={
            'family_rule_count':30,'rule_count':13,
            'attempt_id':ATTEMPT,'operation_sha256':OPERATION,
            'original_audit_sha256':A_SHA,'original_audit_tail':TAIL,
            'advancement_authorized':False,'full_semantic_passes':0,
            'individual_mg0_passes':0,
            'rules':{rid:{
                'original_pixel_geometry_checks':{'source_original_a':True,
                                                  'source_original_b':True},
                'requirement_sha256':'d'*64,'source_sha256':'c'*64,
                'full_rule_semantics':'UNKNOWN',
                'individual_mg0':'UNKNOWN','advancement_authorized':False}
                for rid in DESIGN_IDS},
        }
        from c07_p1_remaining_visual_review import IDS as QUANT_IDS
        self.p1_quant={
            'family_rule_count':30,'rule_count':13,
            'attempt_id':ATTEMPT,'operation_sha256':OPERATION,
            'original_audit_sha256':A_SHA,'original_audit_tail':TAIL,
            'advancement_authorized':False,'full_semantic_passes':0,
            'individual_mg0_passes':0,
            'rules':{rid:{
                'checks':{'pre_d_policy_and_current_original_bytes_reopened':True,
                          'rule_specific_original_measurement_within_pre_d_contract':False},
                'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
                'advancement_authorized':False} for rid in QUANT_IDS},
        }
        import c07_p6_collision_semantics as c6
        import c07_p6_walkability_semantics as w6
        import c07_p7_rage_semantics as r7
        import c07_p8_final_qa_semantics as q8
        self.p678_specific={}
        for label,ids in (('P6_COLLISION',c6.IDS),
                          ('P6_WALKABILITY',w6.IDS),
                          ('P7_RAGE',r7.IDS),
                          ('P8_FINAL',q8.IDS)):
            self.p678_specific[label]={
                'source_rule_count':len(ids),
                'attempt_id':ATTEMPT,'operation_sha256':OPERATION,
                'original_audit_sha256':A_SHA,'original_audit_tail':TAIL,
                'advancement_authorized':False,
                'full_rule_semantic_passes':0,'individual_mg0_passes':0,
                'rules':{rid:{
                    'original_machine_checks':{
                        label+'_source_a':True,label+'_source_b':True},
                    'requirement_sha256':'d'*64,'source_sha256':'c'*64,
                    'exact_attempt_id':ATTEMPT,'operation_sha256':OPERATION,
                    'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
                    'advancement_authorized':False} for rid in ids},
            }
        from c07_native_source_rule_replayers import NATIVE_RULES
        self.p345_macro={
            'schema':'c07-p345-forty-original-source-macro-v1',
            'canonical_rule_count':40,'due_count':40,
            'visited_due_count':40,
            'attempt_id':ATTEMPT,
            'operation_sha256':OPERATION,
            'advancement_authorized':False,
            'individual_mg0_independently_approved':False,
            'fivem_runtime_approved':False,'owner_approved':False,
            'result_counts':{'PASS':0,'FAIL':0,'UNKNOWN':40,
                             'BLOCKED':0,'NOT_DUE':0},
            # This is a fixture proving the gate, NOT a real source replay.
            'rows':{rid:{
                'machine_result':'UNKNOWN','blocked_reason':None,
                'source_checks':{name:(index==0)
                                  for index,name in
                                  enumerate(NATIVE_RULES[rid][1])}}
                    for rid in batch.p345.IDS},
        }
        self.mg0={
            'rule_count':100,'operation_bound':True,
            'operation_sha256':OPERATION,'attempt_id':ATTEMPT,
            'individual_mg0_passes':0,'advancement_authorized':False,
            'audit_sha256':A_SHA,'audit_tail_sha256':TAIL,
            'rules':{rid:{'verdict':'UNKNOWN'} for rid in batch.COHORT},
        }

    def run_batch(self):
        with (patch.object(batch.p1,'inspect',return_value=self.reports[0]) as p1,
              patch.object(batch.p345,'inspect',return_value=self.reports[1]) as p345,
              patch.object(batch.p678,'inspect',return_value=self.reports[2]) as p678,
              patch.object(batch.mg0,'inspect_batch',return_value=self.mg0) as mg0,
              patch('c07_p345_macro_execution.run',
                    return_value=self.p345_macro) as macro,
              patch('c07_p1_design_source_review.inspect',
                    return_value=self.p1_design) as design,
              patch('c07_p1_remaining_visual_review.inspect_family',
                    return_value=self.p1_quant) as quantitative,
              patch('c07_p6_collision_semantics.inspect',
                    return_value=self.p678_specific['P6_COLLISION']) as col,
              patch('c07_p6_walkability_semantics.inspect',
                    return_value=self.p678_specific['P6_WALKABILITY']) as walk,
              patch('c07_p7_rage_semantics.inspect',
                    return_value=self.p678_specific['P7_RAGE']) as rage,
              patch('c07_p8_final_qa_semantics.inspect',
                    return_value=self.p678_specific['P8_FINAL']) as qa):
            result=batch.inspect(self.inv,self.plan,Controller(),'GARDEN','STEP100',
                                 self.work,source_loader=lambda path:b'')
            for reader in (p1,p345,p678):
                reader.assert_called_once()
            self.assertEqual(mg0.call_args.kwargs['operation_sha256'],OPERATION)
            # The execution certificate independently replays the same
            # immutable original Controller context, not the producer report.
            self.assertEqual(macro.call_count,2)
            self.assertEqual(macro.call_args_list[0].args[0],
                             macro.call_args_list[1].args[0])
            design.assert_called_once()
            quantitative.assert_called_once()
            self.assertEqual(quantitative.call_args.args[0]['work'],self.work)
            self.assertEqual(result['p1_thirteen_original_quantitative'],
                             self.p1_quant)
            for reader in (col,walk,rage,qa):
                reader.assert_called_once()
                self.assertEqual(reader.call_args.args[:2],(self.inv,self.plan))
            self.assertEqual(result['p678_thirty_rule_specific_original'],
                             self.p678_specific)
            self.assertEqual(design.call_args.args[:2],(self.inv,self.plan))
            self.assertEqual(result['p1_thirteen_original_design'],self.p1_design)
            self.assertEqual(macro.call_args.args[0]['work'],self.work)
            self.assertEqual(result['p345_forty_source_macro'],self.p345_macro)
            self.assertEqual(mg0.call_args.args[4],sorted(batch.COHORT))
            return result

    def test_exact_100_distinct_canonical_ids_and_zero_fake_passes(self):
        self.assertEqual(len(batch.COHORT),100)
        self.assertEqual(len(set(batch.COHORT)),100)
        result=self.run_batch()
        self.assertEqual(result['rule_count'],100)
        families=result['whole_family_macro_code_review']
        self.assertEqual([m['rule_count'] for m in families['macros']],
                         [30,40,30])
        self.assertFalse(families['advancement_authorized'])
        self.assertFalse(families['c07_finished'])
        self.assertEqual(set(result['rules']),set(batch.COHORT))
        self.assertEqual(result['original_source_predicates_observed'],100)
        self.assertEqual(result['full_reviewed_new'],0)
        self.assertEqual(result['individual_mg0_passes'],0)
        self.assertEqual(result['full_semantic_passes'],0)
        self.assertFalse(result['advancement_authorized'])
        for rid,row in result['rules'].items():
            with self.subTest(rule=rid):
                self.assertEqual(row['full_literal_semantic_verdict'],'UNKNOWN')
                self.assertEqual(row['individual_mg0'],'UNKNOWN')
                self.assertIn('INDEPENDENT_FULL_LITERAL_REVIEW_UNVERIFIED',
                              row['missing_positive_proof'])
                self.assertFalse(row['reviewed_enrollment_authorized'])

    def test_each_rule_source_observation_is_not_an_automatic_full_pass(self):
        for index,ids,field in (
            (0,batch.p1.IDS,'original_native_measured_criteria'),
            (1,batch.p345.IDS,'machine_observations'),
            (2,batch.p678.IDS,'native_original_machine_evidence'),
        ):
            rid=ids[0]
            first=next(iter(self.reports[index]['rules'][rid][field]))
            self.reports[index]['rules'][rid][field][first]=False
            result=self.run_batch()
            self.assertFalse(result['rules'][rid]['source_predicates_observed'])
            self.assertIn('ORIGINAL_SOURCE_PREDICATE_UNPROVEN',
                          result['rules'][rid]['missing_positive_proof'])
            self.reports[index]['rules'][rid][field][first]=True

    def test_mg0_fail_on_exact_operation_is_never_lost(self):
        rid=batch.COHORT[2]
        self.mg0['rules'][rid]['verdict']='FAIL'
        result=self.run_batch()
        self.assertEqual(result['mg0_fail_count'],1)
        self.assertEqual(result['rules'][rid]['full_literal_semantic_verdict'],'FAIL')
        self.assertEqual(result['full_semantic_passes'],0)

    def test_cross_operation_and_original_audit_replay_rejected(self):
        for key,bad in (('operation_sha256','0'*64),
                        ('attempt_id','1'*64),
                        ('original_audit_sha256','2'*64),
                        ('original_audit_tail','3'*64)):
            report=self.reports[1]
            prior=report[key]
            report[key]=bad
            with self.subTest(key=key):
                with self.assertRaisesRegex(batch.NativeBatchBlocked,
                                            'ORIGINAL_READER_CONTEXT_CHANGED'):
                    self.run_batch()
            report[key]=prior

    def test_forged_full_rule_or_mg0_pass_rejected(self):
        rid=batch.COHORT[0]
        self.reports[0]['rules'][rid]['full_rule_semantics']='PASS'
        with self.assertRaisesRegex(batch.NativeBatchBlocked,'PER_RULE_ORIGINAL_PROOF_UNTRUSTED'):
            self.run_batch()
        self.reports[0]['rules'][rid]['full_rule_semantics']='UNKNOWN'
        self.mg0['rules'][rid]['verdict']='PASS'
        with self.assertRaisesRegex(batch.NativeBatchBlocked,'MG0_FALSE_POSITIVE'):
            self.run_batch()

    def test_p678_all_thirty_original_rules_reject_forged_pass_or_missing(self):
        self.p678_specific['P7_RAGE']['advancement_authorized']=True
        with self.assertRaisesRegex(batch.NativeBatchBlocked,
                                    'P678_FAMILY_ORIGINAL_READER_UNTRUSTED'):
            self.run_batch()
        self.p678_specific['P7_RAGE']['advancement_authorized']=False
        self.p678_specific['P8_FINAL']['rules'].pop(
            next(iter(self.p678_specific['P8_FINAL']['rules'])))
        with self.assertRaisesRegex(batch.NativeBatchBlocked,
                                    'P678_FAMILY_ORIGINAL_READER_UNTRUSTED'):
            self.run_batch()

    def test_p1_family_refuses_forged_design_approval_or_missing_id(self):
        self.p1_design['advancement_authorized']=True
        with self.assertRaisesRegex(batch.NativeBatchBlocked,
                                    'P1_DESIGN_THIRTEEN_ORIGINAL_RULES_UNTRUSTED'):
            self.run_batch()
        self.p1_design['advancement_authorized']=False
        self.p1_design['rules'].pop(next(iter(self.p1_design['rules'])))
        with self.assertRaisesRegex(batch.NativeBatchBlocked,
                                    'P1_DESIGN_THIRTEEN_ORIGINAL_RULES_UNTRUSTED'):
            self.run_batch()

    def test_p1_quantitative_family_rejects_forged_full_and_missing_original(self):
        self.p1_quant['advancement_authorized']=True
        with self.assertRaisesRegex(
                batch.NativeBatchBlocked,
                'C07_BATCH100_P1_QUANTITATIVE_SOURCE_REPLAY_UNTRUSTED'):
            self.run_batch()
        self.p1_quant['advancement_authorized']=False
        self.p1_quant['rules'].pop(next(iter(self.p1_quant['rules'])))
        with self.assertRaisesRegex(
                batch.NativeBatchBlocked,
                'C07_BATCH100_P1_QUANTITATIVE_SOURCE_REPLAY_UNTRUSTED'):
            self.run_batch()

    def test_p345_macro_refuses_forged_40_rule_approval_or_missing(self):
        self.p345_macro['advancement_authorized']=True
        with self.assertRaisesRegex(batch.NativeBatchBlocked,
                                    'P345_MACRO_NOT_EXECUTED_OR_UNTRUSTED'):
            self.run_batch()
        self.p345_macro['advancement_authorized']=False
        self.p345_macro['rows'].pop(batch.p345.IDS[0])
        with self.assertRaisesRegex(batch.NativeBatchBlocked,
                                    'P345_MACRO_NOT_EXECUTED_OR_UNTRUSTED'):
            self.run_batch()

    def test_40_visited_with_one_blocked_is_not_certified(self):
        rid=batch.p345.IDS[10]
        self.p345_macro['rows'][rid]['machine_result']='BLOCKED'
        self.p345_macro['rows'][rid]['blocked_reason']='original missing'
        self.p345_macro['rows'][rid]['source_checks']={}
        self.p345_macro['result_counts']['BLOCKED']=1
        self.p345_macro['result_counts']['UNKNOWN']=39
        with self.assertRaisesRegex(ValueError,
                                    'C07_P345_CERTIFICATE_SOURCE_REPLAY_BLOCKED'):
            self.run_batch()

    def test_missing_exact_operation_pin_and_source_requirement_rejected(self):
        self.mg0['operation_bound']=False
        with self.assertRaisesRegex(batch.NativeBatchBlocked,
                                    'INDEPENDENT_OPERATION_MG0_UNTRUSTED'):
            self.run_batch()
        self.mg0['operation_bound']=True
        rid=batch.COHORT[0]
        self.reports[0]['rules'][rid]['requirement_sha256']='e'*64
        with self.assertRaisesRegex(batch.NativeBatchBlocked,
                                    'PER_RULE_ORIGINAL_PROOF_UNTRUSTED'):
            self.run_batch()


if __name__=='__main__':
    unittest.main()

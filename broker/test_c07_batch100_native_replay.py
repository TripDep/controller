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
        self.p345_macro={
            'canonical_rule_count':40,'due_count':40,
            'visited_due_count':40,
            'attempt_id':ATTEMPT,
            'operation_sha256':OPERATION,
            'advancement_authorized':False,
            'individual_mg0_independently_approved':False,
            'fivem_runtime_approved':False,'owner_approved':False,
            'rows':{rid:{'machine_result':'UNKNOWN'}
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
                    return_value=self.p345_macro) as macro):
            result=batch.inspect(self.inv,self.plan,Controller(),'GARDEN','STEP100',
                                 self.work,source_loader=lambda path:b'')
            for reader in (p1,p345,p678):
                reader.assert_called_once()
            self.assertEqual(mg0.call_args.kwargs['operation_sha256'],OPERATION)
            macro.assert_called_once()
            self.assertEqual(macro.call_args.args[0]['work'],self.work)
            self.assertEqual(result['p345_forty_source_macro'],self.p345_macro)
            self.assertEqual(mg0.call_args.args[4],sorted(batch.COHORT))
            return result

    def test_exact_100_distinct_canonical_ids_and_zero_fake_passes(self):
        self.assertEqual(len(batch.COHORT),100)
        self.assertEqual(len(set(batch.COHORT)),100)
        result=self.run_batch()
        self.assertEqual(result['rule_count'],100)
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

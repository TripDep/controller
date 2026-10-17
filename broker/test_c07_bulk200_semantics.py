"""R115: adversarial 200-rule execution fixtures (not genuine asset approval)."""
import hashlib
import unittest
from unittest.mock import patch
import c07_bulk200_semantics as bulk

HEX='a'*64

def build():
    first=['110_ERROR_REGISTRY','A']+[
        'AAA-200-'+chr(65+(i-1)//10)+'-'+str(i).zfill(3)
        for i in range(1,199)]
    total=first+['Q-%03d'%i for i in range(1,564)]
    assert len(total)==763
    rows={rid:{'family':'AAA-200' if rid.startswith('AAA-') else 'OTHER',
                'requirement':'REQUIREMENT '+rid,
                'source_sha256':'b'*64,
                'requirement_sha256':hashlib.sha256(('REQUIREMENT '+rid).encode()).hexdigest(),
                'catalog_section':rid.split('-')[2] if rid.startswith('AAA-') else None}
          for rid in total}
    families={'AAA-200': [rid for rid in total if rid.startswith('AAA-')],
              'OTHER': [rid for rid in total if not rid.startswith('AAA-')]}
    inv={'schema':'gg-effective-family-inventory-v1',
         'rule_count':763,'family_count':2,
         'canonical_master_sha256':HEX,'rules':rows,'families':families}
    plan={'master_sha256':HEX,'phase':'P8','asset_type':'architecture','profiles':['ARCHITECTURE_PROFILE'],'enrolled':{}}
    entries={rid:{'requirement_sha256':row['requirement_sha256'],
                  'source_sha256':row['source_sha256'],
                  'questions':[{'id':rid+':REQUIREMENT','text':'Real source requirement?'}]}
             for rid,row in rows.items()}
    applicability={'by_rule':{rid:{'disposition':'DUE'} for rid in total},'due':sorted(total)}
    return inv,plan,{'entries':entries},applicability

class Tests(unittest.TestCase):
    def setUp(self):
        self.inv,self.plan,ledger,scope=build()
        self.patches=[
            patch.object(bulk.questions,'build',return_value=ledger),
            patch.object(bulk.scope,'inspect',return_value=scope),
            patch.object(bulk.compounds,'inspect',return_value={'due_composites':{
                'AAA-200-G-067':{'source_subcheck_count':3}}}),
        ]
        for p in self.patches:p.start()
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])

    def test_first_200_executed_with_distinct_proof_lanes(self):
        out=bulk.inspect(self.inv,self.plan)
        self.assertEqual(out['source_rule_count'],200)
        self.assertEqual([p['count'] for p in out['batch_segments']],[100,100])
        self.assertEqual(out['counts']['DUE'],200)
        self.assertEqual(out['counts']['UNKNOWN'],200)
        self.assertEqual(out['counts']['FAIL'],0)
        self.assertFalse(out['complete_200_semantic_certifications'])
        self.assertFalse(out['advancement_authorized'])
        self.assertNotEqual(out['rules']['AAA-200-A-001']['required_independent_evidence_lanes'],
                            out['rules']['AAA-200-G-065']['required_independent_evidence_lanes'])
        self.assertEqual(out['rules']['AAA-200-G-067']['composite_source_clauses'],3)
        self.assertEqual(len(out['rules']),200)

    def test_registered_one_sha_bound_glb_replays_all_200_not_12(self):
        def scanned(path,sha,ctx,ids):
            self.assertEqual(len(ids),200)
            self.assertEqual(sha,'e'*64)
            self.assertEqual(ctx['attempt_id'],'c'*64)
            return {'rule_count':200,
                    'rules':{rid:{'independent_native_rule_observation':'FAIL'
                         if rid=='AAA-200-G-065' else 'UNKNOWN',
                         'native_negative_findings':['BAD_WINDING']
                         if rid=='AAA-200-G-065' else []} for rid in ids},
                    'work_rule_passes':0,'individual_mg0_passes':0,
                    'advancement_authorized':False}
        first=set(sorted(self.inv['rules'])[:200]);rs={rid:{'semantic_negative_verdict':'UNKNOWN'} for rid in self.inv['rules']}
        neg={'rule_count':763,'batch_counts':[200,200,200,163],
             'batches':[{'rules':dict(list(rs.items())[i:i+200])} for i in range(0,763,200)],
             'positive_semantic_passes':0,'individual_mg0_passes':0,
             'advancement_authorized':False}
        with patch.object(bulk,'inspect_negative',return_value=neg),patch.object(bulk,'verify_live_batch',side_effect=scanned) as scanner:
            out=bulk.inspect(self.inv,self.plan,audit_raw=b'valid source supplied via mocked trusted reader',
                    asset='TEST',attempt_id='c'*64,operation_sha256='d'*64,
                    registered_glb_path='/some/registered.glb',glb_sha256='e'*64)
        self.assertEqual(scanner.call_count,1)
        self.assertEqual(out['counts']['REGISTERED_GLB_BATCH_SLOTS_SCANNED'],200)
        self.assertEqual(out['failed_due_rule_ids'],['AAA-200-G-065'])
        self.assertEqual(out['counts']['FAIL'],1)
        self.assertEqual(out['counts']['UNKNOWN'],199)
        self.assertFalse(out['advancement_authorized'])

    def test_missing_registration_without_audit_rejected(self):
        with self.assertRaisesRegex(bulk.BatchBlocked,'REQUIRES_TRUSTED_AUDIT'):
            bulk.inspect(self.inv,self.plan,registered_glb_path='/tmp/synthetic.glb',glb_sha256='e'*64)

    def test_duplicate_or_missing_canonical_source_rejected(self):
        self.inv['families']['AAA-200'].append('A')
        with self.assertRaisesRegex(bulk.BatchBlocked,'MEMBERSHIP_CHANGED'):
            bulk.inspect(self.inv,self.plan)

    def test_requirement_unchanged_by_assistant(self):
        inv,plan,ledger,scope=build()
        inv['rules']['AAA-200-A-004']['requirement_sha256']='f'*64
        with patch.object(bulk.questions,'build',return_value=ledger):
            with self.assertRaisesRegex(bulk.BatchBlocked,'SOURCE_REQUIREMENT_DRIFT'):
                bulk.inspect(inv,plan)

    def test_historic_document_pass_not_production_pass(self):
        docs={'results':{rid:{'documentary_result':'PASS','documentary_checks':{'c':True}}
                         for rid in ['AAA-200-A-008','AAA-200-A-009',
                                     'AAA-200-B-011','AAA-200-B-013',
                                     'AAA-200-B-014','AAA-200-B-015',
                                     'AAA-200-B-016','AAA-200-B-017',
                                     'AAA-200-B-018','AAA-200-B-019','AAA-200-B-020']},
              'individual_rule_mg0_passes':0,'advancement_authorized':False}
        with patch('r173_rule_semantics.inspect',return_value=docs):
            x=bulk.inspect(self.inv,self.plan,r173_qa_raw=b'QA',r173_catalog_raw=b'catalog')
        self.assertEqual(x['counts']['HISTORICAL_DOCUMENTARY_EVALUATED'],11)
        self.assertEqual(x['counts']['UNKNOWN'],200)
        self.assertEqual(x['positive_semantic_and_mg0_rule_passes'],0)
        self.assertFalse(x['advancement_authorized'])

    def test_partial_audit_binding_rejected(self):
        with self.assertRaisesRegex(bulk.BatchBlocked,'EXACT_AUDIT_ALL_OR_NOTHING'):
            bulk.inspect(self.inv,self.plan,audit_raw=b'one line',asset='TEST')

if __name__=='__main__':unittest.main()

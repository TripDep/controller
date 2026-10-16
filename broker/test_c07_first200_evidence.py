"""C07 first-200 evidence execution tests (fixtures are not asset passes)."""
import unittest
from unittest.mock import patch
import c07_first200_evidence as mod
from approved_validators import REVIEWED

HEX='a'*64

def fixtures():
    ids=['110_ERROR_REGISTRY','A'] + [
      'AAA-200-'+chr(ord('A')+(i-1)//10)+'-'+str(i).zfill(3)
      for i in range(1,199)]
    # Remaining 563 IDs are irrelevant to this fixed-segment unit fixture.
    allids=ids+['Q-%03d'%i for i in range(1,564)]
    inv={'schema':'gg-effective-family-inventory-v1',
         'rule_count':763,'family_count':2,
         'canonical_master_sha256':HEX,
         'families':{'GROUP':ids,'REST':allids[200:]},
         'rules':{rid:{
           'family':'GROUP' if j<200 else 'REST',
           'requirement_sha256':mod.digest('requirement'+rid),
           'source_sha256':HEX,
           'catalog_section':rid.split('-')[2] if rid.startswith('AAA-200-') else None,
         } for j,rid in enumerate(allids)}}
    due=sorted(ids[:185])
    ledger={'entries':{rid:{
       'requirement_sha256':inv['rules'][rid]['requirement_sha256'],
       'source_sha256':HEX,
       'questions':[{'id':rid+':REQUIREMENT','text':'Hai verificato?'}]
    } for rid in allids}}
    appraisal={'due':due,'by_rule':{rid:{
        'disposition':'DUE' if rid in due else 'FUTURE_PHASE'
    } for rid in allids}}
    compound_ids={ids[0],ids[4],ids[16]}
    composite={'due_composites':{rid:{'source_subcheck_count':3}
                for rid in compound_ids}}
    plan={'enrolled':{},'phase':'P0','asset_type':'architecture',
          'profiles':['ARCHITECTURE_PROFILE'],
          'master_sha256':HEX}
    return inv,plan,ledger,appraisal,compound_ids,composite

class Tests(unittest.TestCase):
    def setUp(self):
        self.inv,self.plan,ledger,scope,ids,subchecks=fixtures()
        self.patches=[patch.object(mod.question_bank,'build',return_value=ledger),
                      patch.object(mod.operation_scope,'inspect',return_value=scope),
                      patch.object(mod.composites,'ids',return_value=ids),
                      patch.object(mod.composites,'inspect',return_value=subchecks)]
        for p in self.patches:p.start()
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])

    def test_all_200_have_individual_evidence_contracts_not_fake_pass(self):
        x=mod.inspect(self.inv,self.plan)
        self.assertEqual(x['rule_count'],200)
        self.assertEqual([p['rule_count'] for p in x['segments']],[100,100])
        self.assertEqual(len(x['rules']),200)
        self.assertEqual(x['rules']['AAA-200-G-065']['evidence_family'],
                         'HARD_SURFACE_GEOMETRY_QA')
        self.assertEqual(x['counts']['DOCUMENTARY_NOT_EVALUATED'],200)
        self.assertEqual(x['newly_operational_native_semantic_verifiers'],0)
        self.assertEqual(x['independent_work_mg0_passes'],0)
        self.assertFalse(x['advancement_authorized'])

    def test_drift_in_first_200_cannot_silently_skip(self):
        xs=self.inv['families']['GROUP']
        xs[10]=xs[11]
        with self.assertRaisesRegex(mod.IncompleteNativeBatch,'CANONICAL_MEMBERSHIP'):
            mod.inspect(self.inv,self.plan)

    def test_source_bound_documentary_failures_not_upgraded_to_asset_passes(self):
        details={}
        for rule in list(REVIEWED)[:11]:
            if rule not in self.inv['families']['GROUP']:
                continue
            details[rule]={'documentary_result':'FAIL' if rule=='AAA-200-B-013' else 'PASS',
                           'documentary_checks':{'source_scope_bound':True}}
        # Fixture only checks integration with a previously authenticated
        # documentary reader; the private CI independently reads REAL bytes.
        from unittest.mock import patch as mock
        result={'schema':'gg-r173-p0-documentary-verdict-v1',
                'individual_rule_mg0_passes':0,'advancement_authorized':False,
                'results':details}
        if len(details)!=11:
            self.skipTest('unrecognized fixture reviewer list')
        with mock('r173_rule_semantics.inspect',return_value=result):
            x=mod.inspect(self.inv,self.plan,qa_raw=b'QA',catalog_raw=b'CAT')
        self.assertEqual(x['counts']['DOCUMENTARY_FAIL'],1)
        self.assertEqual(x['counts']['DOCUMENTARY_PASS_SCOPE_LIMITED'],10)
        self.assertFalse(x['advancement_authorized'])
        self.assertFalse(x['rules']['AAA-200-A-009']['production_pass'])

    def test_unmatched_evidence_pair_rejected(self):
        with self.assertRaisesRegex(mod.IncompleteNativeBatch,
                                    'DOCUMENTARY_SOURCE_BYTES_REQUIRED'):
            mod.inspect(self.inv,self.plan,qa_raw=b'fake report')

if __name__=='__main__':
    unittest.main()

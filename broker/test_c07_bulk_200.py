"""Batch 200 tests: synthetic structure only. Private CI checks real sources."""
import unittest
from unittest.mock import patch

import c07_bulk_200 as b

MASTER='a'*64
REVIEWER='AAA-200-B-012'

def fixture():
    ids=['Q-%03d'%n for n in range(1,763)]+[REVIEWER]
    families={'TEST':ids}
    inv={'schema':'gg-effective-family-inventory-v1','canonical_master_sha256':MASTER,
         'rule_count':763,'family_count':1,'families':families,
         'rules':{rid:{'family':'TEST','requirement_sha256':b.digest(rid),
                       'source_sha256':MASTER} for rid in ids}}
    plan={'master_sha256':MASTER,'phase':'P0','asset_type':'architecture',
          'profiles':['ARCHITECTURE_PROFILE'],'enrolled':{}}
    entries={rid:{'family':'TEST','requirement_sha256':b.digest(rid),
                  'source_sha256':MASTER,'questions':[{'text':'Hai verificato '+rid+'?'}],
                  'classification':'YES_NO_WORDING_REVIEWED_PROOF_PENDING',
                  'compound_subchecks_pending':rid in set(ids[:72])} for rid in ids}
    ledger={'rule_count':763,'wording_reviewed_count':758,'reviewed_count':5,
            'generic_count':0,'compound_pending_count':72,'entries':entries}
    due=sorted(ids[:600])
    by={rid:{'disposition':'DUE' if rid in due else 'FUTURE_PHASE'} for rid in ids}
    application={'due':due,'future_phase':sorted(set(ids)-set(due)),
                 'not_applicable':[],'context_excluded':[],
                 'by_rule':by,'due_without_reviewed_native_verifier':due}
    allcomp=set(ids[:72])
    cp={'canonical_composite_count':72,'due_composite_count':72,
        'due_composites':{rid:{'source_subcheck_count':2,
                  'source_decomposition':'SOURCE_CANDIDATE'} for rid in allcomp}}
    return inv,plan,ledger,application,allcomp,cp

class Tests(unittest.TestCase):
    def setUp(self):
        self.inv,self.plan,self.ledger,self.app,self.comp,self.report=fixture()
        self.patches=[
            patch.object(b.answers,'build',return_value=self.ledger),
            patch.object(b.scope,'inspect',return_value=self.app),
            patch.object(b.compound,'inspect',return_value=self.report),
            patch.object(b.compound,'ids',return_value=self.comp)]
        for p in self.patches:p.start()
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])

    def test_four_batches_source_checked_all_763_no_operational_pass(self):
        result=b.inspect(self.inv,self.plan)
        self.assertEqual([x['count'] for x in result['batches']],[200,200,200,163])
        self.assertEqual(result['reviewed_canonical_source_rules'],763)
        self.assertEqual(result['applicability']['DUE'],600)
        self.assertEqual(result['independent_semantic_and_mg0_passes'],0)
        self.assertEqual(result['canonical_composites'],72)
        self.assertFalse(result['advancement_authorized'])
        self.assertEqual(sum(len(x['rules']) for x in result['batches']),763)
        self.assertEqual(set.union(*(set(x['rules']) for x in result['batches'])),
                         set(self.inv['rules']))

    def test_100_rule_batches_are_supported(self):
        x=b.inspect(self.inv,self.plan,batch_size=100)
        self.assertEqual([v['count'] for v in x['batches']],[100]*7+[63])
        self.assertEqual(x['batch_count'],8)

    def test_due_rule_missing_semantics_stays_unknown_not_pass(self):
        result=b.inspect(self.inv,self.plan)
        row=next(r['rules']['Q-001'] for r in result['batches']
                 if 'Q-001' in r['rules'])
        self.assertEqual(row['individual_mg0'],'UNKNOWN')
        self.assertEqual(row['current_asset_semantic_verdict'],'UNKNOWN')
        self.assertIn('NO_REVIEWED_NATIVE_SEMANTIC_IMPLEMENTATION',row['blockers'])
        self.assertIn('NOT_ENROLLED_IN_CONTROLLER_PLAN',row['blockers'])

    def test_partial_or_forged_mg0_cannot_be_claimed(self):
        fake={'schema':'gg-c07-mg0-canonical-batch-readback-v1',
              'master_sha256':MASTER,'rule_count':600,'rules':{},
              'advancement_authorized':False,'individual_mg0_passes':0,
              'counts':{'PASS':0}}
        with self.assertRaisesRegex(b.BatchBlocked,'UNTRUSTED_MG0_BINDING'):
            b.inspect(self.inv,self.plan,mg0=fake)

    def test_duplicate_source_id_and_question_drift_are_blocked(self):
        self.inv['families']['TEST'][-1]=self.inv['families']['TEST'][0]
        with self.assertRaisesRegex(b.BatchBlocked,'CANONICAL_SET_DRIFT'):
            b.inspect(self.inv,self.plan)

    def test_invalid_batch_size_not_silently_accepted(self):
        with self.assertRaisesRegex(b.BatchBlocked,'CHUNK_SIZE'):
            b.inspect(self.inv,self.plan,batch_size=199)

if __name__=='__main__':
    unittest.main()

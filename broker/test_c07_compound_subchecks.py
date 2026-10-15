"""C07 composite negative tests; source extraction is never asset QA."""
import hashlib
import unittest
from unittest.mock import patch

import c07_compound_subchecks as c
import c07_answer_semantics as answers
from test_c07_answer_semantics import Reviewed758Regression


def sha(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def source_30():
    return ('### Exact recovered 30-control source list\n\n'
            + ''.join(str(n)+'. Control source '+str(n)+' for this piece.\n'
                      for n in range(1,31))
            + '\n### G0 canonical role\n')


class CanonicalCompositeSourceTests(unittest.TestCase):
    def test_exactly_72_reviewed_source_flags(self):
        inv = Reviewed758Regression().inventory()
        self.assertEqual(len(c.ids(inv)),72)
        self.assertIn('G0',c.ids(inv))
        self.assertIn('MG0',c.ids(inv))
        self.assertIn('P8',c.ids(inv))

    def test_real_g0_source_count_cannot_shrink_to_17(self):
        rows, status = c.clauses('G0',source_30())
        self.assertEqual(len(rows),30)
        self.assertEqual(rows[0][0],1)
        self.assertEqual(rows[-1][0],30)
        self.assertIn('NOT_SEMANTICALLY_VERIFIED',status)
        incomplete=source_30().replace('20. Control source 20 for this piece.\n','')
        with self.assertRaisesRegex(c.IncompleteComposite,
                                    'C07_G0_NOT_ALL_30_SOURCE_CONTROLS'):
            c.clauses('G0',incomplete)

    def test_unlisted_composite_never_claims_complete_source_split(self):
        rows, state = c.clauses('Q','STOP -> DOMANDA -> COMPRENSIONE VERIFICATA')
        self.assertEqual(len(rows),1)
        self.assertEqual(state,'UNSPLIT_COMPOSITE_REVIEW_PENDING')

    def sample(self,src='Must check both\n- verified source baseline\n- dependent geometry'):
        inv={'schema':'gg-effective-family-inventory-v1',
             'canonical_master_sha256':'a'*64,'rule_count':1,
             'rules':{'A':{'family':'MASTER_CHAIN','requirement':src,
                           'requirement_sha256':sha(src),'source_sha256':'e'*64}}}
        with patch.object(c,'ids',return_value={'A'}):
            report=c.inspect(inv,['A'])
        self.assertEqual(report['due_composite_count'],1)
        self.assertEqual(len(report['due_composites']['A']['subchecks']),2)
        return report

    def packet(self,report,index,answer='YES'):
        sc=report['due_composites']['A']['subchecks'][index]
        return {'rule_id':'A','subcheck_id':sc['subcheck_id'],
                'clause_sha256':sc['clause_sha256'],
                'master_sha256':report['master_sha256'],
                'attempt_id':'b'*64,'operation_sha256':'d'*64,
                'answer':answer,'evidence_refs':[]}

    def assess(self,report,packets):
        return c.assess(report,packets,attempt_id='b'*64,
                        operation_sha256='d'*64)

    def test_missing_subcontrols_point_to_exact_source_clause(self):
        r=self.sample()
        a=self.assess(r,[self.packet(r,0)])
        self.assertEqual(a['result'],'UNKNOWN')
        self.assertEqual(a['missing'][0]['subcheck_id'],'A:SC002')
        self.assertFalse(a['advancement_authorized'])

    def test_no_to_one_subcontrol_is_precise_fail(self):
        r=self.sample()
        a=self.assess(r,[self.packet(r,0,'YES'),self.packet(r,1,'NO')])
        self.assertEqual(a['result'],'FAIL')
        self.assertEqual(a['failed'][0]['subcheck_id'],'A:SC002')

    def test_all_positive_is_unknown_without_independent_proof(self):
        r=self.sample()
        a=self.assess(r,[self.packet(r,0),self.packet(r,1)])
        self.assertEqual(a['result'],'UNKNOWN')
        self.assertFalse(a['independent_subcontrol_proof_verified'])
        self.assertFalse(a['advancement_authorized'])

    def test_duplicate_replay_and_unknown_subcontrol_rejected(self):
        r=self.sample()
        p=self.packet(r,0)
        with self.assertRaisesRegex(c.IncompleteComposite,'DUPLICATE'):
            self.assess(r,[p,p])
        q=dict(p,attempt_id='f'*64)
        with self.assertRaisesRegex(c.IncompleteComposite,'REPLAY'):
            self.assess(r,[q])
        q=dict(p,subcheck_id='A:SC999')
        with self.assertRaisesRegex(c.IncompleteComposite,'UNKNOWN_SUBCHECK'):
            self.assess(r,[q])
        q=dict(p,clause_sha256='0'*64)
        with self.assertRaisesRegex(c.IncompleteComposite,'REPLAY'):
            self.assess(r,[q])

    def test_no_magic_hash_makes_self_report_a_pass(self):
        r=self.sample()
        p=self.packet(r,0)
        p['evidence_refs']=[{'ref':'unverified:pointer','sha256':'f'*64}]
        a=self.assess(r,[p,self.packet(r,1)])
        self.assertEqual(a['result'],'UNKNOWN')
        self.assertFalse(a['independent_subcontrol_proof_verified'])


if __name__=='__main__':
    unittest.main()

"""Answer ingress regression; checks no self-declaration can claim asset PASS."""
import unittest
from unittest.mock import patch

import c07_live_answer_gate as gate
import c07_answer_semantics as contract
from test_c07_answer_semantics import fixture, answer


class AnswerGateTests(unittest.TestCase):
    def setUp(self):
        self.inventory = fixture()
        self.ledger = contract.build(self.inventory)
        self.plan = {'phase': 'P0', 'asset_type': 'architecture',
                     'master_sha256': self.inventory['canonical_master_sha256']}
        self.work = {'phase': 'P0', 'master_sha256': self.inventory['canonical_master_sha256'],
                     'work_item_sha256': 'a'*64, 'attempt_id': 'b'*64,
                     'attempt_number': 1, 'previous_attempt_id': None,
                     'operation_sha256': 'd'*64}
        self.checkpoint = {'asset': 'TEST', 'next_step': 3,
                           'last_audit_hash': 'f'*64, 'plan_record_hash': 'e'*64}
        self.patches = [patch.object(gate.scope, 'inspect', return_value={
            'due': ['AAA-200-G-067']}),
            patch.object(contract, 'build', return_value=self.ledger)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def review(self, packets):
        return gate.inspect(self.inventory, self.plan, self.work,
                            packets, self.checkpoint)

    def test_missing_is_stopped_with_precise_question(self):
        r = self.review([])
        self.assertEqual(r['missing'][0]['rule_id'], 'AAA-200-G-067')
        self.assertIn('DUE_QUESTIONS_NOT_ANSWERED', r['blocking_reasons'])
        self.assertFalse(r['may_request_native_proof'])

    def test_no_to_checked_is_fail(self):
        p = [answer(self.ledger, 'AAA-200-G-067:CHECK', 'NO'),
             answer(self.ledger, 'AAA-200-G-067:REMAIN', 'NO')]
        r = self.review(p)
        self.assertEqual(r['answer_verdict'], 'FAIL')
        self.assertEqual(r['failed'][0]['question_id'], 'AAA-200-G-067:CHECK')
        self.assertFalse(r['advancement_authorized'])

    def test_yes_to_defects_remaining_is_fail(self):
        p = [answer(self.ledger, 'AAA-200-G-067:CHECK', 'YES'),
             answer(self.ledger, 'AAA-200-G-067:REMAIN', 'YES')]
        self.assertEqual(self.review(p)['failed'][0]['question_id'], 'AAA-200-G-067:REMAIN')

    def test_yes_and_no_defect_still_only_await_native_proof(self):
        p = [answer(self.ledger, 'AAA-200-G-067:CHECK', 'YES'),
             answer(self.ledger, 'AAA-200-G-067:REMAIN', 'NO')]
        r = self.review(p)
        self.assertTrue(r['may_request_native_proof'])
        self.assertEqual(r['answer_verdict'], 'UNKNOWN')
        self.assertFalse(r['individual_mg0_verified'])
        self.assertFalse(r['advancement_authorized'])

    def test_compound_due_stays_blocked_even_with_answers(self):
        p = [answer(self.ledger, 'AAA-200-G-067:CHECK', 'YES'),
             answer(self.ledger, 'AAA-200-G-067:REMAIN', 'NO')]
        self.ledger['entries']['AAA-200-G-067']['compound_subchecks_pending'] = True
        r = self.review(p)
        self.assertEqual(r['compound_subchecks_unverified'], ['AAA-200-G-067'])
        self.assertFalse(r['may_request_native_proof'])

    def test_replay_attempt_denied(self):
        p = [answer(self.ledger, 'AAA-200-G-067:CHECK', 'NO')]
        p[0]['attempt_id'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'ANSWER_REPLAY_OR_DRIFT'):
            self.review(p)

    def test_due_list_cannot_be_supplied_by_assistant(self):
        p = [answer(self.ledger, 'Q-075:DEFECT', 'YES')]
        with self.assertRaisesRegex(ValueError, 'ANSWER_UNREVIEWED_OR_NOT_DUE'):
            self.review(p)

    def test_controller_question_batch_is_attempt_bound_read_only(self):
        batch = gate.challenge(self.inventory, self.plan, self.work, self.checkpoint)
        self.assertEqual(batch['question_count'], 2)
        self.assertEqual({q['question_id'] for q in batch['questions']},
                         {'AAA-200-G-067:CHECK', 'AAA-200-G-067:REMAIN'})
        self.assertTrue(all(q['source_sha256'] == 'c'*64 for q in batch['questions']))
        self.assertEqual(batch['attempt_id'], self.work['attempt_id'])
        self.assertEqual(batch['checkpoint']['plan_record_hash'],
                         self.checkpoint['plan_record_hash'])
        self.assertFalse(batch['advancement_authorized'])

    def test_controller_due_not_manipulated_by_answerer(self):
        batch = gate.challenge(self.inventory, self.plan, self.work, self.checkpoint)
        self.assertNotIn('Q-075:DEFECT', {q['question_id'] for q in batch['questions']})
        self.assertEqual(batch['due_rules_sha256'], gate.digest(['AAA-200-G-067']))

    def test_large_due_source_is_indexed_and_paged_without_scope_bypass(self):
        rid = 'AAA-200-G-067'
        self.ledger['entries'][rid]['compound_subchecks_pending'] = True
        rows = [{'subcheck_id': rid+':SC'+str(i).zfill(3),
                 'clause_sha256': 'a'*64, 'canonical_clause': 'source clause '+str(i)}
                for i in range(1,61)]
        contract = {'schema': 'gg-c07-canonical-composites-v1',
                    'master_sha256': self.ledger['master_sha256'],
                    'canonical_composite_count':72,'due_composite_count':1,
                    'due_composites':{rid:{
                        'family':'AAA-200','source_sha256':'c'*64,
                        'requirement_sha256':self.ledger['entries'][rid]['requirement_sha256'],
                        'source_decomposition':'SOURCE_LIST_CANDIDATES_REVIEW_PENDING',
                        'source_subcheck_count':60,'subchecks':rows}}}
        self.inventory['rule_count'] = 763
        with patch.object(gate.composites,'inspect',return_value=contract):
            batch=gate.challenge(self.inventory,self.plan,self.work,self.checkpoint,
                                 detail_rule=rid,subcheck_offset=20,subcheck_limit=20)
            self.assertEqual(batch['compound_source_subchecks'][rid]['source_subcheck_count'],60)
            self.assertNotIn('subchecks',batch['compound_source_subchecks'][rid])
            self.assertEqual(len(batch['selected_source_subcheck_page']['subchecks']),20)
            self.assertEqual(batch['selected_source_subcheck_page']['next_offset'],40)
            overview=gate.challenge(self.inventory,self.plan,self.work,self.checkpoint)
            self.assertIsNone(overview['selected_source_subcheck_page'])
            with self.assertRaisesRegex(ValueError,'C07_SUBCHECK_VIEW_NOT_DUE'):
                gate.challenge(self.inventory,self.plan,self.work,self.checkpoint,
                               detail_rule='Q-075')
            response=gate.inspect(self.inventory,self.plan,self.work,[],
                                  self.checkpoint,subcheck_packets=[])
            self.assertEqual(response['compound_answer_assessment']['missing_total'],60)
            self.assertEqual(len(response['compound_answer_assessment']['missing']),20)
            self.assertTrue(response['compound_answer_assessment']['missing_truncated'])
            self.assertFalse(response['advancement_authorized'])

    def test_evidence_reference_never_self_verifies(self):
        p = [answer(self.ledger, 'AAA-200-G-067:CHECK', 'YES',
                    refs=[{'ref': 'untrusted', 'sha256': 'f'*64}]),
             answer(self.ledger, 'AAA-200-G-067:REMAIN', 'NO')]
        r = self.review(p)
        self.assertTrue(r['unverified_evidence_refs'])
        self.assertFalse(r['independent_semantics_verified'])


if __name__ == '__main__':
    unittest.main()

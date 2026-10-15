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

    def test_evidence_reference_never_self_verifies(self):
        p = [answer(self.ledger, 'AAA-200-G-067:CHECK', 'YES',
                    refs=[{'ref': 'untrusted', 'sha256': 'f'*64}]),
             answer(self.ledger, 'AAA-200-G-067:REMAIN', 'NO')]
        r = self.review(p)
        self.assertTrue(r['unverified_evidence_refs'])
        self.assertFalse(r['independent_semantics_verified'])


if __name__ == '__main__':
    unittest.main()

import unittest
from pathlib import Path
from c07_macro100_controller import original_observations
from c07_macro100_domain import Context, evaluate
from c07_macro100_semantics import EVALUATORS


class OriginalObservationTests(unittest.TestCase):
    def test_registered_packet_cannot_supply_domain_observations(self):
        packet = {'event': 'ARTIFACT_RECORDED', 'role': 'C07_DOMAIN_OBSERVATIONS',
                  'observations': {'claims': [{'kind': 'OWNER_ACCEPTED'}],
                                   'owner_approvals': [{'decision': 'ACCEPT'}]}}
        result = original_observations([packet], {}, b'original master', Path('/master'))
        self.assertNotIn('claims', result)
        self.assertNotIn('owner_approvals', result)
        self.assertEqual(evaluate(EVALUATORS['BEHAVIOR-063'], Context(result)).result, 'UNKNOWN')

    def test_historical_master_check_is_not_complete_read_or_current_readback(self):
        record = {'event': 'STEP_CLOSE', 'result': 'PASS',
                  'master_check_after': {'sha256': 'a'*64, 'path': '/old/master'}}
        result = original_observations([record], {}, b'new master', Path('/master'))
        self.assertNotIn('source_reads', result)
        self.assertNotIn('readbacks', result)
        self.assertEqual(result['controller_records'], [record])
        self.assertEqual(evaluate(EVALUATORS['A'], Context(result)).result, 'UNKNOWN')

    def test_step_pass_cannot_become_runtime_or_artistic_pass(self):
        result = original_observations([{'event': 'STEP_CLOSE', 'result': 'PASS'}],
                                       {'delivery_status': 'VERIFIED'}, b'master', Path('/master'))
        self.assertNotIn('runs', result)
        self.assertNotIn('visual_reviews', result)
        self.assertNotIn('deliverables_after', result)


if __name__ == '__main__':
    unittest.main()

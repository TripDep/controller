"""Test actual hash-chained MG0 incident triage; never authorizes an asset."""
import unittest
from mg0_audit_semantics import inspect
from real_work_intake import IntakeBlocked, canonical, sha


class Tests(unittest.TestCase):
    def setUp(self):
        self.master = (b'## MG0 \xe2\x80\x94 PROCESS FALSIFICATION\n'
                       b'Canonical trigger pattern recovered from the old chat:\n'
                       b'The response is not limited to fixing the asset.\n'
                       b'Controller MG0 step `0035` closed `FAIL`\n')
        self.rows = []
        for item in (
            {'event': 'STEP_OPEN', 'step': '0035', 'authorization_token': 'A',
             'action': 'MG0 process-integrity audit', 'resolves': []},
            {'event': 'STEP_CLOSE', 'step': '0035', 'authorization_token': 'A',
             'action': 'MG0 process-integrity audit', 'result': 'FAIL',
             'evidence_operation': 'MG0 confirmed process inconsistency: synthetic'},
            {'event': 'STEP_OPEN', 'step': '0036', 'authorization_token': 'B',
             'action': 'Correct process', 'resolves': ['0035']},
            {'event': 'STEP_CLOSE', 'step': '0036', 'authorization_token': 'B',
             'action': 'Correct process', 'result': 'PASS'},
            {'event': 'BLOCKER_RESOLVED', 'step': '0036', 'resolves': '0035',
             'result': 'PASS'},
        ):
            item['asset'] = 'SOUTH_GATE_HIGH_V1'
            item['prev_hash'] = self.rows[-1]['record_hash'] if self.rows else 'GENESIS'
            item['record_hash'] = sha(canonical(item))
            self.rows.append(item)

    def inspect(self):
        audit = b'\n'.join(canonical(r) for r in self.rows) + b'\n'
        return inspect(self.master, audit, 'SOUTH_GATE_HIGH_V1', sha(self.master),
                       'AAA-200-B-012')

    def test_real_process_trigger_and_linked_correction_not_rule_pass(self):
        result = self.inspect()
        self.assertEqual(result['global_trigger'], 'CONFIRMED')
        self.assertEqual(len(result['trigger_events']), 1)
        self.assertEqual(result['trigger_events'][0]['correction_records'][0]['correction_step'],
                         '0036')
        self.assertEqual(result['individual_rule_mg0'], 'UNKNOWN')
        self.assertFalse(result['advancement_authorized'])
        self.assertFalse(result['current_attempt_reapplication_verified'])

    def test_no_audited_incident_never_becomes_not_triggered(self):
        self.rows = self.rows[:1]
        self.assertEqual(self.inspect()['global_trigger'], 'UNKNOWN')

    def test_master_must_confirm_the_same_incident(self):
        self.master = self.master.replace(b'Controller MG0 step `0035` closed `FAIL`',
                                          b'unsupported claim')
        with self.assertRaisesRegex(IntakeBlocked, 'MG0_MASTER_AUDIT_INCIDENT_NOT_RECONCILED'):
            self.inspect()

    def test_tampered_record_rejected(self):
        self.rows[1]['result'] = 'PASS'
        with self.assertRaisesRegex(IntakeBlocked, 'INTAKE_AUDIT_RECORD'):
            self.inspect()


if __name__ == '__main__':
    unittest.main()

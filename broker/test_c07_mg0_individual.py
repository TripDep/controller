"""Adversarial tests for five canonical individual-rule MG0 trigger classes."""
import copy
import unittest

import c07_mg0_individual as mg
from real_work_intake import canonical, sha, IntakeBlocked

ASSET='SOUTH_GATE_HIGH_V1'
RULE='AAA-200-A-009'
ATTEMPT='b'*64
MASTER=('## MG0 — PROCESS FALSIFICATION\n'
        'Canonical trigger pattern recovered from the old chat:\n' +
        ''.join('- '+v+'\n' for v in mg.TRIGGERS)+
        'The response is not limited to fixing the asset.\n'
        'invalidate affected states and reapply the corrected process\n').encode()


class Tests(unittest.TestCase):
    def setUp(self):
        self.rows=[]
        self.add('WORK_INIT')

    def add(self, event, scoped=False, **fields):
        row={'asset':ASSET,'event':event,**fields,
             'prev_hash':self.rows[-1]['record_hash'] if self.rows else 'GENESIS'}
        if scoped:
            row.update(rule_id=RULE,attempt_id=ATTEMPT)
        row['record_hash']=sha(canonical(row))
        self.rows.append(row)
        return row

    def report(self, master=MASTER,rule=RULE,attempt=ATTEMPT):
        raw=b'\n'.join(canonical(r) for r in self.rows)+b'\n'
        return mg.inspect(master,raw,ASSET,sha(master),rule,attempt)

    def test_unknown_not_promoted_when_no_owner_or_audit_coverage(self):
        x=self.report()
        self.assertEqual(x['canonical_trigger_count'],5)
        self.assertEqual(x['individual_rule_mg0'],'UNKNOWN')
        self.assertTrue(all(t['status']=='UNKNOWN_NOT_EXHAUSTIVELY_OBSERVED'
                            for t in x['triggers']))
        self.assertFalse(x['advancement_authorized'])

    def test_owner_failure_after_pass_detects_escaped_and_autonomous_failure(self):
        self.add('STEP_CLOSE',True,result='PASS')
        owner=self.add('USER_REVIEW',True,result='FAIL',detected_by='OWNER',
                       owner_evidence_sha256='c'*64,assistant_preflight_passed=True)
        x=self.report()
        self.assertEqual([t['id'] for t in x['triggers']
                          if t['status']=='OBSERVED_IN_AUDIT'],[1,3])
        self.assertEqual(x['individual_rule_mg0'],'FAIL')
        self.assertIn(owner['record_hash'],x['observed_failure_record_hashes'])

    def test_revoked_verified_state_detected(self):
        passed=self.add('STEP_CLOSE',True,result='PASS')
        self.add('VERIFIED_STATE_REVOKED',True,
                 previous_verified_record_hash=passed['record_hash'])
        x=self.report()
        self.assertEqual(x['triggers'][1]['status'],'OBSERVED_IN_AUDIT')
        self.assertEqual(x['individual_rule_mg0'],'FAIL')

    def test_repeated_failure_class_detected(self):
        self.add('QUALITY_FINDING',True,failure_class='ILLEGAL_INTERSECTION')
        self.add('QUALITY_FINDING',True,failure_class='ILLEGAL_INTERSECTION')
        x=self.report()
        self.assertEqual(len(x['triggers'][3]['event_hashes']),2)
        self.assertEqual(x['individual_rule_mg0'],'FAIL')

    def test_formally_passed_but_non_deliverable_detected(self):
        self.add('STEP_CLOSE',True,result='PASS')
        self.add('DELIVERY_GATE_CHECK',True,result='BLOCKED')
        x=self.report()
        self.assertEqual(x['triggers'][4]['status'],'OBSERVED_IN_AUDIT')
        self.assertEqual(x['individual_rule_mg0'],'FAIL')

    def test_correction_requires_four_ordered_real_audit_events(self):
        self.add('STEP_CLOSE',True,result='PASS')
        finding=self.add('USER_REVIEW',True,result='FAIL',detected_by='OWNER',
                         owner_evidence_sha256='c'*64,assistant_preflight_passed=False)
        for event in ('MG0_PROCESS_ROOT_CAUSE','MG0_PROCESS_CORRECTION',
                      'MG0_AFFECTED_STATES_INVALIDATED'):
            self.add(event,True,trigger_record_hash=finding['record_hash'],
                     result='PASS',evidence_operation='document hash from reviewed report')
        incomplete=self.report()
        self.assertEqual(incomplete['individual_rule_mg0'],'FAIL')
        self.add('MG0_RULE_REAPPLIED',True,trigger_record_hash=finding['record_hash'],
                 result='PASS',evidence_operation='retested condition')
        complete=self.report()
        self.assertEqual(complete['individual_rule_mg0'],'UNKNOWN')
        self.assertTrue(complete['corrections'][finding['record_hash']]['complete'])
        self.assertFalse(complete['owner_provenance_verified_by_git'])
        self.assertFalse(complete['advancement_authorized'])

    def test_cross_attempt_and_cross_rule_evidence_is_not_replayed(self):
        self.add('STEP_CLOSE',True,result='PASS')
        self.add('USER_REVIEW',True,result='FAIL',detected_by='OWNER',
                 owner_evidence_sha256='c'*64)
        self.assertEqual(self.report(attempt='f'*64)['individual_rule_mg0'],'UNKNOWN')
        self.assertEqual(self.report(rule='OTHER_RULE')['individual_rule_mg0'],'UNKNOWN')

    def test_tampered_audit_chain_rejected(self):
        self.add('STEP_CLOSE',True,result='PASS')
        self.rows[-1]['result']='FAIL'
        with self.assertRaisesRegex(IntakeBlocked,'INTAKE_AUDIT_RECORD'):
            self.report()

    def test_all_five_source_triggers_are_mandatory(self):
        damaged=MASTER.replace(mg.TRIGGERS[2].encode(),b'edited third trigger')
        with self.assertRaisesRegex(IntakeBlocked,
                                     'C07_MG0_FIVE_CANONICAL_TRIGGERS_CHANGED'):
            self.report(master=damaged)


if __name__=='__main__':
    unittest.main()

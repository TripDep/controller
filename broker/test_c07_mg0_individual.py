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


    def test_batch_763_rule_ids_one_audit_readback_same_individual_results(self):
        """763 complete decisions from one canonical audit verification, not 763 scans."""
        from unittest.mock import patch
        # 762 distinct simulated Q identifiers + one real fixture rule.
        ids=sorted(['Q-%03d' % n for n in range(1,763)] + [RULE])
        raw=b'\n'.join(canonical(r) for r in self.rows)+b'\n'
        with patch.object(mg,'audit_check',wraps=mg.audit_check) as checked:
            report=mg.inspect_batch(MASTER,raw,ASSET,sha(MASTER),ids,ATTEMPT)
            self.assertEqual(checked.call_count,1)
        self.assertEqual(report['rule_count'],763)
        self.assertEqual(len(report['rules']),763)
        self.assertEqual(report['audit_events_verified_once'],len(self.rows))
        self.assertEqual(report['individual_mg0_passes'],0)
        self.assertEqual(report['counts']['UNKNOWN'],763)
        self.assertEqual(report['counts']['PASS'],0)
        self.assertFalse(report['advancement_authorized'])
        self.assertEqual(report['rules'][RULE]['verdict'],self.report()['individual_rule_mg0'])

    def test_batch_preserves_exact_failing_rule_and_no_cross_rule_leak(self):
        self.add('STEP_CLOSE',True,result='PASS')
        self.add('USER_REVIEW',True,result='FAIL',detected_by='OWNER',
                 owner_evidence_sha256='e'*64,assistant_preflight_passed=True)
        raw=b'\n'.join(canonical(r) for r in self.rows)+b'\n'
        ids=sorted([RULE,'Q-002','Q-003'])
        report=mg.inspect_batch(MASTER,raw,ASSET,sha(MASTER),ids,ATTEMPT)
        self.assertEqual(report['failed_rule_ids'],[RULE])
        self.assertEqual(report['counts'],{'FAIL':1,'UNKNOWN':2,'PASS':0})
        self.assertEqual(report['rules'][RULE]['observed_failure_count'],1)
        self.assertEqual(report['rules']['Q-002']['observed_failure_count'],0)

    def test_batch_ordered_correction_restores_unknown_not_pass(self):
        self.add('STEP_CLOSE',True,result='PASS')
        review=self.add('USER_REVIEW',True,result='FAIL',detected_by='OWNER',
                        owner_evidence_sha256='e'*64,assistant_preflight_passed=True)
        for kind in ('MG0_PROCESS_ROOT_CAUSE','MG0_PROCESS_CORRECTION',
                     'MG0_AFFECTED_STATES_INVALIDATED','MG0_RULE_REAPPLIED'):
            self.add(kind,True,result='PASS',trigger_record_hash=review['record_hash'],
                     evidence_operation='unit evidence')
        raw=b'\n'.join(canonical(r) for r in self.rows)+b'\n'
        report=mg.inspect_batch(MASTER,raw,ASSET,sha(MASTER),[RULE],ATTEMPT)
        self.assertEqual(report['counts']['UNKNOWN'],1)
        self.assertEqual(report['counts']['PASS'],0)
        self.assertFalse(report['advancement_authorized'])

    def test_batch_tampering_and_duplicate_or_unsorted_rule_ids_fail_closed(self):
        raw=b'\n'.join(canonical(r) for r in self.rows)+b'\n'
        for ids in ([],[RULE,RULE],['Q-003','Q-001']):
            with self.assertRaisesRegex(IntakeBlocked,'BATCH_EXACT_SORTED_UNIQUE'):
                mg.inspect_batch(MASTER,raw,ASSET,sha(MASTER),ids,ATTEMPT)
        for wrong in ('f'*64,):
            with self.assertRaisesRegex(IntakeBlocked,'C07_MG0_MASTER_DRIFT'):
                mg.inspect_batch(MASTER,raw,ASSET,wrong,[RULE],ATTEMPT)
        rows=copy.deepcopy(self.rows)
        rows[0]['event']='FORGED_GREEN_PASS'
        changed=b'\n'.join(canonical(r) for r in rows)+b'\n'
        with self.assertRaisesRegex(IntakeBlocked,'INTAKE_AUDIT_RECORD'):
            mg.inspect_batch(MASTER,changed,ASSET,sha(MASTER),[RULE],ATTEMPT)

    def test_batch_ignores_actual_r178_scoped_non_mg0_audit_event(self):
        self.add('SUPERVISOR_C07_R178_PROCESS_OBSERVATION',True,
                 result='PASS', positive_3d_rule_semantic_passes=0,
                 individual_mg0_passes=0, advancement_authorized=False)
        raw=b'\n'.join(canonical(r) for r in self.rows)+b'\n'
        # A real source-bound observation is not a canonical MG0 claim.
        report=mg.inspect_batch(MASTER,raw,ASSET,sha(MASTER),[RULE],ATTEMPT)
        self.assertEqual(report['counts']['UNKNOWN'],1)
        self.assertEqual(report['counts']['PASS'],0)
        self.assertFalse(report['advancement_authorized'])

    def test_batch_unknown_mg0_specific_claim_still_fails_closed(self):
        self.add('MG0_FAKE_SUCCESS',True,result='PASS')
        raw=b'\n'.join(canonical(r) for r in self.rows)+b'\n'
        with self.assertRaisesRegex(IntakeBlocked,'MG0_UNKNOWN_SCOPED_EVENT'):
            mg.inspect_batch(MASTER,raw,ASSET,sha(MASTER),[RULE],ATTEMPT)

    def test_batch_all_five_canonical_triggers_are_checked_only_once(self):
        damaged=MASTER.replace(mg.TRIGGERS[3].encode(),b'missing pattern')
        raw=b'\n'.join(canonical(r) for r in self.rows)+b'\n'
        with self.assertRaisesRegex(IntakeBlocked,'C07_MG0_FIVE_CANONICAL'):
            mg.inspect_batch(damaged,raw,ASSET,sha(damaged),[RULE],ATTEMPT)


if __name__=='__main__':
    unittest.main()

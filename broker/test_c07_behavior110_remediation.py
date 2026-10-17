"""R130: 110 canonical failure-correction chains; synthetic audit only.

A green test proves the stop gate, never that a real assistant prevented a
behavioral error, nor genuine owner approval or MG0 pass.
"""
import copy
import hashlib
import unittest
from unittest.mock import patch

import c07_behavior_110 as behavior
import c07_mg0_individual as mg
import c07_behavior110_remediation as gate
from real_work_intake import canonical


def sh(data):return hashlib.sha256(data).hexdigest()


class Tests(unittest.TestCase):
    def setUp(self):
        self.asset='TEST'
        self.step='STEP0100'
        self.attempt='b'*64
        self.op='c'*64
        master=('## MG0 — PROCESS FALSIFICATION\n'
                'Canonical trigger pattern recovered from the old chat:\n'
                + ''.join('- '+v+'\n' for v in mg.TRIGGERS)
                + 'The response is not limited to fixing the asset.\n'
                + 'invalidate affected states and reapply the corrected process\n')
        self.master=master.encode()
        self.work={'master_sha256':sh(self.master),'attempt_id':self.attempt,
                   'operation_sha256':self.op}
        self.plan={'master_sha256':self.work['master_sha256']}
        ids=list(gate.IDS)
        headings=[]
        clauses=[]
        for letter,marker,start,end in behavior.SECTIONS:
            headings.append('## %s. %s (%03d–%03d)'%(letter,marker,start,end))
        for i in range(1,111):
            clauses.append('%03d. Errore: synthetic failure %03d → synthetic prevention %03d'%(i,i,i))
        self.registry=('# SOURCE\n'+ '\n'.join(headings+clauses)+'\n').encode()
        pin=sh(self.registry)
        patcher=patch.object(gate,'PIN',pin)
        patcher.start();self.addCleanup(patcher.stop)
        self.rules={}
        for i,rid in enumerate(ids):
            text=clauses[i].split('. ',1)[1]
            self.rules[rid]={
                'family':behavior.FAMILY,'source':behavior.SOURCE,
                'source_path':behavior.CANONICAL_PATH,'source_sha256':pin,
                'requirement':text,'requirement_sha256':sh(text.encode())}
        self.inventory={'schema':'gg-effective-family-inventory-v1',
            'rule_count':763,'canonical_master_sha256':sh(self.master),
            'source_digests':{behavior.SOURCE:pin},
            'families':{behavior.FAMILY:ids},'rules':self.rules}
        self.rows=[]
        self.plan_row=self.add('SUPERVISOR_PLAN_ENROLLED',plan=self.plan)
        self.reserve=self.add('SUPERVISOR_OPERATION_RESERVED',work=copy.deepcopy(self.work))
        self.open=self.add('SUPERVISOR_OPERATION_OPENED',step=self.step,
                           reservation_hash=self.reserve['record_hash'],
                           operation_sha256=self.op)

    def add(self,event,**kw):
        row={'asset':self.asset,'event':event,
             'prev_hash':self.rows[-1]['record_hash'] if self.rows else 'GENESIS',**kw}
        row['record_hash']=sh(canonical(row))
        self.rows.append(row)
        return row

    def raw(self):
        return b''.join(canonical(r)+b'\n' for r in self.rows)

    def report(self,**kw):
        args={'inventory':self.inventory,'plan':self.plan,
              'asset':self.asset,'step':self.step,'work':self.work,
              'master_raw':self.master,'audit_raw':self.raw(),
              'state_tail':self.rows[-1]['record_hash'],
              'registry_raw':self.registry}
        args.update(kw)
        return gate.inspect(**args)

    def finding(self,rule='BEHAVIOR-055',event='QUALITY_FINDING',**fields):
        return self.add(event,step=self.step,rule_id=rule,
                        attempt_id=self.attempt,result='FAIL',**fields)

    def test_all_110_source_bound_rules_read_on_one_real_hash_chain(self):
        out=self.report()
        self.assertEqual(out['source_rules_examined'],110)
        self.assertEqual(len(out['rules']),110)
        self.assertEqual(out['individual_mg0_PASS'],0)
        self.assertEqual(out['rule_count_with_semantic_PASS'],0)
        self.assertEqual(out['result'],'UNKNOWN')
        self.assertTrue(out['original_registry_bytes_rechecked'])
        self.assertEqual(out['observed_failure_rule_ids'],[])
        self.assertTrue(all(not r['new_full_rule_pass'] and
                            r['semantic_result']=='UNKNOWN' and
                            r['individual_mg0']=='UNKNOWN'
                            for r in out['rules'].values()))

    def test_each_of_110_unresolved_regressions_is_detected(self):
        for rid in gate.IDS:
            self.finding(rule=rid)
        out=self.report()
        self.assertEqual(len(out['observed_failure_rule_ids']),110)
        self.assertEqual(len(out['failed_rule_ids']),110)
        self.assertEqual(len(out['uncorrected_finding_rule_ids']),110)
        self.assertTrue(all(r['observed_failure_count']==1 and
                            r['semantic_result']=='FAIL'
                            for r in out['rules'].values()))
        self.assertEqual(out['rule_count_with_semantic_PASS'],0)
        self.assertFalse(out['advancement_authorized'])

    def test_ordered_correction_restarts_audit_but_never_grants_pass(self):
        finding=self.finding()
        for phase in gate.STEPS:
            self.add(phase,step=self.step,rule_id='BEHAVIOR-055',
                     attempt_id=self.attempt,result='PASS',
                     trigger_record_hash=finding['record_hash'],
                     evidence_operation='fixture_claim')
        out=self.report()
        entry=out['rules']['BEHAVIOR-055']
        self.assertEqual(out['ordered_claimed_correction_chains'],1)
        self.assertEqual(entry['semantic_result'],'UNKNOWN')
        self.assertEqual(entry['independent_prevention_effectiveness'],'UNKNOWN')
        self.assertFalse(entry['new_full_rule_pass'])
        self.assertEqual(out['individual_mg0_PASS'],0)

    def test_missing_invalidation_stage_is_a_real_unresolved_failure(self):
        finding=self.finding()
        for phase in gate.STEPS[:2]:
            self.add(phase,step=self.step,rule_id='BEHAVIOR-055',
                     attempt_id=self.attempt,result='PASS',
                     trigger_record_hash=finding['record_hash'],
                     evidence_operation='text')
        out=self.report()
        self.assertEqual(out['result'],'FAIL')
        self.assertIn('MG0_AFFECTED_STATES_INVALIDATED',out['rules']['BEHAVIOR-055']
                      ['observations'][0]['missing_correction_phases'])

    def test_cross_attempt_correction_does_not_heal_current_failure(self):
        finding=self.finding()
        for phase in gate.STEPS:
            self.add(phase,step=self.step,rule_id='BEHAVIOR-055',
                     attempt_id='e'*64,result='PASS',
                     trigger_record_hash=finding['record_hash'],
                     evidence_operation='incorrect_attempt')
        out=self.report()
        self.assertIn('BEHAVIOR-055',out['failed_rule_ids'])

    def test_cross_rule_correction_does_not_heal_current_failure(self):
        finding=self.finding()
        for phase in gate.STEPS:
            self.add(phase,step=self.step,rule_id='BEHAVIOR-056',
                     attempt_id=self.attempt,result='PASS',
                     trigger_record_hash=finding['record_hash'],
                     evidence_operation='incorrect_rule')
        out=self.report()
        self.assertIn('BEHAVIOR-055',out['failed_rule_ids'])

    def test_self_claimed_owner_review_is_not_authenticated_owner(self):
        self.finding(event='USER_REVIEW',detected_by='OWNER',owner_evidence_sha256='d'*64)
        out=self.report()
        report=out['rules']['BEHAVIOR-055']
        self.assertTrue(report['observations'][0]['reported_owner_origin_unverified'])
        self.assertEqual(report['real_owner_identity'],'UNKNOWN')
        self.assertEqual(report['semantic_result'],'FAIL')

    def test_other_step_cannot_reuse_current_attempt_evidence(self):
        self.add('QUALITY_FINDING',step='OTHER',rule_id='BEHAVIOR-055',
                 attempt_id=self.attempt,result='FAIL')
        with self.assertRaisesRegex(gate.UnprovenBehavior,'CROSS_STEP_REPLAY'):
            self.report()

    def test_fake_rereview_in_wrong_order_does_not_qualify(self):
        f=self.finding()
        for phase in gate.STEPS[::-1]:
            self.add(phase,step=self.step,rule_id='BEHAVIOR-055',
                     attempt_id=self.attempt,result='PASS',
                     trigger_record_hash=f['record_hash'],
                     evidence_operation='text')
        out=self.report()
        self.assertIn('BEHAVIOR-055',out['uncorrected_finding_rule_ids'])

    def test_duplicate_phases_rejected_as_ambiguous(self):
        f=self.finding()
        for phase in gate.STEPS:
            self.add(phase,step=self.step,rule_id='BEHAVIOR-055',
                     attempt_id=self.attempt,result='PASS',
                     trigger_record_hash=f['record_hash'],
                     evidence_operation='text')
            if phase=='MG0_PROCESS_ROOT_CAUSE':
                self.add(phase,step=self.step,rule_id='BEHAVIOR-055',
                         attempt_id=self.attempt,result='PASS',
                         trigger_record_hash=f['record_hash'],
                         evidence_operation='duplicate')
        out=self.report()
        self.assertIn('BEHAVIOR-055',out['failed_rule_ids'])

    def test_original_master_or_registry_bytes_changed_is_blocked(self):
        with self.assertRaisesRegex(gate.UnprovenBehavior,'PINNED_MASTER'):
            self.report(master_raw=self.master+b'tamper')
        with self.assertRaisesRegex(gate.UnprovenBehavior,'PINNED_REGISTRY'):
            self.report(registry_raw=self.registry+b'tamper')

    def test_fake_audit_hash_chain_refused(self):
        raw=self.raw().replace(b'QUALITY_',b'TAMPERED_')
        self.finding()
        bad=self.raw().replace(b'QUALITY_FINDING',b'TAMPERED_REPORT')
        with self.assertRaisesRegex(ValueError,'INTAKE_AUDIT_RECORD'):
            self.report(audit_raw=bad)

    def test_replayed_reservation_attempt_or_wrong_operation_blocked(self):
        tampered=dict(self.work,attempt_id='0'*64)
        with self.assertRaisesRegex(gate.UnprovenBehavior,'RESERVED_WORK'):
            self.report(work=tampered)
        with self.assertRaisesRegex(gate.UnprovenBehavior,'RESERVED_WORK'):
            self.report(work=dict(self.work,operation_sha256='a'*64))

    def test_110_rule_text_changes_are_individually_detected(self):
        for rid in gate.IDS:
            before=self.rules[rid]['requirement']
            self.rules[rid]['requirement']=before+' hide regression'
            with self.subTest(rid=rid):
                with self.assertRaisesRegex(gate.UnprovenBehavior,'RULE_TEXT'):
                    self.report()
            self.rules[rid]['requirement']=before

    def test_original_registry_optional_does_not_claim_byte_read(self):
        result=self.report(registry_raw=None)
        self.assertFalse(result['original_registry_bytes_rechecked'])
        self.assertEqual(result['rule_count_with_semantic_PASS'],0)

if __name__=='__main__':unittest.main()
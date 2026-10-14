"""Real Controller/temp-file integration; Git API and semantic verdicts are fixtures.

Positive cases certify wiring only, never a real asset or production MG0 PASS.
"""
import copy
import fcntl
import hashlib
import json
import tempfile
from datetime import datetime, timezone, timedelta
import unittest
from pathlib import Path
from unittest.mock import patch

import golden_controller as gc
import supervisor_judgment as j
from controlled_judgment import ControlledJudgment
from test_rule_evidence import API
from test_supervisor_judgment import inventory, contexts
from test_supervisor_context import seal


class GitFixture(API):
    def __init__(self):
        super().__init__()
        self.logs = ''
        self.history = {}
        self.jobs['jobs'][0]['steps'] = [
            {'name': name, 'status': 'completed', 'conclusion': 'success'} for name in
            (j.SEMANTIC_STEP, 'Judge all canonical families and individual MG0')]

    def next_run(self):
        self.history[self.origin['run_id']] = (copy.deepcopy(self.run), copy.deepcopy(self.jobs), self.logs)
        self.origin = dict(self.origin, run_id=self.origin['run_id'] + 1,
                           job_id=self.origin['job_id'] + 1)
        self.run['id'] = self.origin['run_id']
        self.jobs['jobs'][0].update(id=self.origin['job_id'], run_id=self.origin['run_id'])
        self.logs = ''

    def call(self, method, path):
        for run_id, (run, jobs, _) in self.history.items():
            if path == '/actions/runs/' + str(run_id): return copy.deepcopy(run)
            if path.startswith('/actions/runs/' + str(run_id) + '/attempts/') and path.endswith('/jobs?per_page=100'):
                return copy.deepcopy(jobs)
        if path == '/actions/runs/' + str(self.origin['run_id']): return copy.deepcopy(self.run)
        return super().call(method, path)

    def job_logs(self, job_id):
        for _, jobs, logs in self.history.values():
            if jobs['jobs'][0]['id'] == job_id: return logs
        return self.logs


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.master = self.root / 'MASTER.md'
        self.master.write_text('\n'.join(gc.REQUIRED_MASTER_MARKERS))
        self.inv = inventory()
        self.inv['canonical_master_sha256'] = hashlib.sha256(self.master.read_bytes()).hexdigest()
        self.c = gc.Controller(self.root, self.master)
        self.c.init_asset('TEST', 'SYNTHETIC_TEST_ONLY_NO_REAL_ASSET')
        self.c.authorize_d('TEST', 'unit fixture owner authorization')
        self.api = GitFixture()
        self.s = ControlledJudgment(self.c, 'TEST', self.api, self.inv)
        self.dep = self.root / 'dependency.txt'
        self.dep.write_text('synthetic dependency')
        self.ctx = contexts()
        for role, value in self.ctx.items():
            value['master']['sha256'] = self.inv['canonical_master_sha256']
            value['dependencies']['c' * 64] = hashlib.sha256(self.dep.read_bytes()).hexdigest()
            seal(value)
            p = self.root / j.context.PATHS[role]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(value))
        self.plan = {
            'phase': 'P8', 'asset_type': 'vegetation', 'profiles': ['FOLIAGE_PROFILE'],
            'master_sha256': self.inv['canonical_master_sha256'],
            'dependency_files': {'c' * 64: 'dependency.txt'},
            'asset_specific_extensions_verified': True, 'guardian_required': False,
            'mode': 'OPERATIONAL', 'closure_requested': False,
            'operation': {'action': 'Synthetic test status operation', 'category': 'STATUS',
                          'locks': ['UNIT_ONLY'], 'sections': ['unit'],
                          'evidence_before': 'fixture', 'resolves': [], 'aaa_phase': None},
            'inventory_sha256': j.digest(self.inv), 'issuer': self.api.issuer,
            'enrolled': {rid: {'requirement_sha256': row['requirement_sha256'],
                        'criteria': ['unit_criterion'], 'validator_id': 'SYNTHETIC_UNIT_ONLY',
                        'issuer': self.api.issuer} for rid, row in self.inv['rules'].items()}}
        self.open = self.c.begin('TEST', 'Enroll synthetic test plan', 'STATUS', [], [], 'unit', [])
        self.s.enroll_plan(self.plan)
        self.c.close('TEST', self.open['step'], self.open['token'], 'PASS', 'unit', 'unit', [], True)

    def issue(self, verdict='PASS', work_override=None):
        work = work_override if work_override is not None else self.s.expected_work()
        packets = []
        offers = {}
        for rid, row in self.inv['rules'].items():
            b = j.binding(work, row, rid)
            packet = {'schema': 'gg-semantic-rule-v1', 'scope': j.SEMANTIC_SCOPE,
                      'validator_id': 'SYNTHETIC_UNIT_ONLY', 'binding': b,
                      'rule': {'result': verdict, 'checks': {'unit_criterion': verdict == 'PASS'},
                               'proof_digest': 'd' * 64},
                      'mg0': {'binding': b, 'triggered': False, 'result': 'PASS',
                              'checks': {'canonical_triggers_checked': True}, 'proof_digest': 'f' * 64}}
            packets.append(packet)
            offers[rid] = {'native_origin': self.api.origin, 'expected_packet_sha256': j.digest(packet)}
        old = self.s.records()
        priors = [r for r in old if r['event'] == 'SUPERVISOR_NATIVE_DECISION']
        self.api.logs = '\n'.join('2020-10-13T18:00:00Z ' + j.PREFIX + json.dumps(p) for p in packets)
        result = j.judge(self.inv, work, offers, j.NativeRuleBackend(self.api, self.plan['enrolled']),
                         current_contexts=self.ctx,
                         previous_contexts=priors[-1]['contexts'] if priors else None,
                         previous_decision=priors[-1]['decision'] if priors else None)
        self.api.logs += '\n2020-10-13T18:00:00Z C07_NATIVE_PROCESS_JUDGMENT:' + json.dumps(result)
        return offers, result

    def verified_close(self, active, evidence='unit'):
        # Independent fixture run after begin: these remain synthetic integration tests.
        reserved = [r for r in self.s.records()
                    if r['event'] == 'SUPERVISOR_OPERATION_RESERVED'][-1]
        self.api.next_run()
        self.api.run['created_at'] = (datetime.now(timezone.utc) +
                                      timedelta(seconds=2)).isoformat()
        offers, _ = self.issue(work_override=reserved['work'])
        return self.s.close(active['step'], active['token'], 'PASS', evidence,
                            'unit', [], post_origin=self.api.origin, post_offers=offers)

    def test_post_operation_proof_required_even_after_eligible_begin(self):
        offers, _ = self.issue()
        active = self.s.begin(self.api.origin, offers)
        with self.assertRaisesRegex(j.Blocked, 'POST_NATIVE_PROOF_REQUIRED'):
            self.s.close(active['step'], active['token'], 'PASS', 'bare PASS', 'unit', [])
        self.assertEqual(self.c.asset_state('TEST')['active_step']['step'], active['step'])

    def test_begin_run_cannot_be_reused_as_post_proof(self):
        offers, _ = self.issue()
        active = self.s.begin(self.api.origin, offers)
        with self.assertRaisesRegex(j.Blocked, 'POST_CANNOT_REUSE_BEGIN_PROOF'):
            self.s.close(active['step'], active['token'], 'PASS', 'replay', 'unit', [],
                         post_origin=self.api.origin, post_offers=offers)

    def test_native_fixture_opens_and_closes_real_controller(self):
        offers, _ = self.issue()
        active = self.s.begin(self.api.origin, offers)
        self.assertEqual(active['action'], self.plan['operation']['action'])
        self.verified_close(active, 'wiring only')
        self.assertTrue(self.c.verify_audit_chain('TEST')['ok'])
        self.assertIsNone(self.c.asset_state('TEST')['active_step'])
        self.assertEqual(self.s.records()[-1]['event'], 'SUPERVISOR_OPERATION_CLOSED')

    def test_stop_persisted_without_opening_controller(self):
        offers, _ = self.issue('FAIL')
        with self.assertRaisesRegex(j.Blocked, 'ADVANCEMENT_DENIED'):
            self.s.begin(self.api.origin, offers)
        self.assertIsNone(self.c.asset_state('TEST')['active_step'])
        self.assertEqual(self.s.records()[-1]['decision']['action'], 'STOP_CORRECT_RESUBMIT')

    def test_correction_requires_prior_git_readback(self):
        offers, failed = self.issue('FAIL')
        with self.assertRaises(j.Blocked):
            self.s.begin(self.api.origin, offers)
        self.api.next_run()
        work = self.s.expected_work()
        self.assertEqual(work['attempt_number'], 2)
        self.assertEqual(work['previous_attempt_id'], failed['attempt_id'])
        offers, _ = self.issue()
        active = self.s.begin(self.api.origin, offers)
        self.assertEqual(active['step'], '0002')

    def test_prior_decision_content_changed_blocks(self):
        offers, _ = self.issue('FAIL')
        with self.assertRaises(j.Blocked): self.s.begin(self.api.origin, offers)
        self.api.logs = self.api.logs.replace('STOP_CORRECT_RESUBMIT', 'READY_FOR_EXACT_OPERATION')
        with self.assertRaisesRegex(j.Blocked, 'DECISION_DIGEST'): self.s.expected_work()

    def test_crash_after_reservation_never_replays(self):
        offers, _ = self.issue()
        with patch.object(self.c, 'begin', side_effect=RuntimeError('simulated crash')):
            with self.assertRaises(RuntimeError): self.s.begin(self.api.origin, offers)
        c = gc.Controller(self.root, self.master)
        restored = ControlledJudgment(c, 'TEST', self.api, self.inv)
        with self.assertRaisesRegex(j.Blocked, 'PENDING_RECONCILIATION'): restored.begin(self.api.origin, offers)
        self.assertIsNone(c.asset_state('TEST')['active_step'])

    def test_restart_during_open_does_not_repeat_action(self):
        offers, _ = self.issue()
        active = self.s.begin(self.api.origin, offers)
        restored = ControlledJudgment(gc.Controller(self.root, self.master), 'TEST', self.api, self.inv)
        with self.assertRaisesRegex(j.Blocked, 'STEP_ALREADY_OPEN'): restored.begin(self.api.origin, offers)
        self.verified_close(active)

    def test_replay_after_closed_operation_denied(self):
        offers, _ = self.issue()
        a = self.s.begin(self.api.origin, offers)
        self.verified_close(a)
        restored = ControlledJudgment(gc.Controller(self.root, self.master), 'TEST', self.api, self.inv)
        with self.assertRaisesRegex(j.Blocked, 'PREVIOUS_NOT_FAILED'): restored.begin(self.api.origin, offers)

    def test_changed_master_blocks(self):
        self.master.write_text(self.master.read_text() + '\nchanged')
        with self.assertRaisesRegex(j.Blocked, 'CONTROLLED_MASTER'): self.s.expected_work()

    def test_dependency_change_is_canonical_input(self):
        first = self.s.expected_work()
        self.dep.write_text('changed')
        second = self.s.expected_work()
        self.assertNotEqual(first['work_dependencies'], second['work_dependencies'])
        offers, result = self.issue()
        self.assertFalse(result['advancement_authorized'])

    def test_dependency_traversal_denied(self):
        with self.assertRaisesRegex(j.Blocked, 'DEPENDENCY_PATH'): self.s.local_file('../outside')

    def test_audit_tamper_denied(self):
        with self.c.audit_path('TEST').open('a') as out: out.write('{}\n')
        with self.assertRaisesRegex(j.Blocked, 'AUDIT_INVALID'): self.s.expected_work()

    def test_stale_state_after_audit_append_denied(self):
        old = self.c.state_path.read_bytes()
        self.c.append_event('TEST', {'event': 'UNIT_SIMULATED_PARTIAL_TRANSACTION'})
        self.c.state_path.write_bytes(old)
        with self.assertRaisesRegex(j.Blocked, 'AUDIT_INVALID'): self.s.expected_work()

    def test_concurrent_entry_denied(self):
        with (self.c.control / 'supervisor-operation.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.assertRaisesRegex(j.Blocked, 'CONTROLLED_BUSY'): self.s.expected_work()

    def test_plan_cannot_be_enrolled_outside_governance_step(self):
        with self.assertRaisesRegex(j.Blocked, 'AUTHORIZED_STATUS'): self.s.enroll_plan(self.plan)

    def test_wrong_native_attempt_denied(self):
        offers, _ = self.issue()
        origin = dict(self.api.origin, run_attempt=2)
        with self.assertRaises(ValueError): self.s.begin(origin, offers)

    def test_controller_failure_after_open_remains_blocked(self):
        offers, _ = self.issue()
        a = self.s.begin(self.api.origin, offers)
        self.s.close(a['step'], a['token'], 'FAIL', 'fixture execution failed', 'unit', [])
        self.assertIn(a['step'], self.c.asset_state('TEST')['unresolved'])

    def test_dependency_changed_during_action_blocks_pass(self):
        offers, _ = self.issue()
        a = self.s.begin(self.api.origin, offers)
        self.dep.write_text('changed during operation')
        closed = self.verified_close(a)
        self.assertEqual(closed['result'], 'BLOCKED')

    def test_unrelated_context_update_during_action_keeps_pass(self):
        offers, _ = self.issue()
        a = self.s.begin(self.api.origin, offers)
        value = self.ctx['rescue']
        value['observed_at'] = '2020-10-13T19:00:00+00:00'
        value['state']['version'] += 1
        value['state']['sha256'] = '9' * 64
        value['dependencies']['e' * 64] = '8' * 64
        seal(value)
        (self.root / j.context.PATHS['rescue']).write_text(json.dumps(value))
        closed = self.verified_close(a)
        self.assertEqual(closed['result'], 'PASS')


if __name__ == '__main__':
    unittest.main()

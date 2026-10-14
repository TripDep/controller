"""Native judgments connected to Golden Controller's durable audit.

No model files or asset payloads are sent to Git. The caller provides the
canonical Controller and trusted inventory, never a producer's PASS dictionary.
This adapter governs its own begin/close path; it does not isolate other writers.
"""
import copy
import fcntl
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path

import supervisor_judgment as j
import supervisor_context as context

PLAN_KEYS = {'phase', 'asset_type', 'profiles', 'master_sha256',
             'dependency_files', 'asset_specific_extensions_verified',
             'guardian_required', 'mode', 'closure_requested', 'operation',
             'inventory_sha256', 'issuer', 'enrolled'}
OP_KEYS = {'action', 'category', 'locks', 'sections', 'evidence_before',
           'resolves', 'aaa_phase'}


class ControlledJudgment:
    def __init__(self, controller, asset, api, inventory):
        self.c = controller
        # Controller's own canonical ID, without changing/creating asset state.
        self.asset = asset.strip().upper()
        j.need(self.asset in controller.state['assets'], 'CONTROLLED_UNKNOWN_WORK')
        self.api = api
        self.inventory = inventory

    @contextmanager
    def locked(self):
        """Serialize participating operations and discard stale in-memory state."""
        path = self.c.control / 'supervisor-operation.lock'
        with path.open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise j.Blocked('CONTROLLED_BUSY')
            try:
                self.c.state = json.loads(self.c.state_path.read_text())
                j.need(self.asset in self.c.state['assets'], 'CONTROLLED_UNKNOWN_WORK')
                j.need(self.c.verify_audit_chain(self.asset)['ok'], 'CONTROLLED_AUDIT_INVALID')
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def records(self):
        p = self.c.audit_path(self.asset)
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]

    def append(self, event, **fields):
        record = self.c.append_event(self.asset, {'event': event, **fields})
        # Persist directory entries as well as the fsynced JSONL/state files.
        for directory in (self.c.audit_dir, self.c.control):
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return record

    def enroll_plan(self, plan):
        """Trusted governance installation, inside an authorized STATUS step.

        This records authority, not a semantic certification. It is deliberately
        unavailable as an automatic producer waiver or missing-rule fallback.
        """
        with self.locked():
            st = self.c.asset_state(self.asset)
            active = st.get('active_step')
            j.need(st.get('d_authorized') and active and active['category'] == 'STATUS',
                   'CONTROLLED_PLAN_REQUIRES_AUTHORIZED_STATUS')
            j.need(set(plan) == PLAN_KEYS and set(plan['operation']) == OP_KEYS,
                   'CONTROLLED_PLAN_SCHEMA')
            j.need(plan['inventory_sha256'] == j.digest(self.inventory), 'CONTROLLED_INVENTORY')
            j.need(plan['master_sha256'] == self.c.master_identity()['sha256'], 'CONTROLLED_MASTER')
            j.need(plan['operation']['category'] != 'MASTER_UPDATE', 'CONTROLLED_MASTER_UPDATE_SEPARATE')
            j.need(plan['dependency_files'] and isinstance(plan['enrolled'], dict), 'CONTROLLED_PLAN_DEPENDENCIES')
            rec = self.append('SUPERVISOR_PLAN_ENROLLED', plan=copy.deepcopy(plan),
                              plan_sha256=j.digest(plan), status_step=active['step'])
            return rec['record_hash']

    def plan(self):
        rows = [r for r in self.records() if r['event'] == 'SUPERVISOR_PLAN_ENROLLED']
        j.need(rows, 'CONTROLLED_PLAN_NOT_ENROLLED')
        row = rows[-1]
        j.need(row['plan_sha256'] == j.digest(row['plan']), 'CONTROLLED_PLAN_DIGEST')
        # Enrollment becomes effective only after its controlled STATUS closes PASS.
        closed = [r for r in self.records() if r['event'] == 'STEP_CLOSE' and
                  r.get('step') == row['status_step']]
        j.need(len(closed) == 1 and closed[0]['result'] == 'PASS', 'CONTROLLED_PLAN_NOT_APPROVED')
        j.need(row['plan']['inventory_sha256'] == j.digest(self.inventory), 'CONTROLLED_INVENTORY')
        j.need(row['plan']['master_sha256'] == self.c.master_identity()['sha256'], 'CONTROLLED_MASTER')
        return row

    def local_file(self, relative):
        j.need(isinstance(relative, str) and relative and '\\' not in relative,
               'CONTROLLED_DEPENDENCY_PATH')
        p = Path(relative)
        j.need(not p.is_absolute() and '..' not in p.parts and str(p) == relative,
               'CONTROLLED_DEPENDENCY_PATH')
        full = self.c.root / p
        j.need(full.resolve().is_relative_to(self.c.root) and full.is_file() and
               not any(x.is_symlink() for x in (full, *full.parents)), 'CONTROLLED_DEPENDENCY_PATH')
        return full

    def contexts(self):
        return {role: context.validate(json.loads(self.local_file(path).read_text()))
                for role, path in context.PATHS.items()}

    def prepare(self, row):
        plan = row['plan']
        records = self.records()
        decisions = [r for r in records if r['event'] == 'SUPERVISOR_NATIVE_DECISION']
        previous = decisions[-1] if decisions else None
        if previous and previous['decision']['action'] == 'READY_FOR_EXACT_OPERATION':
            operation = previous['decision']['operation_sha256']
            completed = [r for r in records if r['event'] == 'SUPERVISOR_OPERATION_CLOSED' and
                         r['operation_sha256'] == operation and r['result'] == 'PASS']
            # A newly enrolled exact operation may follow a completed operation.
            # Changing the plan must never erase an unresolved failed attempt.
            if previous['plan_record_hash'] != row['record_hash'] and len(completed) == 1:
                previous = None
        j.need(not previous or previous['decision']['action'] in
               ('STOP_CORRECT_RESUBMIT', 'STOP_CONTEXT_RECHECK'), 'CONTROLLED_PREVIOUS_NOT_FAILED')
        st = self.c.asset_state(self.asset)
        # Bind to the actual Controller position. No caller-supplied step/attempt.
        position = {'next_step': st['next_step'], 'plan_record_hash': row['record_hash'],
                    'operation': plan['operation'], 'work_item_sha256': j.digest(self.asset)}
        work = {k: copy.deepcopy(plan[k]) for k in ('phase', 'asset_type', 'profiles',
                'master_sha256', 'asset_specific_extensions_verified', 'guardian_required',
                'mode', 'closure_requested')}
        work.update(work_item_sha256=j.digest(self.asset), operation_sha256=j.digest(position),
                    work_dependencies={key: hashlib.sha256(self.local_file(path).read_bytes()).hexdigest()
                                       for key, path in plan['dependency_files'].items()},
                    attempt_number=previous['decision']['attempt_number'] + 1 if previous else 1,
                    previous_attempt_id=previous['decision']['attempt_id'] if previous else None)
        work['attempt_id'] = j.digest({'work': work, 'prior_record': previous['record_hash'] if previous else None})
        j.validate_work(work, self.inventory)
        old_decision = None
        if previous:
            old_decision = j.native_decision(self.api, previous['origin'], previous['issuer'])
            j.need(old_decision == previous['decision'], 'CONTROLLED_PRIOR_NATIVE_CHANGED')
        return work, previous, old_decision

    def expected_work(self):
        """Read-only request for native validators; cannot itself authorize work."""
        with self.locked():
            row = self.plan()
            work, _, _ = self.prepare(row)
            return work

    def begin(self, origin, offers):
        """Verify Git, reserve durably, then open only the enrolled exact action.

        Any interruption after reservation leaves the operation consumed. No
        automatic recovery or replay can silently repeat an uncertain action.
        """
        with self.locked():
            st = self.c.asset_state(self.asset)
            j.need(st.get('active_step') is None, 'CONTROLLED_STEP_ALREADY_OPEN')
            records = self.records()
            reserved = [r for r in records if r['event'] == 'SUPERVISOR_OPERATION_RESERVED']
            finished = {r['reservation_hash'] for r in records if r['event'] == 'SUPERVISOR_OPERATION_CLOSED'}
            j.need(all(r['record_hash'] in finished for r in reserved), 'CONTROLLED_OPERATION_PENDING_RECONCILIATION')
            # Use the actual current Library/Controller bytes before any operational
            # begin, not an isolated read-only intake report from an earlier run.
            # This stays inside the Controller lock to avoid accepting a stale state.
            import real_work_intake
            intake = real_work_intake.inspect(
                self.c.master.read_bytes(), self.c.state_path.read_bytes(),
                self.c.audit_path(self.asset).read_bytes(), self.asset,
                self.c.master_identity()['sha256'])
            j.need(intake['controller_preflight_ready'],
                   'CONTROLLED_LIVE_INTAKE_BLOCKED:' + ','.join(intake['blockers']))
            # Canonical MG0 process falsification is checked from the same
            # current Library Master and complete asset audit under the lock.
            # A historic correction event is NOT an individual rule/MG0 PASS.
            import mg0_audit_semantics
            mg0 = mg0_audit_semantics.inspect(
                self.c.master.read_bytes(), self.c.audit_path(self.asset).read_bytes(),
                self.asset, self.c.master_identity()['sha256'])
            j.need(all(event['correction_records'] for event in mg0['trigger_events']),
                   'CONTROLLED_MG0_UNCORRECTED_PROCESS_FAILURE')
            row = self.plan()
            plan = row['plan']
            work, previous, prior_decision = self.prepare(row)
            current = self.contexts()
            decision = j.native_decision(self.api, origin, plan['issuer'])
            backend = j.NativeRuleBackend(self.api, plan['enrolled'])
            fresh = j.judge(self.inventory, work, offers, backend, current_contexts=current,
                            previous_contexts=previous['contexts'] if previous else None,
                            previous_decision=prior_decision)
            j.need(decision == fresh, 'CONTROLLED_NATIVE_DECISION_CHANGED')
            # Preserve real STOP and corrections as well as eligible judgments.
            self.append('SUPERVISOR_NATIVE_DECISION', decision=decision, origin=origin,
                        issuer=plan['issuer'], contexts=current, plan_record_hash=row['record_hash'])
            used = {r['operation_sha256'] for r in reserved}
            receipt = j._consume_checked(decision, fresh, work, work['operation_sha256'], used)
            # Do not open a step if local dependencies/Master/context changed while Git was read.
            j.need(self.c.master_identity()['sha256'] == work['master_sha256'], 'CONTROLLED_MASTER')
            j.need(self.contexts() == current, 'CONTROLLED_CONTEXT_CHANGED_DURING_READ')
            for key, path in plan['dependency_files'].items():
                j.need(hashlib.sha256(self.local_file(path).read_bytes()).hexdigest() ==
                       work['work_dependencies'][key], 'CONTROLLED_DEPENDENCY_CHANGED_DURING_READ')
            reservation = self.append('SUPERVISOR_OPERATION_RESERVED', **receipt,
                                      operation_sha256=work['operation_sha256'], work=work,
                                      contexts=current, plan_record_hash=row['record_hash'])
            active = self.c.begin(self.asset, **plan['operation'])
            self.append('SUPERVISOR_OPERATION_OPENED', reservation_hash=reservation['record_hash'],
                        operation_sha256=work['operation_sha256'], step=active['step'])
            return active

    def close(self, step, token, result, evidence, regression, sections_after, critical=True,
              post_origin=None, post_offers=None):
        with self.locked():
            active = self.c.asset_state(self.asset).get('active_step')
            j.need(active and active['step'] == step and active['token'] == token, 'CONTROLLED_STEP_TOKEN')
            rows = [r for r in self.records() if r['event'] == 'SUPERVISOR_OPERATION_OPENED' and r['step'] == step]
            j.need(len(rows) == 1, 'CONTROLLED_OPEN_RECORD')
            if result.upper() == 'PASS':
                reserved = next(r for r in self.records() if r['record_hash'] == rows[0]['reservation_hash'])
                work = reserved['work']
                plan = next(r['plan'] for r in self.records() if r['record_hash'] == reserved['plan_record_hash'])
                try:
                    current = self.contexts()
                    for role, value in current.items():
                        assessment = context.assess(reserved['contexts'][role], value,
                                                    list(work['work_dependencies']), work['guardian_required'])
                        j.need(value['master']['sha256'] == work['master_sha256'] and
                               all(value['dependencies'].get(k) == h for k, h in work['work_dependencies'].items()) and
                               assessment['action'] not in ('STOP_RELEVANT_CONTEXT_UNKNOWN', 'RECHECK_AFFECTED_CONTROLS'),
                               'CONTROLLED_POST_CONTEXT_RECHECK')
                    for key, path in plan['dependency_files'].items():
                        j.need(hashlib.sha256(self.local_file(path).read_bytes()).hexdigest() ==
                               work['work_dependencies'][key], 'CONTROLLED_POST_DEPENDENCY_RECHECK')
                except (ValueError, KeyError, OSError, TypeError) as exc:
                    result, critical = 'BLOCKED', True
                    evidence += ' | ' + str(exc)
            # A pre-operation verdict never proves the action was performed
            # correctly. PASS requires an independent, *later* authenticated Git
            # semantic judgment on the exact reserved work and every due MG0.
            # FAIL/BLOCKED may always close without pretending to be a PASS.
            if result.upper() == 'PASS' and active.get('category') in ('GENERATION','MUTATION','EXPORT'):
                # A second native PASS about pre-operation inputs cannot by itself
                # prove that a 3D output was actually produced. Verify actual
                # controller-registered output bytes and the append-only audit
                # before allowing a mutating step to close successfully.
                import real_work_intake
                from pathlib import Path
                events, _ = real_work_intake.audit_check(
                    self.c.audit_path(self.asset).read_bytes(), self.asset)
                artifacts = [a for a in self.c.asset_state(self.asset).get('artifacts', ())
                             if a.get('step') == step and isinstance(a.get('path'), str)]
                j.need(artifacts,'CONTROLLED_MUTATING_OUTPUT_EVIDENCE_REQUIRED')
                allowed={'.blend','.glb','.gltf','.fbx','.obj','.ydr','.ytd','.yft','.ymap','.ytyp','.zip'}
                observed=set()
                for item in artifacts:
                    path=Path(item['path'])
                    j.need(path.suffix.lower() in allowed and path.is_file() and
                           not path.is_symlink() and
                           isinstance(item.get('role'),str) and bool(item['role']) and
                           type(item.get('size_bytes')) is int and item['size_bytes'] > 20 and
                           j.evidence.is_sha(item.get('sha256')),
                           'CONTROLLED_MUTATING_OUTPUT_NOT_A_MODEL')
                    j.need(path.stat().st_size == item['size_bytes'] and
                           hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'],
                           'CONTROLLED_MUTATING_OUTPUT_BYTES_CHANGED')
                    match=[ev for ev in events if ev.get('event') == 'ARTIFACT_RECORDED'
                           and ev.get('step') == step and
                           ev.get('evidence_operation') == item]
                    j.need(len(match)==1,'CONTROLLED_MUTATING_OUTPUT_AUDIT_ABSENT')
                    observed.add(item['sha256'])
                j.need(bool(observed),'CONTROLLED_MUTATING_OUTPUT_NO_HASH')
            if result.upper() == 'PASS':
                from datetime import datetime, timezone
                j.need(isinstance(post_origin, dict) and isinstance(post_offers, dict),
                       'CONTROLLED_POST_NATIVE_PROOF_REQUIRED')
                records = self.records()
                reservation = next(r for r in records if r['record_hash'] == rows[0]['reservation_hash'])
                work = reservation['work']
                plan = next(r['plan'] for r in records if r['record_hash'] == reservation['plan_record_hash'])
                began = [r for r in records if r['event'] == 'SUPERVISOR_NATIVE_DECISION'
                         and r['decision'].get('operation_sha256') == work['operation_sha256']]
                j.need(len(began) == 1, 'CONTROLLED_BEGIN_NATIVE_RECORD')
                begin_origin = began[0]['origin']
                j.need(post_origin.get('run_id') != begin_origin.get('run_id') and
                       post_origin.get('job_id') != begin_origin.get('job_id'),
                       'CONTROLLED_POST_CANNOT_REUSE_BEGIN_PROOF')
                post_run = self.api.call('GET', '/actions/runs/' + str(post_origin['run_id']))
                stamp = post_run.get('created_at')
                j.need(isinstance(stamp, str), 'CONTROLLED_POST_RUN_START_NOT_ATTESTED')
                started = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
                opened = datetime.fromisoformat(active['opened_at'].replace('Z', '+00:00'))
                j.need(started.tzinfo is not None and opened.tzinfo is not None and
                       started >= opened, 'CONTROLLED_POST_PREDATES_OPERATION')
                prior_decision = None
                prior_context = None
                if work['attempt_number'] > 1:
                    old = [r for r in records if r['event'] == 'SUPERVISOR_NATIVE_DECISION'
                           and r['decision'].get('attempt_id') == work['previous_attempt_id']]
                    j.need(len(old) == 1, 'CONTROLLED_POST_CORRECTION_LINEAGE')
                    prior_decision = j.native_decision(self.api, old[0]['origin'], old[0]['issuer'])
                    j.need(prior_decision == old[0]['decision'], 'CONTROLLED_POST_PRIOR_GIT_CHANGED')
                    prior_context = old[0]['contexts']
                post_decision = j.native_decision(self.api, post_origin, plan['issuer'])
                post_backend = j.NativeRuleBackend(self.api, plan['enrolled'])
                fresh = j.judge(self.inventory, work, post_offers, post_backend,
                                current_contexts=self.contexts(), previous_contexts=prior_context,
                                previous_decision=prior_decision)
                j.need(post_decision == fresh and
                       fresh.get('advancement_authorized') is True and
                       fresh.get('action') == 'READY_FOR_EXACT_OPERATION' and
                       fresh.get('operation_sha256') == work['operation_sha256'],
                       'CONTROLLED_POST_NATIVE_RULES_MG0_NOT_VERIFIED')
                self.append('SUPERVISOR_POST_OPERATION_VERIFIED',
                            reservation_hash=rows[0]['reservation_hash'],
                            operation_sha256=work['operation_sha256'],
                            native_origin=post_origin, native_decision_sha256=post_decision['decision_sha256'],
                            scope='POST_OPERATION_NATIVE_RULE_AND_MG0_CHECK')
            rec = self.c.close(self.asset, step, token, result, evidence, regression, sections_after, critical)
            self.append('SUPERVISOR_OPERATION_CLOSED', reservation_hash=rows[0]['reservation_hash'],
                        operation_sha256=rows[0]['operation_sha256'], step=step,
                        controller_close_hash=rec['record_hash'], result=rec['result'])
            return rec


def main(argv=None):
    """Controller entry point; canonical sources come from immutable private Git.

    The local workspace holds the Library Master, work state, audit and private
    dependencies. Nothing in that workspace is uploaded by this command.
    """
    import argparse
    import golden_controller
    import family_coverage
    from broker_live_review import decode_file
    from git_judgment_origin import OriginAPI, PRIVATE_REPO_SHA
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('request', 'begin', 'close', 'enroll'))
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--asset', required=True)
    parser.add_argument('--source-ref', required=True)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--origin', type=Path)
    parser.add_argument('--offers', type=Path)
    parser.add_argument('--close-record', type=Path)
    args = parser.parse_args(argv)
    try:
        j.need(j.re.fullmatch('[a-f0-9]{40}', args.source_ref), 'CONTROLLED_IMMUTABLE_SOURCE_REF')
        api = OriginAPI(os.environ['GH_REVIEW_TOKEN'], os.environ['GITHUB_REPOSITORY'])
        j.need(hashlib.sha256(api.repository.encode()).hexdigest() == PRIVATE_REPO_SHA,
               'CONTROLLED_REPOSITORY')
        raw = {key: decode_file(api.call('GET', '/contents/' + path + '?ref=' + args.source_ref), path)
               for key, path in family_coverage.SOURCES.items()}
        c = golden_controller.Controller(args.workspace, args.master)
        inv = family_coverage.build_inventory(raw, c.master_identity()['sha256'])
        bridge = ControlledJudgment(c, args.asset, api, inv)
        def data(path):
            j.need(path is not None, 'CONTROLLED_REQUIRED_INPUT')
            return j.evidence.strict_json(path.read_bytes(), max_size=1000000)
        if args.command == 'request':
            result = {'work': bridge.expected_work(), 'advancement_authorized': False}
        elif args.command == 'enroll':
            result = {'plan_record_hash': bridge.enroll_plan(data(args.plan)),
                      'advancement_authorized': False}
        elif args.command == 'begin':
            result = bridge.begin(data(args.origin), data(args.offers))
        else:
            result = bridge.close(**data(args.close_record))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print('CONTROLLED_BLOCKED:' + str(exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

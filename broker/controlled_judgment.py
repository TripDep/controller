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
OPTIONAL_QUESTION_CONTEXT = {'question_context'}


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

    def verify_question_context(self, plan):
        """Recheck explicit owner-reviewed scope and local evidence under lock.

        A hash pointer alone is not permission. STATUS/D authorization is
        required at enrollment; exact evidence bytes must remain unchanged
        on every subsequent plan access. Missing proof leaves question DUE.
        """
        from c07_contextual_questions import select as context_select
        report = context_select(self.inventory, plan)
        if report:
            for rid in report['excluded']:
                spec = report['rows'][rid]
                proof = self.local_file(spec['evidence_ref']).read_bytes()
                j.need(hashlib.sha256(proof).hexdigest() == spec['evidence_sha256'],
                       'CONTROLLED_300_SCOPE_EVIDENCE_CHANGED:' + rid)
                memo = j.evidence.strict_json(proof, max_size=32000)
                j.need(type(memo) is dict and set(memo) == {
                    'schema','asset','master_sha256','rule_id','requirement_sha256',
                    'reason','owner_decision'} and
                    memo['schema'] == 'gg-c07-owner-scope-decision-v1' and
                    memo['asset'] == self.asset and
                    memo['master_sha256'] == plan['master_sha256'] and
                    memo['rule_id'] == rid and
                    memo['requirement_sha256'] == spec['requirement_sha256'] and
                    memo['reason'] == spec['reason'] and
                    memo['owner_decision'] == 'EXCLUDE_THIS_QUESTION_FOR_THIS_EXACT_ASSET_SCOPE',
                    'CONTROLLED_300_SCOPE_EVIDENCE_NOT_SPECIFIC:' + rid)
        return report

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
            j.need(set(plan) in (PLAN_KEYS, PLAN_KEYS|OPTIONAL_QUESTION_CONTEXT) and
                   set(plan['operation']) == OP_KEYS, 'CONTROLLED_PLAN_SCHEMA')
            self.verify_question_context(plan)
            j.need(plan['inventory_sha256'] == j.digest(self.inventory), 'CONTROLLED_INVENTORY')
            j.need(plan['master_sha256'] == self.c.master_identity()['sha256'], 'CONTROLLED_MASTER')
            j.need(plan['operation']['category'] != 'MASTER_UPDATE', 'CONTROLLED_MASTER_UPDATE_SEPARATE')
            j.need(plan['dependency_files'] and isinstance(plan['enrolled'], dict), 'CONTROLLED_PLAN_DEPENDENCIES')
            # A native origin alone does not prove a validator checks a rule.
            # Only reviewed source-specific implementations may be enrolled.
            from approved_validators import validate as validate_reviewed
            validate_reviewed(plan['enrolled'],self.inventory)
            from c07_operation_scope import require_due_enrolled
            require_due_enrolled(self.inventory, plan)
            # Canonical full inventory always gets exact 153-source gate.
            # Tiny synthetic Controller fixtures have no source digest map.
            if self.inventory.get('rule_count') == 763 or 'source_digests' in self.inventory:
                from c07_non_aaa_153 import require_operational_scope
                require_operational_scope(self.inventory, plan)
                from c07_behavior_110 import require_operational_scope as require_behavior_110
                require_behavior_110(self.inventory, plan)
                from c07_aaa200 import require_operational_scope as require_aaa200
                require_aaa200(self.inventory, plan)
                from c07_questions_300 import require_operational_scope as require_questions_300
                require_questions_300(self.inventory, plan)
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
        self.verify_question_context(row['plan'])
        from approved_validators import validate as validate_reviewed
        validate_reviewed(row['plan']['enrolled'],self.inventory)
        from c07_operation_scope import require_due_enrolled
        require_due_enrolled(self.inventory, row['plan'])
        if self.inventory.get('rule_count') == 763 or 'source_digests' in self.inventory:
            from c07_non_aaa_153 import require_operational_scope
            require_operational_scope(self.inventory, row['plan'])
            from c07_behavior_110 import require_operational_scope as require_behavior_110
            require_behavior_110(self.inventory, row['plan'])
            from c07_aaa200 import require_operational_scope as require_aaa200
            require_aaa200(self.inventory, row['plan'])
            from c07_questions_300 import require_operational_scope as require_questions_300
            require_questions_300(self.inventory, row['plan'])
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
        # Preserve failed assistant-answer attempts, not only native Git STOPs.
        # Otherwise begin can append an answer FAIL and a new request silently
        # reuses the old attempt_id, breaking C08 correction lineage.
        last_gate = next((r for r in reversed(records) if r['event'] in
                          ('SUPERVISOR_NATIVE_DECISION',
                           'SUPERVISOR_ASSISTANT_ANSWER_GATE')), None)
        answer_parent = (last_gate if last_gate and last_gate['event'] ==
                         'SUPERVISOR_ASSISTANT_ANSWER_GATE' else None)
        previous = (last_gate if last_gate and last_gate['event'] ==
                    'SUPERVISOR_NATIVE_DECISION' else None)
        if previous and previous['decision']['action'] == 'READY_FOR_EXACT_OPERATION':
            operation = previous['decision']['operation_sha256']
            completed = [r for r in records if r['event'] == 'SUPERVISOR_OPERATION_CLOSED' and
                         r['operation_sha256'] == operation and r['result'] == 'PASS']
            if previous['plan_record_hash'] != row['record_hash'] and len(completed) == 1:
                previous = None
        j.need(not previous or previous['decision']['action'] in
               ('STOP_CORRECT_RESUBMIT', 'STOP_CONTEXT_RECHECK'), 'CONTROLLED_PREVIOUS_NOT_FAILED')
        st = self.c.asset_state(self.asset)
        position = {'next_step': st['next_step'], 'plan_record_hash': row['record_hash'],
                    'operation': plan['operation'], 'work_item_sha256': j.digest(self.asset)}
        operation_sha = j.digest(position)
        if answer_parent:
            report = answer_parent['report']
            j.need(report.get('plan_record_hash') == row['record_hash'] and
                   report.get('checkpoint', {}).get('plan_record_hash') == row['record_hash'] and
                   report['checkpoint'].get('next_step') == st['next_step'] and
                   report.get('operation_sha256') == operation_sha and
                   report.get('master_sha256') == plan['master_sha256'] and
                   report.get('work_item_sha256') == j.digest(self.asset),
                   'CONTROLLED_ANSWER_RETRY_CONTEXT_DRIFT')
            # A claimed eligible answer that was interrupted before native
            # judgment is UNCERTAIN, not permission to repeat an operation.
            j.need(report.get('may_request_native_proof') is False and
                   report.get('blocking_reasons') and
                   report.get('answer_verdict') in ('FAIL', 'UNKNOWN'),
                   'CONTROLLED_ANSWER_ATTEMPT_REQUIRES_RECONCILIATION')
            j.need(type(report.get('attempt_number')) is int and
                   report['attempt_number'] > 0 and
                   j.evidence.is_sha(report.get('attempt_id')),
                   'CONTROLLED_ANSWER_RETRY_LINEAGE_INVALID')
        parent = answer_parent['report'] if answer_parent else (
            previous['decision'] if previous else None)
        parent_record_hash = (answer_parent or previous or {}).get('record_hash')
        work = {k: copy.deepcopy(plan[k]) for k in ('phase', 'asset_type', 'profiles',
                'master_sha256', 'asset_specific_extensions_verified', 'guardian_required',
                'mode', 'closure_requested')}
        if 'question_context' in plan:
            work['question_context'] = copy.deepcopy(plan['question_context'])
        work.update(work_item_sha256=j.digest(self.asset), operation_sha256=operation_sha,
                    work_dependencies={key: hashlib.sha256(self.local_file(path).read_bytes()).hexdigest()
                                       for key, path in plan['dependency_files'].items()},
                    attempt_number=parent['attempt_number'] + 1 if parent else 1,
                    previous_attempt_id=parent['attempt_id'] if parent else None)
        work['attempt_id'] = j.digest({'work': work, 'prior_record': parent_record_hash})
        j.validate_work(work, self.inventory)
        old_decision = None
        if previous:
            old_decision = j.native_decision(self.api, previous['origin'], previous['issuer'])
            j.need(old_decision == previous['decision'], 'CONTROLLED_PRIOR_NATIVE_CHANGED')
        elif answer_parent:
            # Verified native origin is NOT claimed for an assistant admission.
            # This narrow Controller-audit STOP establishes correction lineage
            # only. Current independent Git/MG0 proofs are still compulsory.
            old_decision = {
                'work_item_sha256': answer_parent['report']['work_item_sha256'],
                'attempt_id': answer_parent['report']['attempt_id'],
                'attempt_number': answer_parent['report']['attempt_number'],
                'action': 'STOP_CORRECT_RESUBMIT',
                'prior_source': 'CONTROLLER_AUDITED_ANSWER_FAIL'}
        return work, previous, old_decision

    def expected_work(self):
        """Read-only request for native validators; cannot itself authorize work."""
        with self.locked():
            row = self.plan()
            work, _, _ = self.prepare(row)
            return work

    def expected_question_batch(self, *, compound_rule=None, subcheck_offset=0, subcheck_limit=20):
        """Offer the exact due-question challenge without authorizing work."""
        with self.locked():
            row = self.plan()
            work, _, _ = self.prepare(row)
            st = self.c.asset_state(self.asset)
            from c07_live_answer_gate import challenge
            checkpoint = {'asset': self.asset, 'next_step': st['next_step'],
                          'last_audit_hash': st['last_audit_hash'],
                          'plan_record_hash': row['record_hash']}
            return {'work': work, 'question_batch':
                    challenge(self.inventory, row['plan'], work, checkpoint,
                              detail_rule=compound_rule,
                              subcheck_offset=subcheck_offset,
                              subcheck_limit=subcheck_limit),
                    'advancement_authorized': False}

    def probe_registered_glb(self, artifact_sha256, rule_id):
        """Read-only evidence probe on a Controller-registered real GLB.

        A work plan, exact attempt, artifact entry and matching append-only
        ARTIFACT_RECORDED event are mandatory. A scanner result is never a
        native semantic/MG0 PASS and this operation never writes the audit.
        """
        from glb_rule_bridge import verify_live, SCANNED_RULES
        from c07_operation_scope import inspect as inspect_scope
        with self.locked():
            row = self.plan()
            work, _, _ = self.prepare(row)
            j.need(rule_id in SCANNED_RULES and
                   rule_id in inspect_scope(self.inventory,row['plan'])['due'],
                   'CONTROLLED_GLB_RULE_NOT_DUE')
            j.need(j.evidence.is_sha(artifact_sha256),
                   'CONTROLLED_GLB_ARTIFACT_DIGEST_REQUIRED')
            st = self.c.asset_state(self.asset)
            matched = [v for v in st.get('artifacts', [])
                       if type(v) is dict and v.get('sha256') == artifact_sha256
                       and isinstance(v.get('path'), str)
                       and Path(v['path']).suffix.lower() == '.glb']
            j.need(len(matched) == 1,
                   'CONTROLLED_GLB_EXACT_REGISTERED_ARTIFACT_REQUIRED')
            item = matched[0]
            p = Path(item['path'])
            j.need(p.is_absolute() and p.is_file() and not p.is_symlink()
                   and not any(parent.is_symlink() for parent in p.parents)
                   and type(item.get('size_bytes')) is int and item['size_bytes'] > 20
                   and p.stat().st_size == item['size_bytes'],
                   'CONTROLLED_GLB_REGISTERED_SOURCE_CHANGED')
            events = [r for r in self.records()
                      if r.get('event') == 'ARTIFACT_RECORDED'
                      and r.get('step') == item.get('step')
                      and r.get('evidence_operation') == item
                      and r.get('result') == 'PASS']
            j.need(len(events) == 1,
                   'CONTROLLED_GLB_SOURCE_AUDIT_MISSING_OR_AMBIGUOUS')
            context = {'asset_id':self.asset, 'attempt_id':work['attempt_id'],
                       'operation_sha256':work['operation_sha256'],
                       'master_sha256':work['master_sha256'],
                       'phase':work['phase'], 'rule_id':rule_id}
            checked = verify_live(p, artifact_sha256, context)
            j.need(checked['acceptance_authorized'] is False
                   and checked['individual_mg0'] == 'UNKNOWN'
                   and checked['semantic_verdict'] in ('UNKNOWN','FAIL'),
                   'CONTROLLED_GLB_EVIDENCE_CANNOT_CERTIFY')
            return {'schema':'gg-c07-controller-glb-diagnostic-v1',
                    'asset':self.asset, 'registered_artifact_sha256':artifact_sha256,
                    'source_record_hash':events[0]['record_hash'],
                    'plan_record_hash':row['record_hash'],
                    'machine_evidence':checked,
                    'semantic_and_mg0_passes':0,
                    'advancement_authorized':False}

    def begin(self, origin, offers, answer_packets=None, subcheck_packets=None):
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
            # C07: receive real answers bound to the exact Controller operation.
            # This never awards PASS: independent native Git rule/MG0 proof is
            # required afterwards. Current composite rules remain STOP until
            # individually verified.
            if self.inventory.get('rule_count') == 763:
                from c07_live_answer_gate import inspect as inspect_answers
                answer_report = inspect_answers(
                    self.inventory, plan, work,
                    answer_packets if answer_packets is not None else [],
                    {'asset': self.asset, 'next_step': st['next_step'],
                     'last_audit_hash': st['last_audit_hash'],
                     'plan_record_hash': row['record_hash']},
                    subcheck_packets=subcheck_packets)
                self.append('SUPERVISOR_ASSISTANT_ANSWER_GATE', report=answer_report)
                print('C07_ANSWER_GATE_REPORT:' + json.dumps(answer_report, sort_keys=True))
                j.need(answer_report['may_request_native_proof'],
                       'CONTROLLED_ASSISTANT_ANSWERS_STOP:' +
                       ','.join(answer_report['blocking_reasons']))
            # Independently replay canonical MG0 process-falsification signals
            # from the complete current Controller audit for EVERY due rule and
            # the exact attempt. An uncorrected observed process failure STOPs
            # before the native operation can be opened. UNKNOWN is not a PASS:
            # the Git per-rule semantic packet must still prove its own MG0.
            from c07_operation_scope import inspect as inspect_scope
            from c07_mg0_individual import inspect as inspect_mg0
            due = inspect_scope(self.inventory, plan)['due']
            master_raw = self.c.master.read_bytes()
            audit_raw = self.c.audit_path(self.asset).read_bytes()
            for rule_id in due:
                review = inspect_mg0(master_raw, audit_raw, self.asset,
                                     work['master_sha256'], rule_id,
                                     work['attempt_id'])
                j.need(review['individual_rule_mg0'] != 'FAIL',
                       'CONTROLLED_CURRENT_RULE_MG0_PROCESS_FAILURE:' + rule_id)
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
                # Independently re-parse the exact Controller-registered GLB
                # after checking the append-only artifact event and its SHA.
                # This is a *negative* machine gate: it cannot itself PASS
                # visual, artistic, runtime, MG0 or canonical rule semantics.
                from glb_output_close_gate import inspect as inspect_glb_outputs
                machine_gate=inspect_glb_outputs(artifacts,work,self.asset,step)
                # Persist both STOPs and eligible machine assessments before
                # evaluating the post-run native judgment. No PASS is awarded
                # by this read-only machine evidence event.
                self.append('SUPERVISOR_GLB_OUTPUT_MACHINE_GATE',
                            step=step,
                            operation_sha256=work['operation_sha256'],
                            attempt_id=work['attempt_id'],
                            source_artifact_sha256=sorted(observed),
                            machine_gate=machine_gate,
                            machine_gate_sha256=j.digest(machine_gate),
                            result=('STOP_MACHINE_EVIDENCE' if not machine_gate[
                                'may_continue_to_independent_native_post_review'] else
                                'ELIGIBLE_FOR_SEPARATE_NATIVE_REVIEW_NO_PASS'))
                j.need(machine_gate['may_continue_to_independent_native_post_review']
                       and machine_gate['semantic_result']=='UNKNOWN'
                       and machine_gate['individual_mg0']=='UNKNOWN'
                       and machine_gate['advancement_authorized'] is False,
                       'CONTROLLED_GLB_MACHINE_OUTPUT_STOP:'+
                       ','.join(v['reason'] for v in machine_gate['machine_blockers']))

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
                    if len(old) == 1:
                        prior_decision = j.native_decision(self.api, old[0]['origin'], old[0]['issuer'])
                        j.need(prior_decision == old[0]['decision'], 'CONTROLLED_POST_PRIOR_GIT_CHANGED')
                        prior_context = old[0]['contexts']
                    else:
                        # Earlier admission failed before native Git; verify
                        # its append-only Controller provenance and exact lineage.
                        prior_gate = [r for r in records if
                            r['event'] == 'SUPERVISOR_ASSISTANT_ANSWER_GATE' and
                            r.get('report',{}).get('attempt_id') == work['previous_attempt_id']]
                        j.need(not old and len(prior_gate) == 1 and
                               prior_gate[0]['report'].get('may_request_native_proof') is False and
                               prior_gate[0]['report'].get('blocking_reasons') and
                               prior_gate[0]['report'].get('attempt_number') == work['attempt_number'] - 1 and
                               prior_gate[0]['report'].get('work_item_sha256') == work['work_item_sha256'] and
                               prior_gate[0]['report'].get('operation_sha256') == work['operation_sha256'],
                               'CONTROLLED_POST_CORRECTION_LINEAGE')
                        prior_decision = {
                            'work_item_sha256': work['work_item_sha256'],
                            'attempt_id': work['previous_attempt_id'],
                            'attempt_number': work['attempt_number'] - 1,
                            'action': 'STOP_CORRECT_RESUBMIT',
                            'prior_source': 'CONTROLLER_AUDITED_ANSWER_FAIL'}
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
    parser.add_argument('command', choices=('request', 'begin', 'close', 'enroll', 'probe-glb'))
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--asset', required=True)
    parser.add_argument('--source-ref', required=True)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--origin', type=Path)
    parser.add_argument('--offers', type=Path)
    parser.add_argument('--answers', type=Path)
    parser.add_argument('--subcheck-answers', type=Path)
    parser.add_argument('--compound-rule')
    parser.add_argument('--subcheck-offset', type=int, default=0)
    parser.add_argument('--subcheck-limit', type=int, default=20)
    parser.add_argument('--close-record', type=Path)
    parser.add_argument('--glb-sha256')
    parser.add_argument('--glb-rule')
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
        if args.command == 'probe-glb':
            result = bridge.probe_registered_glb(args.glb_sha256, args.glb_rule)
        elif args.command == 'request':
            result = bridge.expected_question_batch(
                compound_rule=args.compound_rule,
                subcheck_offset=args.subcheck_offset,
                subcheck_limit=args.subcheck_limit)
        elif args.command == 'enroll':
            result = {'plan_record_hash': bridge.enroll_plan(data(args.plan)),
                      'advancement_authorized': False}
        elif args.command == 'begin':
            result = bridge.begin(data(args.origin), data(args.offers),
                                  data(args.answers) if args.answers else None,
                                  data(args.subcheck_answers) if args.subcheck_answers else None)
        else:
            result = bridge.close(**data(args.close_record))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print('CONTROLLED_BLOCKED:' + str(exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

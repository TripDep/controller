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

    def probe_registered_glb_batch(self, artifact_sha256, rule_ids):
        """One Controller-registered real GLB, many exact DUE canonical IDs.

        This is independent negative evidence only: cannot enroll validators,
        certify unseen artistic checks, authorize work or provide MG0 PASS.
        """
        from glb_rule_bridge import verify_live_batch
        from c07_operation_scope import inspect as inspect_scope
        with self.locked():
            row = self.plan()
            work, _, _ = self.prepare(row)
            due = set(inspect_scope(self.inventory,row['plan'])['due'])
            j.need(type(rule_ids) is list and 0 < len(rule_ids) <= 200
                   and rule_ids == sorted(set(rule_ids))
                   and set(rule_ids) <= due
                   and set(rule_ids) <= set(self.inventory['rules']),
                   'CONTROLLED_GLB_BATCH_CANONICAL_DUE_RULES_REQUIRED')
            j.need(j.evidence.is_sha(artifact_sha256),
                   'CONTROLLED_GLB_BATCH_SOURCE_SHA_REQUIRED')
            st = self.c.asset_state(self.asset)
            matches = [v for v in st.get('artifacts', [])
                       if type(v) is dict and v.get('sha256') == artifact_sha256
                       and isinstance(v.get('path'), str)
                       and Path(v['path']).suffix.lower() == '.glb']
            j.need(len(matches) == 1,
                   'CONTROLLED_GLB_BATCH_REGISTERED_ARTIFACT_REQUIRED')
            item = matches[0]
            p = Path(item['path'])
            j.need(p.is_absolute() and p.is_file() and not p.is_symlink()
                   and not any(parent.is_symlink() for parent in p.parents)
                   and type(item.get('size_bytes')) is int and item['size_bytes'] > 20
                   and p.stat().st_size == item['size_bytes'],
                   'CONTROLLED_GLB_BATCH_REGISTERED_SOURCE_CHANGED')
            events = [r for r in self.records()
                      if r.get('event') == 'ARTIFACT_RECORDED'
                      and r.get('step') == item.get('step')
                      and r.get('evidence_operation') == item
                      and r.get('result') == 'PASS']
            j.need(len(events) == 1,
                   'CONTROLLED_GLB_BATCH_AUDIT_PROOF_MISSING_OR_AMBIGUOUS')
            context = {'asset_id':self.asset, 'attempt_id':work['attempt_id'],
                       'operation_sha256':work['operation_sha256'],
                       'master_sha256':work['master_sha256'], 'phase':work['phase']}
            observed = verify_live_batch(p,artifact_sha256,context,rule_ids)
            j.need(observed['rule_count'] == len(rule_ids)
                   and set(observed['rules']) == set(rule_ids)
                   and observed['work_rule_passes'] == 0
                   and observed['individual_mg0_passes'] == 0
                   and observed['advancement_authorized'] is False
                   and all(e['individual_mg0'] == 'UNKNOWN'
                           and e['independent_native_rule_observation']
                           in ('FAIL','UNKNOWN')
                           for e in observed['rules'].values()),
                   'CONTROLLED_GLB_BATCH_NO_NATIVE_OR_MG0_PASS')
            return {'schema':'gg-c07-controller-registered-glb-batch-v1',
                    'asset':self.asset,
                    'registered_artifact_sha256':artifact_sha256,
                    'source_record_hash':events[0]['record_hash'],
                    'plan_record_hash':row['record_hash'],
                    'native_negative_rule_observations':observed,
                    'operational_semantic_passes':0,
                    'individual_mg0_passes':0,
                    'advancement_authorized':False}

    def probe_registered_visual_deck(self, artifact_sha256, manifest_path, manifest_sha256):
        """Read-only 8-angle integrity challenge on exact registered GLB.

        This checks source/manifest/image transport, not authenticity of
        image contents or artistic quality. No Controller state transition.
        """
        from glb_visual_deck_readback import readback
        from c07_operation_scope import inspect as inspect_scope
        with self.locked():
            row=self.plan()
            work,_,_=self.prepare(row)
            j.need('VISUAL_QA' in inspect_scope(self.inventory,row['plan'])['due'],
                   'CONTROLLED_VISUAL_QA_NOT_DUE')
            j.need(j.evidence.is_sha(artifact_sha256)
                   and j.evidence.is_sha(manifest_sha256),
                   'CONTROLLED_VISUAL_IMMUTABLE_PINS_REQUIRED')
            found=[v for v in self.c.asset_state(self.asset).get('artifacts',[])
                   if type(v) is dict and v.get('sha256')==artifact_sha256
                   and type(v.get('path')) is str
                   and Path(v['path']).suffix.lower()=='.glb']
            j.need(len(found)==1,'CONTROLLED_VISUAL_REGISTERED_GLB_REQUIRED')
            artifact=found[0]
            events=[ev for ev in self.records() if ev.get('event')=='ARTIFACT_RECORDED'
                    and ev.get('step')==artifact.get('step')
                    and ev.get('evidence_operation')==artifact
                    and ev.get('result')=='PASS']
            j.need(len(events)==1,'CONTROLLED_VISUAL_GLTF_AUDIT_MISSING')
            manifest=self.local_file(manifest_path)
            context={'asset_id':self.asset,'attempt_id':work['attempt_id'],
                     'operation_sha256':work['operation_sha256'],
                     'master_sha256':work['master_sha256'],'phase':work['phase']}
            evidence=readback(Path(artifact['path']),manifest,artifact_sha256,
                              manifest_sha256,context)
            j.need(evidence['semantic_verdict']=='UNKNOWN'
                   and evidence['individual_mg0']=='UNKNOWN'
                   and evidence['work_advancement_authorized'] is False,
                   'CONTROLLED_VISUAL_CANNOT_CERTIFY')
            return {'schema':'gg-c07-controller-visual-deck-probe-v1',
                    'registered_source_sha256':artifact_sha256,
                    'artifact_audit_record_hash':events[0]['record_hash'],
                    'approved_plan_record_hash':row['record_hash'],
                    'visual_evidence':evidence,'advancement_authorized':False}

    def probe_registered_blender_roundtrip(self, artifact_sha256, blender_executable):
        """Read-only native Blender inspection of a registered .blend source.

        Requires exact current work identity, canonical MACHINE_QA DUE and
        unique real ARTIFACT_RECORDED. Even successful Blender subprocess
        never grants visual, FiveM, semantic, production or MG0 PASS.
        """
        from c07_operation_scope import inspect as inspect_scope
        from blender_roundtrip_driver import inspect as run_blender_diagnostic
        with self.locked():
            row=self.plan()
            work,_,_=self.prepare(row)
            j.need('MACHINE_QA' in inspect_scope(self.inventory,row['plan'])['due'],
                   'CONTROLLED_NATIVE_MACHINE_QA_NOT_DUE')
            j.need(j.evidence.is_sha(artifact_sha256),
                   'CONTROLLED_NATIVE_SHA_REQUIRED')
            found=[v for v in self.c.asset_state(self.asset).get('artifacts',[])
                   if type(v) is dict and v.get('sha256')==artifact_sha256
                   and type(v.get('path')) is str
                   and Path(v['path']).suffix.lower()=='.blend']
            j.need(len(found)==1,'CONTROLLED_NATIVE_EXACT_REGISTERED_BLEND_REQUIRED')
            item=found[0]
            p=Path(item['path'])
            j.need(p.is_absolute() and p.is_file() and not p.is_symlink()
                   and not any(parent.is_symlink() for parent in p.parents)
                   and type(item.get('size_bytes')) is int
                   and p.stat().st_size==item['size_bytes'],
                   'CONTROLLED_NATIVE_SOURCE_CHANGED')
            events=[ev for ev in self.records()
                    if ev.get('event')=='ARTIFACT_RECORDED'
                    and ev.get('step')==item.get('step')
                    and ev.get('evidence_operation')==item
                    and ev.get('result')=='PASS']
            j.need(len(events)==1,'CONTROLLED_NATIVE_AUDIT_MISSING_OR_DUPLICATE')
            native=run_blender_diagnostic(p,artifact_sha256,
                Path(blender_executable),timeout_seconds=900)
            j.need(native['advancement_authorized'] is False
                   and native['individual_mg0']=='UNKNOWN'
                   and native['production_acceptance']=='NOT_AUTHORIZED'
                   and native['binary_identity_independently_attested'] is False,
                   'CONTROLLED_NATIVE_PROBE_CANNOT_GRANT_PASS')
            return {'schema':'gg-c07-controlled-blender-roundtrip-v1',
                    'asset':self.asset,'attempt_id':work['attempt_id'],
                    'operation_sha256':work['operation_sha256'],
                    'master_sha256':work['master_sha256'],
                    'registered_blend_sha256':artifact_sha256,
                    'source_record_hash':events[0]['record_hash'],
                    'plan_record_hash':row['record_hash'],
                    'native_runtime_diagnostic':native,
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
            from c07_mg0_individual import inspect_batch as inspect_mg0_batch
            due = inspect_scope(self.inventory, plan)['due']
            master_raw = self.c.master.read_bytes()
            audit_raw = self.c.audit_path(self.asset).read_bytes()
            mg0_batch = inspect_mg0_batch(master_raw, audit_raw, self.asset,
                                          work['master_sha256'], due,
                                          work['attempt_id'])
            # One verified chain readback; every DUE ID still receives its own
            # exact-attempt result. Unknown never means a semantic MG0 PASS.
            j.need(mg0_batch['rule_count'] == len(due) and
                   mg0_batch['individual_mg0_passes'] == 0 and
                   mg0_batch['advancement_authorized'] is False and
                   set(mg0_batch['rules']) == set(due),
                   'CONTROLLED_MG0_BATCH_SCOPE_INCOMPLETE')
            if mg0_batch['failed_rule_ids']:
                j.need(False, 'CONTROLLED_CURRENT_RULE_MG0_PROCESS_FAILURE:' +
                       mg0_batch['failed_rule_ids'][0])
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
            # C07 R112: mandatory exact-attempt replay of source/owner/GLB
            # negative semantic evidence. No prior green CI or missing error
            # can be treated as a rule or individual MG0 PASS.
            if result.upper() == 'PASS' and self.inventory.get('rule_count') == 763:
                from c07_negative_semantic_replay import inspect as replay_negatives
                events = self.records()
                reservations = [r for r in events
                                if r['record_hash'] == rows[0]['reservation_hash']
                                and r.get('event') == 'SUPERVISOR_OPERATION_RESERVED']
                j.need(len(reservations) == 1,
                       'CONTROLLED_R112_EXACT_RESERVATION_REQUIRED')
                reserved_work = reservations[0]['work']
                plans = [r for r in events
                         if r['record_hash'] == reservations[0]['plan_record_hash']
                         and r.get('event') == 'SUPERVISOR_PLAN_ENROLLED']
                j.need(len(plans) == 1,
                       'CONTROLLED_R112_PINNED_ENROLLED_PLAN_REQUIRED')
                # R114: verify one real canonical P0 process obligation
                # against ORIGINAL Controller state, hash-chain and dependency
                # file bytes. A per-operation documentary PASS is not a 3D,
                # positive full-rule or MG0 pass.
                from c07_operation_scope import inspect as inspected_scope
                if 'AAA-200-R-178' in inspected_scope(
                        self.inventory, plans[0]['plan'])['due']:
                    from c07_process_r178 import inspect as inspect_process_r178
                    provenance = inspect_process_r178(
                        self.c, self.asset, step, reserved_work,
                        plans[0]['plan'], self.inventory,
                        lambda relative: self.local_file(relative).read_bytes())
                    j.need(provenance['individual_mg0_passes'] == 0
                           and provenance['positive_3d_rule_semantic_passes'] == 0
                           and provenance['advancement_authorized'] is False,
                           'CONTROLLED_R114_PROCESS_OBSERVATION_CANNOT_CERTIFY')
                    self.append('SUPERVISOR_C07_R178_PROCESS_OBSERVATION',
                                attempt_id=reserved_work['attempt_id'],
                                operation_sha256=reserved_work['operation_sha256'],
                                rule_id='AAA-200-R-178',
                                result=provenance['current_operation_process_observation'],
                                failed_criteria=provenance['failed_criteria'],
                                provenance=provenance,
                                positive_3d_rule_semantic_passes=0,
                                individual_mg0_passes=0,
                                advancement_authorized=False)
                    j.need(provenance['current_operation_process_observation']
                           == 'PASS',
                           'CONTROLLED_R114_REAL_PROCESS_STATE_OR_DEPS_FAIL:'+
                           ','.join(provenance['failed_criteria']))
                replay = replay_negatives(
                    self.inventory, plans[0]['plan'],
                    self.c.audit_path(self.asset).read_bytes(),
                    self.asset, reserved_work['attempt_id'], batch_size=200,
                    operation_sha256=reserved_work['operation_sha256'])
                j.need(replay['rule_count'] == 763
                       and replay['batch_counts'] == [200,200,200,163]
                       and replay['positive_semantic_passes'] == 0
                       and replay['individual_mg0_passes'] == 0
                       and replay['advancement_authorized'] is False,
                       'CONTROLLED_R112_UNTRUSTED_SEMANTIC_REPLAY')
                self.append(
                    'SUPERVISOR_C07_NEGATIVE_RULE_REPLAY',
                    attempt_id=reserved_work['attempt_id'],
                    operation_sha256=reserved_work['operation_sha256'],
                    master_sha256=reserved_work['master_sha256'],
                    audit_input_sha256=replay['audit_sha256'],
                    replay_sha256=replay['report_sha256'],
                    batch_rule_digests=[x['detail_sha256'] for x in replay['batches']],
                    failed_due_rule_ids=replay['semantic_negative_fail_rule_ids'],
                    untrusted_owner_review_rule_ids=
                        replay['unverified_owner_review_rule_ids'],
                    result=('BLOCKED' if replay['next_action']=='STOP_CORRECT_REVIEW'
                            else 'UNKNOWN_NEEDS_POSITIVE_SEMANTICS_AND_MG0'),
                    work_passes=0, individual_mg0_passes=0,
                    advancement_authorized=False)
                j.need(replay['next_action'] != 'STOP_CORRECT_REVIEW',
                       'CONTROLLED_R112_SEMANTIC_FAILURE_STOP:'+
                       ','.join(replay['semantic_negative_fail_rule_ids']+
                                replay['unverified_owner_review_rule_ids']))
                # R115 ONE source-locked execution over all first 200 rules,
                # not another 200-item wording checklist. The same immutable
                # per-rule obligations flow into technical review below.
                # R116: second 200 rules are BEHAVIOR-110, G0, governance and
                # remaining AAA delivery, NOT a second copy of mesh predicates.
                # Independent consumer reads actual source rule clauses and
                # ORIGINAL append-only Controller audit before close(PASS).
                from c07_bulk_segment import inspect as inspect_bulk_segment
                second = inspect_bulk_segment(
                    self.inventory, plans[0]['plan'], segment=2,
                    audit_raw=self.c.audit_path(self.asset).read_bytes(),
                    asset=self.asset, attempt_id=reserved_work['attempt_id'],
                    operation_sha256=reserved_work['operation_sha256'])
                j.need(second['source_rule_count']==200 and
                       second['actual_controller_audit_scanned'] is True and
                       second['independent_current_asset_pass_count']==0 and
                       second['individual_mg0_pass_count']==0 and
                       second['advancement_authorized'] is False,
                       'CONTROLLED_R116_INCOMPLETE_SECOND_200_RULES')
                self.append('SUPERVISOR_C07_SECOND200_SEMANTIC_EVIDENCE',
                    attempt_id=reserved_work['attempt_id'],
                    operation_sha256=reserved_work['operation_sha256'],
                    master_sha256=reserved_work['master_sha256'],
                    source_rule_ids_sha256=second['source_rule_ids_sha256'],
                    rule_count=second['source_rule_count'],
                    source_chain=second['source_chain'],
                    batch_segments=second['chunks'],
                    native_counts=second['counts'],
                    failed_due_rule_ids=second['failed_due_rule_ids'],
                    result=('FAIL' if second['failed_due_rule_ids']
                            else 'UNKNOWN_SEMANTIC_PROOF_REQUIRED'),
                    current_asset_passes=0, individual_mg0_passes=0,
                    advancement_authorized=False)
                j.need(not second['failed_due_rule_ids'],
                       'CONTROLLED_R116_SECOND_200_NATIVE_FAILURES:'+
                       ','.join(second['failed_due_rule_ids']))
                # R117 Q-001..Q-150 and full source-defined third 200:
                # authenticate source question identities from the CURRENT
                # Controller answer gate, without equating YES with true.
                third = inspect_bulk_segment(
                    self.inventory, plans[0]['plan'], segment=3,
                    audit_raw=self.c.audit_path(self.asset).read_bytes(),
                    asset=self.asset, attempt_id=reserved_work['attempt_id'],
                    operation_sha256=reserved_work['operation_sha256'])
                j.need(third['source_rule_count']==200 and
                       third['actual_controller_audit_scanned'] is True and
                       third['independent_current_asset_pass_count']==0 and
                       third['individual_mg0_pass_count']==0 and
                       third['advancement_authorized'] is False,
                       'CONTROLLED_R117_INCOMPLETE_THIRD_200_RULES')
                self.append('SUPERVISOR_C07_THIRD200_QUESTION_AUDIT',
                    attempt_id=reserved_work['attempt_id'],
                    operation_sha256=reserved_work['operation_sha256'],
                    master_sha256=reserved_work['master_sha256'],
                    source_rule_ids_sha256=third['source_rule_ids_sha256'],
                    rule_count=third['source_rule_count'],
                    source_chain=third['source_chain'],
                    batch_segments=third['chunks'],
                    counts=third['counts'],
                    failed_due_rule_ids=third['failed_due_rule_ids'],
                    result=('FAIL' if third['failed_due_rule_ids']
                            else 'UNKNOWN_NEEDS_NATIVE_Q_PROOF'),
                    current_asset_passes=0, individual_mg0_passes=0,
                    advancement_authorized=False)
                j.need(not third['failed_due_rule_ids'],
                    'CONTROLLED_R117_THIRD_200_SEMANTIC_FAILURE:'+
                    ','.join(third['failed_due_rule_ids']))
                # R118: final 163 source rules (Q151..Q300 + governance).
                # Re-read ORIGINAL Controller work-state under the current
                # lock; an output cannot outvote absent D0 authorization.
                final_chunk = inspect_bulk_segment(
                    self.inventory, plans[0]['plan'], segment=4,
                    audit_raw=self.c.audit_path(self.asset).read_bytes(),
                    asset=self.asset, attempt_id=reserved_work['attempt_id'],
                    operation_sha256=reserved_work['operation_sha256'],
                    controller_state=self.c.state)
                j.need(final_chunk['source_rule_count']==163 and
                       final_chunk['actual_controller_audit_scanned'] is True
                       and final_chunk['controller_state_observation'][
                         'controller_state_tail_matches_original_audit'] is True
                       and final_chunk['independent_current_asset_pass_count']==0
                       and final_chunk['individual_mg0_pass_count']==0
                       and final_chunk['advancement_authorized'] is False,
                       'CONTROLLED_R118_INCOMPLETE_LAST_163_RULES')
                self.append('SUPERVISOR_C07_FINAL163_SEMANTIC_EVIDENCE',
                    attempt_id=reserved_work['attempt_id'],
                    operation_sha256=reserved_work['operation_sha256'],
                    master_sha256=reserved_work['master_sha256'],
                    source_rule_ids_sha256=final_chunk['source_rule_ids_sha256'],
                    rule_count=final_chunk['source_rule_count'],
                    state_evidence=final_chunk['controller_state_observation'],
                    source_chain=final_chunk['source_chain'],
                    batch_segments=final_chunk['chunks'],
                    counts=final_chunk['counts'],
                    failed_due_rule_ids=final_chunk['failed_due_rule_ids'],
                    result=('FAIL' if final_chunk['failed_due_rule_ids']
                            else 'UNKNOWN_NEEDS_INDEPENDENT_SEMANTIC_MG0'),
                    current_asset_passes=0,individual_mg0_passes=0,
                    advancement_authorized=False)
                j.need(not final_chunk['failed_due_rule_ids'],
                    'CONTROLLED_R118_FINAL_163_SEMANTIC_FAILURE:'+
                    ','.join(final_chunk['failed_due_rule_ids']))
                from c07_bulk200_semantics import inspect as bulk_200
                bulk = bulk_200(self.inventory, plans[0]['plan'],
                    audit_raw=self.c.audit_path(self.asset).read_bytes(),
                    asset=self.asset,
                    attempt_id=reserved_work['attempt_id'],
                    operation_sha256=reserved_work['operation_sha256'],
                    current_process_observation=(
                        provenance if 'AAA-200-R-178' in inspected_scope(
                            self.inventory, plans[0]['plan'])['due'] else None))
                j.need(bulk['source_rule_count']==200
                       and len(bulk['rules'])==200
                       and bulk['counts']['DUE']+bulk['counts']['NOT_DUE']==200
                       and bulk['positive_semantic_and_mg0_rule_passes']==0
                       and bulk['advancement_authorized'] is False,
                       'CONTROLLED_R115_INCOMPLETE_200_RULE_EXECUTION')
                self.append('SUPERVISOR_C07_R115_BATCH200_SEMANTIC_EXECUTION',
                    attempt_id=reserved_work['attempt_id'],
                    operation_sha256=reserved_work['operation_sha256'],
                    master_sha256=reserved_work['master_sha256'],
                    source_rule_ids_sha256=bulk['source_rule_ids_sha256'],
                    batch_segments=bulk['batch_segments'],
                    counts=bulk['counts'], current_asset_passes=0,
                    mode='INDEPENDENT_PROOF_LANES_WITHOUT_GLOBAL_POSITIVE_PASS',
                    advancement_authorized=False)
                j.need(not bulk['failed_due_rule_ids'],
                       'CONTROLLED_R115_BATCH200_RECOGNIZED_SEMANTIC_FAILURE:'+
                       ','.join(bulk['failed_due_rule_ids']))
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

                # C07: unlike an optional read-only probe, this real
                # Controller close gate REPLAYS every supported DUE canonical
                # native negative predicate on the actual output bytes.
                # The caller cannot select/omit its rule list.
                from c07_operation_scope import inspect as inspect_rule_scope
                from glb_rule_bridge import (CANONICAL_GLB_RULES,
                                             verify_live_batch)
                native_due = sorted(set(inspect_rule_scope(
                    self.inventory, plan)['due']) & set(CANONICAL_GLB_RULES))
                if native_due:
                    j.need(len(native_due) <= 200,
                           'CONTROLLED_POST_NATIVE_200_RULE_BOUND')
                    native_reports = []
                    negative_ids = set()
                    for item in artifacts:
                        if Path(item['path']).suffix.lower() != '.glb':
                            continue
                        native_context = {
                            'asset_id': self.asset,
                            'attempt_id': work['attempt_id'],
                            'operation_sha256': work['operation_sha256'],
                            'master_sha256': work['master_sha256'],
                            'phase': work['phase']}
                        scan = verify_live_batch(
                            Path(item['path']), item['sha256'],
                            native_context, native_due)
                        j.need(scan['rule_count'] == len(native_due)
                               and set(scan['rules']) == set(native_due)
                               and scan['individual_mg0_passes'] == 0
                               and scan['work_rule_passes'] == 0
                               and scan['advancement_authorized'] is False,
                               'CONTROLLED_POST_NATIVE_RULE_SCAN_CANNOT_AUTHORIZE')
                        negative_ids.update(rid for rid, check in scan['rules'].items()
                            if check['independent_native_rule_observation'] == 'FAIL')
                        native_reports.append(scan)
                    j.need(native_reports,
                           'CONTROLLED_POST_NATIVE_NO_VERIFIED_GLB')
                    self.append('SUPERVISOR_CANONICAL_NATIVE_NEGATIVE_GATE',
                                step=step, attempt_id=work['attempt_id'],
                                operation_sha256=work['operation_sha256'],
                                master_sha256=work['master_sha256'],
                                native_rule_ids=native_due,
                                registered_glb_sha256=sorted(a['sha256']
                                    for a in artifacts
                                    if Path(a['path']).suffix.lower() == '.glb'),
                                native_reports_sha256=j.digest(native_reports),
                                native_reports=native_reports,
                                result=('FAIL_NATIVE_FINDINGS' if negative_ids
                                        else 'UNKNOWN_AWAITING_SEMANTIC_AND_MG0'),
                                work_rule_passes=0, advancement_authorized=False)
                    j.need(not negative_ids,
                           'CONTROLLED_POST_CANONICAL_NATIVE_RULE_FAIL:'+
                           ','.join(sorted(negative_ids)))
                    # Even zero findings does NOT permit this action to close:
                    # the independent post-run semantic+MG0 gate still follows.

                # R115 repeats its entire first-200 evidence set against each
                # ORIGINAL Controller-registered GLB. 200 source-locked rule
                # contracts, a real machine re-scan, and no auto PASS.
                if self.inventory.get('rule_count')==763:
                    from c07_bulk200_semantics import inspect as batch_semantics
                    native_summaries=[]
                    for glb in (x for x in artifacts
                                if Path(x['path']).suffix.lower()=='.glb'):
                        reviewed=batch_semantics(
                            self.inventory, plan,
                            audit_raw=self.c.audit_path(self.asset).read_bytes(),
                            asset=self.asset, attempt_id=work['attempt_id'],
                            operation_sha256=work['operation_sha256'],
                            registered_glb_path=glb['path'],
                            glb_sha256=glb['sha256'])
                        j.need(reviewed['source_rule_count']==200 and
                               reviewed['actual_native_single_scan'] is True and
                               reviewed['positive_semantic_and_mg0_rule_passes']==0 and
                               reviewed['advancement_authorized'] is False,
                               'CONTROLLED_R115_GLB_BATCH_CANNOT_CERTIFY')
                        native_summaries.append({
                            'registered_glb_sha256':glb['sha256'],
                            'source_rule_ids_sha256':reviewed['source_rule_ids_sha256'],
                            'source_rules_examined':reviewed['source_rule_count'],
                            'native_machine_observations':reviewed['counts'][
                                'RULE_SPECIFIC_GLTF_NEGATIVE_PREDICATES'],
                            'current_rule_negative_findings':reviewed['failed_due_rule_ids'],
                            'batch_segment_digests':reviewed['batch_segments'],
                            'work_or_mg0_passes':0})
                    j.need(native_summaries,
                           'CONTROLLED_R115_REGISTERED_GLB_FOR_200_REQUIRED')
                    self.append('SUPERVISOR_C07_R115_REGISTERED_GLB_200_BATCH',
                         step=step, attempt_id=work['attempt_id'],
                         operation_sha256=work['operation_sha256'],
                         source_glbs=native_summaries,
                         current_semantic_passes=0,individual_mg0_passes=0,
                         advancement_authorized=False)
                    failures=sorted({rid for summary in native_summaries
                                     for rid in summary['current_rule_negative_findings']})
                    j.need(not failures,'CONTROLLED_R115_NATIVE_NEGATIVE_STOP:'+
                           ','.join(failures))

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
    parser.add_argument('command', choices=('request', 'begin', 'close', 'enroll', 'probe-glb', 'probe-visual', 'probe-blender'))
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
    parser.add_argument('--visual-manifest-path')
    parser.add_argument('--visual-manifest-sha256')
    parser.add_argument('--blender-executable', type=Path)
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
        if args.command == 'probe-blender':
            j.need(args.blender_executable is not None,
                   'CONTROLLED_BLENDER_BINARY_REQUIRED')
            result=bridge.probe_registered_blender_roundtrip(
                args.glb_sha256,args.blender_executable)
        elif args.command == 'probe-visual':
            result=bridge.probe_registered_visual_deck(args.glb_sha256,
                args.visual_manifest_path,args.visual_manifest_sha256)
        elif args.command == 'probe-glb':
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

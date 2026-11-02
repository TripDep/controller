"""Read macro100 evidence through an existing Controller transaction.

Registration authenticates provenance within this Controller, not semantic
truth of documentary statements. No packet may replace acquired audit/state.
"""
from pathlib import Path
import ast
from real_work_intake import strict_json, sha
from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_macro100_domain import require
from c07_macro100_semantics import inspect_candidate


def read_persisted_snapshot(controller_source, master_path, state_path, audit_path, asset):
    """Acquire a closed or blocked work item without opening/mutating a step.

    Read original bytes twice so mixed-revision reads cannot become a snapshot.
    Historical event Master identities are retained; they are not rewritten to
    the current Master. No observational facts are invented for missing lanes.
    """
    paths = [Path(p) for p in (controller_source, master_path, state_path, audit_path)]
    require(all(p.is_file() and not p.is_symlink() for p in paths), 'original snapshot file unavailable')
    raw = [p.read_bytes() for p in paths]
    versions = [node.value.value for node in ast.parse(raw[0]).body
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'VERSION'
                                                       for t in node.targets)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    require(len(versions) == 1, 'Controller version declaration ambiguous')
    state = strict_json(raw[2])
    require(type(state) is dict and asset in state.get('assets', {}), 'work item absent from state')
    from real_work_intake import audit_check
    records, tail = audit_check(raw[3], asset)
    current = state['assets'][asset]
    require(current.get('last_audit_hash') == tail, 'persisted audit/state divergence')
    require(all(p.read_bytes() == b for p,b in zip(paths, raw)), 'snapshot changed while reading')
    return {'schema': 'gg-c07-persisted-controller-snapshot-v1', 'asset': asset,
            'controller_version': versions[0],
            'source_sha256': dict(zip(('controller', 'master', 'state', 'audit'), map(sha, raw))),
            'audit_tail': tail, 'records': records, 'asset_state': current,
            'historical_master_sha256': sorted({r[k]['sha256'] for r in records
                 for k in ('master_check_before', 'master_check_after')
                 if isinstance(r.get(k), dict) and 'sha256' in r[k]}),
            'mg0': 'NOT_RUN', 'advancement_authorized': False}


def acquire(inventory, plan, controller, asset, step, work):
    records, tail, state, audit_sha = _original_attempt(
        inventory, plan, controller, asset, step, work)
    require(state.get('last_audit_hash') == tail, 'Controller state/audit divergence')
    master_raw = controller.master.read_bytes()
    require(sha(master_raw) == inventory['canonical_master_sha256'], 'Controller Master changed')
    state_raw = controller.state_path.read_bytes()
    persisted = strict_json(state_raw)
    require(persisted.get('assets', {}).get(asset) == state, 'persisted asset state differs')
    artifacts = _registered_artifacts(records, state, step,
                                     lambda path: Path(path).read_bytes(), work)
    expected = {k: work[k] for k in ('attempt_id', 'operation_sha256', 'master_sha256')}
    expected.update(asset=asset, step=step)
    blobs = {digest: raw for _, _, digest, raw in artifacts}
    blobs[sha(master_raw)] = master_raw
    blobs[sha(state_raw)] = state_raw
    audit_raw = controller.audit_path(asset).read_bytes()
    require(sha(audit_raw) == audit_sha, 'audit changed during acquisition')
    blobs[audit_sha] = audit_raw
    require(controller.state_path.read_bytes() == state_raw and
            controller.master.read_bytes() == master_raw, 'Controller changed during acquisition')
    # Only facts read from the Controller itself enter the evaluator. Artifact
    # registration does not establish the truth of arbitrary JSON observations.
    # In particular the former observation packet is never parsed or evaluated.
    observations = original_observations(records, state, master_raw, controller.master)
    report = inspect_candidate(inventory, observations, blobs)
    report['acquisition'] = {'binding': expected, 'audit_sha256': audit_sha,
                             'audit_tail': tail, 'state_sha256': sha(state_raw),
                             'registered_artifact_count': len(artifacts),
                             'observation_origin': 'ORIGINAL_CONTROLLER_RECORDS_ONLY',
                             'documentary_truth_authenticated': False}
    return report


def original_observations(records, state, master_raw, master_path):
    """Project original records without manufacturing absent domain evidence.

    A master_check proves the recorded file identity, not that its contents
    were completely read. A PASS close is not owner acceptance, a deployment,
    a functional test, a photographic origin or a license. Those lanes stay
    absent until an actual reader for their original source exists.
    """
    current = {'sha256': sha(master_raw), 'path': str(master_path),
               'version': state.get('master_version', 'UNKNOWN')}
    return {'master': current, 'controller_records': records,
            'controller_asset_state': state}


def acquire_registered_copies(snapshot, copies):
    """Read recovered Library originals by registered digest, not old host path.

    Repeated historical paths may identify different revisions; use the digest
    as the relocation key and preserve each registration/step independently.
    An unavailable revision remains missing, never silently substituted with a
    later file of the same name. Returns original bytes for consuming readers.
    """
    require(snapshot.get('schema') == 'gg-c07-persisted-controller-snapshot-v1',
            'verified Controller snapshot required')
    require(type(copies) is dict, 'original-copy mapping required')
    registrations = snapshot['asset_state'].get('artifacts')
    require(type(registrations) is list, 'Controller artifact registry unavailable')
    originals = {}
    results = []
    for registration in registrations:
        digest = registration.get('sha256')
        size = registration.get('size_bytes')
        row = {'registered_path': registration.get('path'),
               'step': registration.get('step'), 'sha256': digest}
        if type(digest) is not str or type(size) is not int or size <= 0:
            row['acquisition'] = 'UNBOUND'
        elif digest not in copies:
            row['acquisition'] = 'MISSING'
        else:
            path = Path(copies[digest])
            require(path.is_file() and not path.is_symlink(), 'original copy unavailable: '+digest)
            raw = path.read_bytes()
            require(len(raw) == size and sha(raw) == digest,
                    'recovered original differs from Controller registration: '+digest)
            require(path.read_bytes() == raw, 'recovered original changed during read: '+digest)
            originals[digest] = raw
            row['acquisition'] = 'ORIGINAL_BYTES_VERIFIED'
        results.append(row)
    return {'registrations': results, 'original_bytes': originals,
            'mg0': 'NOT_RUN', 'advancement_authorized': False}


def read_original_telemetry(path):
    """Read actual run records without promoting self-reports to provider facts.

    Wall elapsed is recomputed from timestamp pairs. Productive time and final
    provider events remain unavailable unless acquired independently; the log's
    prose, completion labels and EXECUTION_BUDGET are retained as claims only.
    """
    from c07_macro100_domain import instant
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'original telemetry unavailable')
    raw = path.read_bytes()
    require(len(raw) <= 40_000_000, 'telemetry exceeds source bound')
    rows = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        require(bool(line.strip()), 'blank telemetry record')
        record = strict_json(line)
        require(type(record) is dict, 'telemetry record must be object')
        starts = [record[k] for k in ('run_started_at', 'run_started_at_utc', 'run_start_utc')
                  if record.get(k) is not None]
        require(len(starts) <= 1, 'ambiguous telemetry start timestamp')
        finish = record.get('run_finished_at')
        elapsed = None
        if starts and finish is not None:
            elapsed = instant(finish)-instant(starts[0])
            require(elapsed >= 0, 'telemetry timestamps reversed')
        rows.append({'line': line_number, 'record_sha256': sha(line),
                     'run_id': record.get('run_id', record.get('run_number')),
                     'wall_elapsed_recomputed_seconds': elapsed,
                     'productive_seconds': None,
                     'provider_termination_cause': 'UNKNOWN',
                     'original_claims': record})
    require(bool(rows) and path.read_bytes() == raw, 'empty or changing telemetry source')
    return {'schema': 'gg-c07-original-telemetry-readback-v1',
            'source_sha256': sha(raw), 'records': rows,
            'productive_time_verified': False, 'provider_final_event_verified': False,
            'mg0': 'NOT_RUN', 'advancement_authorized': False}

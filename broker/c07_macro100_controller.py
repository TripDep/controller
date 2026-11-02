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
    packets = [a for a in artifacts if a[0] == 'C07_DOMAIN_OBSERVATIONS']
    require(len(packets) == 1, 'exactly one current registered domain-observation packet required')
    document = strict_json(packets[0][3])
    require(type(document) is dict and set(document) == {'schema', 'binding', 'observations'},
            'domain-observation packet schema')
    require(document['schema'] == 'gg-c07-controller-domain-observations-v1', 'domain-observation version')
    expected = {k: work[k] for k in ('attempt_id', 'operation_sha256', 'master_sha256')}
    expected.update(asset=asset, step=step)
    require(document['binding'] == expected, 'domain observations belong to different transaction')
    blobs = {digest: raw for _, _, digest, raw in artifacts}
    blobs[sha(master_raw)] = master_raw
    blobs[sha(state_raw)] = state_raw
    audit_raw = controller.audit_path(asset).read_bytes()
    require(sha(audit_raw) == audit_sha, 'audit changed during acquisition')
    blobs[audit_sha] = audit_raw
    require(controller.state_path.read_bytes() == state_raw and
            controller.master.read_bytes() == master_raw, 'Controller changed during acquisition')
    report = inspect_candidate(inventory, document['observations'], blobs)
    report['acquisition'] = {'binding': expected, 'audit_sha256': audit_sha,
                             'audit_tail': tail, 'state_sha256': sha(state_raw),
                             'observation_packet_sha256': packets[0][2],
                             'registered_artifact_count': len(artifacts),
                             'documentary_truth_authenticated': False}
    return report

"""C07 R122: first 200 *missing* native-positive obligations, exact-attempt readback.

This is an executable independent-evidence acquisition and full-clause gap
engine, NOT a replacement for an approved domain-specific semantic verifier.
No source/checksum/green CI/producer YES can grant a full-rule or MG0 PASS.
A missing reviewer, unsplit composite, or absent independent proof stays UNKNOWN.
"""
import hashlib
import json
import re
from pathlib import Path

from c07_operation_scope import inspect as operation_scope
from c07_compound_subchecks import inspect as composite_inspect
from approved_validators import REVIEWED
from c07_bulk200_semantics import SECTION_LANES
from c07_bulk_segment import FAMILY_CHANNELS, FALLBACK_CHANNELS
from c07_process_positive_batch import inspect as process_inspect
from real_work_intake import audit_check

SCHEMA = 'gg-c07-r122-positive200-source-bound-gaps-v1'
SHA = re.compile(r'[a-f0-9]{64}\Z')

class PositiveBatchBlocked(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise PositiveBatchBlocked(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode('utf-8'))


def select(inventory, plan):
    """Exactly the first 200 P0/DUE rules with no reviewed FULL verifier.

    The Controller recomputes applicability; the producer cannot choose 200
    convenient IDs. This is a new 200-missing window, not R115's first 200 IDs.
    """
    scope = operation_scope(inventory, plan)
    need(inventory.get('schema') == 'gg-effective-family-inventory-v1' and
         inventory.get('rule_count') == 763 and
         len(set(inventory.get('rules', {}))) == 763 and
         scope['master_sha256'] == inventory['canonical_master_sha256'],
         'R122_TRUSTED_FULL_CANON_REQUIRED')
    candidates = sorted(set(scope['due']) - set(REVIEWED))
    need(len(candidates) >= 200, 'R122_LESS_THAN_200_MISSING_RULES')
    selected = candidates[:200]
    for rid in selected:
        row = inventory['rules'][rid]
        need(type(row.get('requirement')) is str and row['requirement'].strip() and
             sha(row['requirement'].encode('utf-8')) == row['requirement_sha256'] and
             type(row.get('source_sha256')) is str and
             SHA.fullmatch(row['source_sha256']) is not None,
             'R122_REQUIREMENT_SOURCE_DRIFT:' + rid)
    return selected, scope


def _source_clauses(rid, rule, composite):
    if composite is not None:
        clauses = composite['subchecks']
        need(len(clauses) == len({c['subcheck_id'] for c in clauses}),
             'R122_DUPLICATE_CANONICAL_CLAUSE:' + rid)
        for c in clauses:
            need(sha(c['canonical_clause'].encode()) == c['clause_sha256'] and
                 c['provenance_requirement_sha256'] == rule['requirement_sha256'],
                 'R122_CHANGED_COMPOSITE_CLAUSE:' + rid)
        # The current decomposition is still unreviewed. It cannot be PASS.
        return clauses, composite['source_decomposition']
    if rid == '110_ERROR_REGISTRY':
        errors = re.findall(r'(?m)^(\d{3})[.]\s+(.+)$', rule['requirement'])
        need([int(n) for n, _ in errors] == list(range(1, 111)),
             'R122_REGRESSION_110_SOURCE_DECOMPOSITION_INCOMPLETE')
        return [{'subcheck_id': rid + ':SC' + n,
                 'canonical_clause': s, 'clause_sha256': sha(s.encode()),
                 'provenance_requirement_sha256': rule['requirement_sha256']}
                for n, s in errors], 'EXACT_110_SOURCE_ITEMS_NOT_YET_REVIEWED'
    return [{'subcheck_id': rid + ':SC001',
             'canonical_clause': rule['requirement'],
             'clause_sha256': rule['requirement_sha256'],
             'provenance_requirement_sha256': rule['requirement_sha256']}], 'SINGLE_SOURCE_OBLIGATION_REVIEW_PENDING'


def _lanes(rule):
    family = rule['family']
    if family == 'AAA-200':
        m = re.match(r'AAA-200-([A-T])-\d{3}\Z', rule['rule_id'])
        need(m is not None, 'R122_AAA_RULE_ID_INVALID')
        return SECTION_LANES[m.group(1)]
    return FAMILY_CHANNELS.get(family, FALLBACK_CHANNELS)


def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    """Scan original canonical, audit, dependencies, artifacts and clause gaps.

    Fail closed for changed/forged sources and cross-operation replays. Only
    original actual-file SHA observations are machine-positive, not rule PASS.
    For full PASS, independently implemented domain reviewers and real per-rule
    MG0 are still obligatory and deliberately NOT inferred or simulated here.
    """
    selected, scope = select(inventory, plan)
    need(type(asset) is str and asset == asset.upper() and bool(asset) and
         type(step) is str and bool(step) and type(work) is dict and
         work.get('master_sha256') == inventory['canonical_master_sha256'] and
         plan.get('master_sha256') == work['master_sha256'] and
         type(work.get('attempt_id')) is str and SHA.fullmatch(work['attempt_id']) and
         type(work.get('operation_sha256')) is str and SHA.fullmatch(work['operation_sha256']) and
         callable(source_loader), 'R122_EXACT_WORK_AND_READERS_REQUIRED')
    original_master = controller.master.read_bytes()
    need(sha(original_master) == work['master_sha256'],
         'R122_ORIGINAL_MASTER_CHANGED')
    audit_raw = controller.audit_path(asset).read_bytes()
    records, tail = audit_check(audit_raw, asset)
    state = controller.asset_state(asset)
    need(state.get('last_audit_hash') == tail, 'R122_AUDIT_STATE_CHANGED')
    opened = [e for e in records if e.get('event') == 'SUPERVISOR_OPERATION_OPENED'
              and e.get('step') == step]
    need(len(opened) == 1, 'R122_ONE_OPEN_OPERATION_REQUIRED')
    reserved = [e for e in records if e.get('event') == 'SUPERVISOR_OPERATION_RESERVED'
                and e.get('record_hash') == opened[0].get('reservation_hash')]
    need(len(reserved) == 1 and reserved[0].get('work') == work,
         'R122_CROSS_ATTEMPT_OR_OPERATION_REPLAY')
    plans = [e for e in records if e.get('event') == 'SUPERVISOR_PLAN_ENROLLED'
             and e.get('record_hash') == reserved[0].get('plan_record_hash')]
    need(len(plans) == 1 and plans[0].get('plan') == plan,
         'R122_NONCANONICAL_ENROLLED_PLAN')
    need((state.get('active_step') or {}).get('step') == step,
         'R122_ACTIVE_OPERATION_CHANGED')
    # R120 is the independent source-specific provider of 13 scoped machine
    # observations; it MUST stay unable to grant broader full-rule PASS.
    process = process_inspect(inventory, plan, controller, asset, step, work,
                              source_loader=source_loader)
    need(process['complete_work_rule_passes'] == 0 and
         process['individual_mg0_passes'] == 0 and
         process['advancement_authorized'] is False and
         len(process['results']) == 13, 'R122_PROCESS_OBSERVATION_PRIVILEGE_ESCALATION')
    composites = composite_inspect(inventory, selected)['due_composites']
    result = {}
    observed_count = 0
    all_missing = {}
    for rid in selected:
        source = inventory['rules'][rid]
        need(source['family'] == scope['by_rule'][rid]['family'] and
             source['source_sha256'] == scope['by_rule'][rid]['source_sha256'] and
             source['requirement_sha256'] == scope['by_rule'][rid]['requirement_sha256'],
             'R122_RULE_SCOPE_PROVENANCE_CHANGED:' + rid)
        clauses, completeness = _source_clauses(rid, source, composites.get(rid))
        # Machine positives are strictly bounded to what R120 measured.
        sub = process['results'].get(rid)
        machine = sub.get('scoped_positive_observation') if sub else None
        scope_positive = machine == 'OBSERVED_SCOPE_PASS'
        observed_count += int(scope_positive)
        missing = ['RULE_SPECIFIC_FULL_NATIVE_REVIEWED_VERIFIER',
                   'REAL_INDEPENDENT_CLAUSE_PROOFS_ON_SAME_ATTEMPT',
                   'INDIVIDUAL_RULE_MG0_FIVE_CANONICAL_CONDITIONS']
        if rid in composites or rid == '110_ERROR_REGISTRY':
            missing.append('INDEPENDENT_REVIEW_OF_EXHAUSTIVE_COMPOSITE_DECOMPOSITION')
        lanes = _lanes({**source, 'rule_id': rid})
        # No synthetic/user-made positive packets accepted as a source.
        result[rid] = {
            'rule_id': rid, 'source_sha256': source['source_sha256'],
            'requirement_sha256': source['requirement_sha256'],
            'canonical_clause_count': len(clauses),
            'clause_index_sha256': digest([(c['subcheck_id'], c['clause_sha256'])
                                          for c in clauses]),
            'source_decomposition': completeness,
            'required_independent_evidence_lanes': list(lanes),
            'machine_scoped_positive_observed': scope_positive,
            'machine_observation_is_not_full_semantics': True,
            'full_semantics': 'UNKNOWN', 'individual_mg0': 'UNKNOWN',
            'missing_evidence': missing, 'work_pass': False}
        all_missing[rid] = missing
    need(len(result) == 200 and len(set(result)) == 200 and
         set(result).isdisjoint(REVIEWED), 'R122_DUPLICATE_OR_OLD_REVIEWED_RULE')
    report = {'schema': SCHEMA, 'asset': asset, 'step': step,
              'attempt_id': work['attempt_id'],
              'operation_sha256': work['operation_sha256'],
              'master_sha256': work['master_sha256'],
              'source_rule_count': 200, 'source_rule_ids_sha256': digest(selected),
              'original_controller_audit_sha256': sha(audit_raw),
              'original_controller_audit_tail': tail,
              'original_master_sha256': sha(original_master),
              'r120_scoped_machine_positive_in_target': observed_count,
              'full_native_positive_verified_new': 0,
              'full_semantic_passes_on_current_attempt': 0,
              'individual_mg0_passes': 0, 'unknown_count': 200,
              'missing_evidence_by_rule': all_missing,
              'rules': result, 'advancement_authorized': False,
              'status': 'SOURCE_BOUND_NATIVE_POSITIVE_GAPS_UNKNOWN'}
    report['report_sha256'] = digest({k: v for k, v in report.items()
                                      if k != 'report_sha256'})
    return report
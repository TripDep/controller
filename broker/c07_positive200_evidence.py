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


# R128: the first real source-bound 200-rule batch is a FIXED cohort.
# Recomputing "first 200 missing" after a rule graduates silently replaces
# that graduated rule with an unrelated one. This makes a 200-rule batch
# impossible to finish incrementally. Keep the R122 verified IDs intact.
R122_FROZEN_SHA256='63f56366b9b4be5a491db3feccec99860110191474baf68aa6da7e86d226b355'
_R122_NONRANGE="110_ERROR_REGISTRY|A|AAA-200-A-001|AAA-200-A-002|AAA-200-A-003|AAA-200-A-004|AAA-200-A-005|AAA-200-A-006|AAA-200-A-007|AAA-200-A-010|AAA-200-C-021|AAA-200-C-022|AAA-200-C-023|AAA-200-C-024|AAA-200-C-025|AAA-200-C-026|AAA-200-C-027|AAA-200-C-028|AAA-200-C-029|AAA-200-C-030|AAA-200-R-171|AAA-200-R-172|AAA-200-R-173|AAA-200-R-174|AAA-200-R-175|AAA-200-R-176|AAA-200-R-177|AAA-200-R-178|AAA-200-R-179|AAA-200-R-180|ADVERSARIAL_QA|APPEND_ONLY_AUDIT|ARCHITECTURAL_QUALITY_FLOOR|ARCHITECTURE_1TO1|ASSISTANT_BEHAVIOR_PROTOCOL|AUTONOMOUS_PRE_PASS_QUESTION|B|BLOCK_ON_UNKNOWN|C|CG1|CG2|CG3|CG4|CROSS_PIECE_COHERENCE|D|D-METODO|D-RISULTATO|D-TEMPO|D0|DEFINITION_OF_DONE|DELIVERY_FIREWALL|DEPENDENCY_RECHECK|DEVELOPER_RULES_CANONICAL|E|EXPORT_REIMPORT|F|FIVEM_TARGET|FRESH_EYES|G0|G0-01|G0-02|G0-03|G0-04|G0-05|G0-06"
R122_FROZEN_IDS=tuple(sorted(set(_R122_NONRANGE.split('|')) |
    {'BEHAVIOR-'+str(i).zfill(3) for i in range(1,111)} |
    {'EXEC-'+str(i).zfill(3) for i in range(1,26)}))

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
    # Original R122 units use non-operational synthetic inventories.
    # Real canonical inventory ALWAYS retains the immutable original cohort
    # even as approved_validators.REVIEWED grows from 12 to 13, 14, ... .
    real_canon = ('110_ERROR_REGISTRY' in inventory['rules'] and
                  'BEHAVIOR-110' in inventory['rules'] and
                  inventory.get('source_digests', {}).get('aaa_catalog') ==
                  'f9e7e0d11398c26095f5b3a83a2cf1e8a14ea459bc47dc09c4dfad891664fcf9')
    if real_canon:
        selected = list(R122_FROZEN_IDS)
        need(len(selected)==200 and digest(selected)==R122_FROZEN_SHA256,
             'R128_FROZEN_COHORT_DIGEST_CHANGED')
        need(set(selected)<=set(scope['due']),
             'R128_COHORT_NOT_ALL_DUE_IN_CURRENT_OPERATION')
    else:
        # Legacy synthetic test fixture only; never a source-authorized
        # production cohort. Such inventories cannot provide the pinned
        # canonical catalog SHA or original 110-regression source.
        need('source_digests' not in inventory or
             inventory.get('source_digests', {}).get('aaa_catalog') is None,
             'R128_UNRECOGNIZED_CANONICAL_INVENTORY')
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
    real_canon = (set(selected) == set(R122_FROZEN_IDS) and
        inventory.get('source_digests', {}).get('aaa_catalog') ==
        'f9e7e0d11398c26095f5b3a83a2cf1e8a14ea459bc47dc09c4dfad891664fcf9')
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
        missing = ['REAL_INDEPENDENT_CLAUSE_PROOFS_ON_SAME_ATTEMPT',
                   'INDIVIDUAL_RULE_MG0_FIVE_CANONICAL_CONDITIONS']
        if rid not in REVIEWED:
            missing.insert(0, 'RULE_SPECIFIC_FULL_NATIVE_REVIEWED_VERIFIER')
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
         (not real_canon or set(result) == set(R122_FROZEN_IDS)),
         'R128_COHORT_IDS_CHANGED_OR_INCOMPLETE')
    report = {'schema': SCHEMA, 'asset': asset, 'step': step,
              'attempt_id': work['attempt_id'],
              'operation_sha256': work['operation_sha256'],
              'master_sha256': work['master_sha256'],
              'source_rule_count': 200, 'source_rule_ids_sha256': digest(selected),
              'frozen_first200_ids': bool(real_canon),
              'cohort_reviewed_implementations': sum(r in REVIEWED for r in selected),
              'cohort_missing_reviewed_implementations': sum(r not in REVIEWED for r in selected),
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

def reconcile_current200(inventory, plan, controller, asset, step, work,
                         *, r120, r123, r124, r122, r129=None, r130=None, r136=None, r138=None, r139=None):
    """R127: original-audit convergence of 200 per-rule observations and MG0.

    The four inputs MUST be direct immutable in-memory results produced by the
    Controller's own inspectors in one locked close. Cross-attempt replay,
    changed audit bytes, changed source results, missing IDs and false PASS
    cannot create work authorization. Actual positive full-rule and MG0
    credentials are NOT inferred from hash identities or synthetic CI.
    """
    from c07_mg0_individual import inspect_batch as inspect_mg0

    selected, scope = select(inventory, plan)
    if r129 is not None:
        from c07_exec25_native_observation import IDS as EXEC25_IDS, SCHEMA as EXEC25_SCHEMA
        need(type(r129) is dict
             and r129.get('schema') == EXEC25_SCHEMA
             and r129.get('source_rule_count') == 25
             and set(r129.get('rules',{})) == set(EXEC25_IDS)
             and set(EXEC25_IDS) <= set(selected)
             and all(r129.get(k) == work[k] for k in
                     ('master_sha256','attempt_id','operation_sha256'))
             and r129.get('full_rule_passes') == 0
             and r129.get('individual_mg0_passes') == 0
             and r129.get('advancement_authorized') is False
             and all(v.get('full_rule_pass') is False
                     and v.get('individual_mg0') == 'UNKNOWN'
                     and v.get('full_rule_semantics') == 'UNKNOWN'
                     for v in r129['rules'].values()),
             'R129_FULL_RULE_OR_MG0_FALSE_CERTIFICATION')
    if r138 is not None:
        from c07_exec25_domain_machine_probes import SCHEMA as R138_SCHEMA
        from c07_exec25_native_observation import IDS as EXEC25_IDS
        need(r129 is not None and type(r138) is dict
             and r138.get('schema')==R138_SCHEMA
             and r138.get('source_rule_count')==25
             and r138.get('domain_probes')==50
             and set(r138.get('rules',{}))==set(EXEC25_IDS)
             and all(r138.get(k)==work[k] for k in
                     ('master_sha256','attempt_id','operation_sha256'))
             and r138.get('full_native_semantics_passes')==0
             and r138.get('individual_mg0_passes')==0
             and r138.get('advancement_authorized') is False,
             'R138_UNTRUSTED_EXEC_DOMAIN_OR_FALSE_MG0')
    if r139 is not None:
        from c07_native_output_oracle import SCHEMA as R139_SCHEMA
        expected_ids={'AAA-200-R-176','AAA-200-R-180'}
        need(type(r139) is dict and
             r139.get('schema')==R139_SCHEMA and
             r139.get('source_rules_examined')==2 and
             set(r139.get('rules',{}))==expected_ids and
             expected_ids<=set(selected) and
             all(r139.get(k)==work[k] for k in
                 ('master_sha256','attempt_id','operation_sha256')) and
             r139.get('full_work_rule_passes')==0 and
             r139.get('individual_mg0_passes')==0 and
             r139.get('advancement_authorized') is False,
             'R139_INVALID_NATIVE_OUTPUT_OR_MG0_CLAIM')
    if r130 is not None:
        from c07_behavior110_remediation import IDS as BEHAVIOR110_IDS
        need(type(r130) is dict
             and r130.get('schema')=='gg-c07-r130-original-110-remediation-evidence-v1'
             and r130.get('source_rules_examined')==110
             and set(r130.get('rules',{}))==set(BEHAVIOR110_IDS)
             and set(BEHAVIOR110_IDS)<=set(selected)
             and all(r130.get(k)==work[k] for k in
                 ('master_sha256','attempt_id','operation_sha256'))
             and r130.get('rule_count_with_semantic_PASS')==0
             and r130.get('individual_mg0_PASS')==0
             and r130.get('advancement_authorized') is False
             and r130.get('result') in ('FAIL','UNKNOWN'),
             'R131_ORIGINAL_BEHAVIOR_110_FALSE_PASS_OR_ATTEMPT_REPLAY')
    if r136 is not None:
        need(type(r136) is dict and
             r136.get('schema')=='gg-c07-native-2-exact-process-semantics-v1' and
             r136.get('source_rule_count')==2 and
             set(r136.get('rules',{}))=={'AAA-200-R-172','AAA-200-R-178'} and
             {'AAA-200-R-172','AAA-200-R-178'}<=set(selected) and
             all(r136.get(k)==work[k] for k in
                 ('master_sha256','attempt_id','operation_sha256')) and
             r136.get('literal_process_semantics_passes')==
                  sum(row.get('literal_process_semantics')=='PASS'
                      for row in r136['rules'].values()) and
             r136.get('full_work_rule_passes')==0 and
             r136.get('individual_mg0_passes')==0 and
             r136.get('advancement_authorized') is False,
             'R136_FALSE_NATIVE_PROCESS_RULE_OR_CROSS_ATTEMPT')
    need(len(selected) == 200 and len(set(selected)) == 200,
         'R127_MISSING_EXACT_SOURCE200')
    need(type(work) is dict and work.get('master_sha256') ==
         inventory['canonical_master_sha256'] and
         plan.get('master_sha256') == work['master_sha256'] and
         type(asset) is str and asset and asset == asset.upper() and
         type(step) is str and step, 'R127_SOURCE_WORK_INVALID')
    for name, data in [('R123',r123),('R124',r124)]:
        need(type(data) is dict and
             all(data.get(k) == work[k] for k in
                 ('master_sha256','attempt_id','operation_sha256')) and
             data.get('individual_mg0_passes') == 0 and
             data.get('advancement_authorized') is False,
             'R127_'+name+'_EXACT_ATTEMPT_OR_FALSE_PASS')
    need(type(r120) is dict and r120.get('master_sha256') ==
         work['master_sha256'] and r120.get('attempt_id') ==
         work['attempt_id'] and r120.get('operation_sha256') ==
         work['operation_sha256'] and r120.get('individual_mg0_passes') == 0 and
         r120.get('complete_work_rule_passes') == 0 and
         r120.get('advancement_authorized') is False,
         'R127_R120_EXACT_ATTEMPT_OR_FALSE_PASS')
    need(type(r122) is dict and
         r122.get('schema') == SCHEMA and
         r122.get('asset') == asset and r122.get('step') == step and
         all(r122.get(k) == work[k] for k in
             ('master_sha256','attempt_id','operation_sha256')) and
         r122.get('source_rule_count') == 200 and
         r122.get('source_rule_ids_sha256') == digest(selected) and
         r122.get('unknown_count') == 200 and
         r122.get('full_native_positive_verified_new') == 0 and
         r122.get('individual_mg0_passes') == 0 and
         r122.get('advancement_authorized') is False and
         set(r122.get('rules',{})) == set(selected) and
         r122.get('report_sha256') == digest(
             {k:v for k,v in r122.items() if k != 'report_sha256'}),
         'R127_R122_SOURCE_REPORT_MISSING_OR_FORGED')
    expected120 = set((
        'AAA-200-A-004','AAA-200-A-005','AAA-200-B-011',
        'AAA-200-B-016','AAA-200-B-017','AAA-200-R-171',
        'AAA-200-R-172','AAA-200-R-175','AAA-200-R-176',
        'AAA-200-R-177','AAA-200-R-178','AAA-200-R-179',
        'AAA-200-R-180'))
    expected123 = {'AAA-200-R-172','AAA-200-R-178'}
    expected124 = {'AAA-200-R-'+str(n).zfill(3)
                   for n in (171,173,174,175,176,177,179,180)}
    need(set(r120.get('results',{})) == expected120 and
         set(r123.get('rules',{})) == expected123 and
         set(r124.get('rules',{})) == expected124 and
         r123.get('rule_count') == 2 and
         r124.get('source_rules_evaluated') == 8 and
         r123.get('full_work_rule_passes') == 0 and
         r124.get('full_current_attempt_rule_passes') == 0 and
         r124.get('full_native_semantic_certifications_new') == 0,
         'R127_REVIEWER_SOURCE_SET_INCOMPLETE')
    original = controller.audit_path(asset).read_bytes()
    rows, tail = audit_check(original, asset)
    master = controller.master.read_bytes()
    need(sha(master) == work['master_sha256'] and
         controller.asset_state(asset).get('last_audit_hash') == tail,
         'R127_CANONICAL_MASTER_OR_STATE_DRIFT')
    raw_lines = original.splitlines(keepends=True)
    need(len(raw_lines) == len(rows), 'R127_AUDIT_SERIALIZATION_CHANGED')
    pairs = [
        ('R120',r120.get('audit_tail'),None,
         'SUPERVISOR_C07_R120_POSITIVE_PROCESS_BATCH',
         'results',r120['results']),
        ('R123',r123.get('audit_tail_sha256'),r123.get('audit_sha256'),
         'SUPERVISOR_C07_R123_NATIVE_POSITIVE_PROCESS',
         'source_specific_semantic_observations',r123['rules']),
        ('R124',r124.get('real_controller_audit_tail'),
         r124.get('real_controller_audit_sha256'),
         'SUPERVISOR_C07_R124_EIGHT_POSITIVE_PROCESS_SCOPES',
         'exact_rule_source_evidence',r124['rules']),
        ('R122',r122.get('original_controller_audit_tail'),
         r122.get('original_controller_audit_sha256'),
         'SUPERVISOR_C07_R122_POSITIVE200_NATIVE_GAP_AUDIT',
         'report_sha256',r122['report_sha256']),
    ]
    if r129 is not None:
        pairs.insert(0, ('R129',r129.get('original_audit_tail'),
            r129.get('original_audit_sha256'),
            'SUPERVISOR_C07_R129_EXEC25_ORIGINAL_OBSERVATIONS',
            'exact_rule_source_observations',r129['rules']))
    if r138 is not None:
        pairs.insert(next(i for i,p in enumerate(pairs) if p[0]=='R129')+1,
          ('R138',r138.get('original_audit_tail'),
            r138.get('original_audit_sha256'),
            'SUPERVISOR_C07_R138_EXEC25_DOMAIN_MACHINE_PROBES',
            'exact_original_exec_rule_probes',r138['rules']))
    if r139 is not None:
        pairs.insert(next(i for i,p in enumerate(pairs) if p[0]=='R124')+1,
          ('R139',r139.get('original_audit_tail'),
            r139.get('original_audit_sha256'),
            'SUPERVISOR_C07_R139_ORIGINAL_BINARY_OUTPUT_EXPECTATION',
            'source_specific_expected_output_evidence',r139['rules']))
    if r130 is not None:
        pairs.insert(0,('R130',r130.get('original_audit_tail'),
            r130.get('original_audit_sha256'),
            'SUPERVISOR_C07_R130_BEHAVIOR110_REMEDIATION',
            'per_rule_verdicts',r130['rules']))
    if r136 is not None:
        pairs.insert(next(i for i,p in enumerate(pairs) if p[0]=='R123')+1,
          ('R136',r136.get('original_audit_tail'),
            r136.get('original_audit_sha256'),
            'SUPERVISOR_C07_R136_TWO_LITERAL_NATIVE_SEMANTICS',
            'exact_rule_proofs',r136['rules']))
    positions=[]
    for label,prior,exact_bytes_hash,event,field,expected in pairs:
        need(type(prior) is str and SHA.fullmatch(prior) is not None,
             'R127_'+label+'_AUDIT_TAIL_MISSING')
        indices=[i for i,r in enumerate(rows) if r['record_hash']==prior]
        need(len(indices)==1,'R127_'+label+'_AUDIT_SNAPSHOT_REPLAY')
        i=indices[0]
        positions.append(i)
        if exact_bytes_hash is not None:
            need(type(exact_bytes_hash) is str and SHA.fullmatch(exact_bytes_hash) is not None and
                 sha(b''.join(raw_lines[:i+1])) == exact_bytes_hash,
                 'R127_'+label+'_ORIGINAL_AUDIT_BYTES_CHANGED')
        need(i+1 < len(rows) and rows[i+1].get('event') == event and
             rows[i+1].get('attempt_id') == work['attempt_id'] and
             rows[i+1].get('operation_sha256') == work['operation_sha256'] and
             rows[i+1].get(field) == expected,
             'R127_'+label+'_RECEIPT_DIFFERENT_FROM_REAL_AUDIT')
    need(positions == sorted(set(positions)) and
         len(positions) == (4+int(r129 is not None)+int(r130 is not None)+int(r136 is not None)+int(r138 is not None)+int(r139 is not None)) and
         positions[-1] == len(rows)-2 and
         rows[-1]['record_hash']==tail,
         'R127_AUDIT_SNAPSHOT_ORDER_OR_FINAL_RECEIPT')
    mg0 = inspect_mg0(master,original,asset,work['master_sha256'],
                      selected,work['attempt_id'])
    need(mg0.get('rule_count')==200 and
         mg0.get('attempt_id')==work['attempt_id'] and
         mg0.get('audit_sha256')==sha(original) and
         mg0.get('audit_tail_sha256')==tail and
         set(mg0.get('rules',{}))==set(selected) and
         mg0.get('counts',{}).get('PASS')==0 and
         mg0.get('individual_mg0_passes')==0 and
         mg0.get('advancement_authorized') is False,
         'R127_MG0_ORIGINAL_INDIVIDUAL_READBACK_FALSE_PASS')
    details={};scoped_count=0;positive_subchecks=0;failures=[];behavior_failures=[];literal_process_semantics=0
    for rid in selected:
        canonical=inventory['rules'][rid]
        anchor=r122['rules'][rid]
        need(anchor.get('rule_id')==rid and
             anchor.get('requirement_sha256')==canonical['requirement_sha256'] and
             anchor.get('source_sha256')==canonical['source_sha256'] and
             anchor.get('full_semantics')=='UNKNOWN' and
             anchor.get('individual_mg0')=='UNKNOWN' and
             anchor.get('work_pass') is False,
             'R127_SOURCE_RULE_REPLACED_OR_FALSIFIED:'+rid)
        checks={}
        if rid in r120['results']:
            item=r120['results'][rid]
            observed=item.get('scope_criteria')
            need(item.get('rule_id')==rid and
                 item.get('source_sha256')==canonical['source_sha256'] and
                 item.get('requirement_sha256')==canonical['requirement_sha256'] and
                 type(observed) is dict and bool(observed) and
                 all(type(v) is bool for v in observed.values()) and
                 item.get('work_pass') is False and
                 item.get('individual_mg0') in ('UNKNOWN','NOT_DUE'),
                 'R127_R120_RULE_SOURCE_OR_FALSE_PASS:'+rid)
            checks['R120']=observed
        if rid in r123['rules']:
            item=r123['rules'][rid]
            observed=item.get('criteria')
            need(item.get('source_sha256')==canonical['source_sha256'] and
                 item.get('requirement_sha256')==canonical['requirement_sha256'] and
                 type(observed) is dict and bool(observed) and
                 all(type(v) is bool for v in observed.values()) and
                 item.get('individual_mg0')=='UNKNOWN' and
                 item.get('advancement_authorized') is False and
                 item.get('semantic_result') == (
                     'SEMANTIC_OBSERVED' if all(observed.values()) else 'UNKNOWN'),
                 'R127_R123_RULE_SOURCE_OR_FALSE_PASS:'+rid)
            checks['R123']=observed
        if rid in r124['rules']:
            item=r124['rules'][rid]
            observed=item.get('machine_checks')
            need(item.get('rule_id')==rid and
                 item.get('source_sha256')==canonical['source_sha256'] and
                 item.get('requirement_sha256')==canonical['requirement_sha256'] and
                 type(observed) is dict and bool(observed) and
                 all(type(v) is bool for v in observed.values()) and
                 item.get('positive_subpredicates') == sorted(
                     k for k,v in observed.items() if v) and
                 item.get('missing_subpredicates') == sorted(
                     k for k,v in observed.items() if not v) and
                 item.get('full_rule_semantics') == 'UNKNOWN' and
                 item.get('individual_mg0')=='UNKNOWN' and
                 item.get('advancement_authorized') is False,
                 'R127_R124_RULE_SOURCE_OR_FALSE_PASS:'+rid)
            checks['R124']=observed
        if r129 is not None and rid in r129['rules']:
            item=r129['rules'][rid]
            observed=item.get('scoped_machine_predicates')
            need(item.get('rule_id')==rid and
                 item.get('source_sha256')==canonical['source_sha256'] and
                 item.get('requirement_sha256')==canonical['requirement_sha256'] and
                 type(observed) is dict and len(observed)==2 and
                 all(type(v) is bool for v in observed.values()) and
                 item.get('actually_observed')==sorted(
                     k for k,v in observed.items() if v) and
                 item.get('missing_independent_semantics')==sorted(
                     k for k,v in observed.items() if not v) and
                 bool(item.get('missing_independent_semantics')) and
                 item.get('full_rule_pass') is False and
                 item.get('full_rule_semantics')=='UNKNOWN' and
                 item.get('individual_mg0')=='UNKNOWN' and
                 item.get('advancement_authorized') is False,
                 'R129_SOURCE_CLAUSE_OR_FALSE_NATIVE_PASS:'+rid)
            checks['R129']=observed
        witness=mg0['rules'][rid]
        behavioral=None
        if r130 is not None and rid in r130['rules']:
            behavioral=r130['rules'][rid]
            need(behavioral.get('rule_id')==rid and
                 behavioral.get('source_sha256')==canonical['source_sha256'] and
                 behavioral.get('requirement_sha256')==canonical['requirement_sha256'] and
                 behavioral.get('observed_failure_count')==
                    len(behavioral.get('observations',())) and
                 behavioral.get('semantic_result') in ('FAIL','UNKNOWN') and
                 behavioral.get('individual_mg0')==witness.get('verdict') and
                 behavioral.get('independent_prevention_effectiveness')=='UNKNOWN' and
                 behavioral.get('real_owner_identity')=='UNKNOWN' and
                 behavioral.get('new_full_rule_pass') is False and
                 behavioral.get('advancement_authorized') is False,
                 'R131_BEHAVIOR_RULE_SOURCE_MG0_OR_FALSE_PASS:'+rid)
            checks['R130']={
                'canonical_error_prevention_source_bound':True,
                'current_attempt_failure_linkage_inspected':True,
                'independently_verified_prevention_and_owner':False,
            }
            if behavioral['semantic_result']=='FAIL':behavior_failures.append(rid)
        individual_literal_semantics='NOT_IMPLEMENTED'
        if r136 is not None and rid in r136['rules']:
            item=r136['rules'][rid]
            individual_literal_semantics=item.get('literal_process_semantics')
            source_clause=canonical['requirement']
            native=r123['rules'][rid]
            observed=item.get('original_machine_criteria')
            extra=item.get('additional_full_literal_criteria')
            need(item.get('rule_id')==rid
                 and item.get('source_sha256')==canonical['source_sha256']
                 and item.get('requirement_sha256')==canonical['requirement_sha256']
                 and item.get('exact_literal_requirement')==source_clause
                 and observed==native['criteria']
                 and type(extra) is dict and bool(extra)
                 and all(type(v) is bool for v in extra.values())
                 and item.get('individual_mg0')=='UNKNOWN'
                 and item.get('full_work_rule_pass') is False
                 and item.get('owner_acceptance')=='UNKNOWN'
                 and item.get('advancement_authorized') is False
                 and individual_literal_semantics==(
                     'PASS' if all(observed.values()) and all(extra.values())
                     else 'UNKNOWN'),
                 'R136_SOURCE_SEMANTIC_OR_FALSE_POSITIVE:'+rid)
            literal_process_semantics+=int(individual_literal_semantics=='PASS')
            checks['R136_literal']=extra
        if r138 is not None and rid in r138['rules']:
            item=r138['rules'][rid]
            prev=r129['rules'][rid]
            observed=item.get('additional_domain_machine_criteria')
            need(item.get('rule_id')==rid
                 and item.get('source_sha256')==canonical['source_sha256']
                 and item.get('requirement_sha256')==canonical['requirement_sha256']
                 and item.get('original_scoped_machine_criteria')==
                     prev['scoped_machine_predicates']
                 and type(observed) is dict and len(observed)==2
                 and all(type(v) is bool for v in observed.values())
                 and item.get('observed')==sorted(k for k,v in observed.items() if v)
                 and item.get('not_verified')==sorted(k for k,v in observed.items() if not v)
                 and item.get('additional_oracle_digest')==digest({
                     'rule_id':rid,'source_sha256':canonical['source_sha256'],
                     'criteria':observed})
                 and item.get('whole_source_requirement')=='UNKNOWN'
                 and item.get('individual_mg0')=='UNKNOWN'
                 and item.get('owner_approval')=='UNKNOWN'
                 and item.get('advancement_authorized') is False,
                 'R138_UNTRUSTED_EXEC_NATIVE_PER_RULE:'+rid)
            checks['R138_EXEC_domain']=observed
        if r139 is not None and rid in r139['rules']:
            item=r139['rules'][rid]
            val=item.get('source_specific_output_conditions')
            need(item.get('rule_id')==rid and
                 item.get('requirement_sha256')==canonical['requirement_sha256']
                 and item.get('source_sha256')==canonical['source_sha256']
                 and item.get('native_r124_checks')==
                     r124['rules'][rid]['machine_checks']
                 and type(val) is dict and len(val)==4
                 and all(type(x) is bool for x in val.values())
                 and item.get('machine_semantics')==(
                     'OBSERVED_SCOPE_PASS' if all(val.values()) else 'UNKNOWN')
                 and item.get('individual_mg0')=='UNKNOWN'
                 and item.get('full_work_rule_pass') is False
                 and item.get('owner_acceptance')=='UNKNOWN'
                 and item.get('advancement_authorized') is False,
                 'R139_SOURCE_SPECIFIC_OUTPUT_PROOF_CHANGED:'+rid)
            checks['R139_exact_geometry_outcome']=val
        scoped_count += int(bool(checks))
        positive_subchecks += sum(sum(v is True for v in group.values())
                                  for group in checks.values())
        need(witness.get('verdict') in ('UNKNOWN','FAIL'),
             'R127_FALSIFIED_INDIVIDUAL_MG0:'+rid)
        if witness['verdict']=='FAIL':failures.append(rid)
        details[rid]={
          'rule_id':rid,'source_sha256':canonical['source_sha256'],
          'requirement_sha256':canonical['requirement_sha256'],
          'source_clause_count':anchor['canonical_clause_count'],
          'source_clause_index_sha256':anchor['clause_index_sha256'],
          'machine_scoped_checks':checks,
          'source_exact_literal_process_semantics':individual_literal_semantics,
          'behavior110_failure_observation':behavioral,
          'mg0_failure_observation':witness,
          'full_semantics':'UNKNOWN','individual_mg0':witness['verdict'],
          'combined_result':'FAIL' if witness['verdict']=='FAIL' or
                        (behavioral and behavioral['semantic_result']=='FAIL')
                        else 'UNKNOWN',
          'full_rule_pass':False,'work_authorized':False,
        }
    need(len(details)==200 and
         all(row['full_rule_pass'] is False for row in details.values()),
         'R127_MISSING_TWO_HUNDRED_OR_FAKE_PASS')
    result={
        'schema':'gg-c07-r127-unified200-current-attempt-v1',
        'asset':asset,'step':step,
        'master_sha256':work['master_sha256'],
        'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'original_audit_tail':tail,'original_audit_sha256':sha(original),
        'source_rules_examined':200,'source_rule_ids_sha256':digest(selected),
        'machine_scope_rule_count':scoped_count,
        'original_exec25_individual_evidence_converged':25 if r129 is not None else 0,
        'original_exec25_domain_evidence_converged':25 if r138 is not None else 0,
        'original_binary_output_rules_examined':2 if r139 is not None else 0,
        'original_binary_output_semantics_observed':(
            r139['new_output_semantics_observed'] if r139 is not None else 0),
        'original_behavior110_individual_evidence_converged':110 if r130 is not None else 0,
        'original_literal_process_rule_evidence_converged':2 if r136 is not None else 0,
        'native_literal_process_semantics_passes':literal_process_semantics,
        'observed_machine_subpredicates':positive_subchecks,
        'behavior110_failed_rule_ids':sorted(set(behavior_failures)),
        'mg0_failed_rule_ids':failures,'mg0_unknown_count':mg0['counts']['UNKNOWN'],
        'full_rule_passes':0,'individual_mg0_passes':0,
        'unknown_rule_count':200-len(set(failures)|set(behavior_failures)),
        'result':'FAIL' if failures or behavior_failures else 'UNKNOWN',
        'rules':details,'advancement_authorized':False,
    }
    result['report_sha256']=digest(result)
    return result

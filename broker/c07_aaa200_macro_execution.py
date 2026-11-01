"""C07: execute whole A-T AAA-200 phase macros on original Controller bytes.

Twenty ten-rule families are visited in coherent P0-P8 macro blocks, not
promoted by individual micro-observations. Only explicitly code-reviewed
native replayers may produce a source-only PASS; unreviewed remain UNKNOWN.
No signed producer report, CI fixture, source pin or family count grants
independent MG0, owner acceptance, FiveM or advancement authorization.
"""
from c07_cohort_completion_gate import catalog200_macro_snapshot
from c07_native_source_rule_replayers import (
    FULL_LITERAL_REVIEWED, NATIVE_RULES, VALIDATORS, build_packet)
from supervisor_judgment import binding, semantic_packet

PHASE_INDEX = {'P'+str(i):i for i in range(9)}
CONTEXT_KEYS = frozenset((
    'inventory', 'plan', 'controller', 'asset', 'step', 'work', 'source_loader'
))


class WholeMacroBlocked(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise WholeMacroBlocked(message)


def summarize(rows):
    statuses = {r['source_result'] for r in rows}
    if 'FAIL' in statuses:
        return 'FAIL'
    if 'BLOCKED' in statuses:
        return 'BLOCKED'
    if 'UNKNOWN' in statuses:
        return 'UNKNOWN'
    if statuses == {'NOT_DUE'}:
        return 'NOT_DUE'
    return 'SOURCE_REPLAY_ONLY'


def inspect(context):
    """Run every DUE registered rule, keep all others explicitly UNKNOWN.

    This reader has no discretionary rule selection and cannot silently
    replace a member of the immutable A-T catalog after new code enrolls.
    """
    need(type(context) is dict and set(context) == CONTEXT_KEYS and
         type(context.get('inventory')) is dict and
         type(context.get('plan')) is dict and
         type(context.get('work')) is dict and
         type(context.get('asset')) is str and context['asset'] and
         type(context.get('step')) is str and context['step'] and
         callable(context.get('source_loader')),
         'C07_AAA200_MACRO_TRUSTED_CONTROLLER_CONTEXT_REQUIRED')
    plan, work = context['plan'], context['work']
    stage = plan.get('phase')
    need(stage in PHASE_INDEX and work.get('phase') == stage and
         type(work.get('attempt_id')) is str and
         type(work.get('operation_sha256')) is str and
         type(work.get('master_sha256')) is str,
         'C07_AAA200_MACRO_PHASE_OR_OPERATION_MISMATCH')
    registry = catalog200_macro_snapshot(context['inventory'])
    need(registry['canonical_rule_count'] == 200 and
         registry['family_count'] == 20 and
         registry['advancement_authorized'] is False,
         'C07_AAA200_MACRO_CATALOG_CODE_REGISTRY_DRIFT')
    rows = {}
    macros = []
    replay_attempted = replay_completed = 0
    for group in registry['macros']:
        family_reports = []
        for family in group['families']:
            family_rows = []
            for rid in (
                    'AAA-200-' + family['family'] + '-' + str(n).zfill(3)
                    for n in range(
                        (ord(family['family']) - 65) * 10 + 1,
                        (ord(family['family']) - 65) * 10 + 11)):
                due = PHASE_INDEX[group['phase']] <= PHASE_INDEX[stage]
                row = {
                    'source_result':'NOT_DUE' if not due else 'UNKNOWN',
                    'code_reviewed': rid not in family['missing_ids'],
                    'independent_mg0':'NOT_DUE' if not due else 'UNKNOWN',
                    'full_semantic_asset_verdict':'UNKNOWN',
                    'source_checks':{}, 'blocked_reason':None,
                    'advancement_authorized':False,
                }
                if due and row['code_reviewed']:
                    replay_attempted += 1
                    try:
                        expected = binding(
                            work, context['inventory']['rules'][rid], rid)
                        packet = build_packet(context, rid, expected=expected)
                    except (ValueError, TypeError, KeyError, IndexError,
                            AssertionError, OSError) as exc:
                        row['source_result'] = 'BLOCKED'
                        row['blocked_reason'] = (
                            type(exc).__name__ + ':' + str(exc)[:200])
                    else:
                        # Reuse the canonical strict packet validator, not
                        # just a few convenient producer fields.
                        semantic_packet(packet, expected, {
                            'validator_id': VALIDATORS[rid],
                            'criteria': NATIVE_RULES[rid][1],
                        })
                        requirement = packet.get('rule', {})
                        mg0 = packet.get('mg0', {})
                        checks = requirement.get('checks')
                        need(packet.get('binding') == expected and
                             type(requirement) is dict and
                             type(mg0) is dict and
                             type(checks) is dict and
                             set(checks) == set(NATIVE_RULES[rid][1]) and
                             all(type(v) is bool for v in checks.values()) and
                             requirement.get('result') in
                                 ('PASS','FAIL','UNKNOWN') and
                             mg0.get('result') in
                                 ('PASS','FAIL','UNKNOWN') and
                             rid in FULL_LITERAL_REVIEWED and
                             not (requirement['result'] == 'PASS' and
                                  not all(checks.values())) and
                             not (mg0['result'] == 'PASS' and
                                  requirement['result'] != 'PASS'),
                             'C07_AAA200_MACRO_REPLAYER_FALSE_POSITIVE:' + rid)
                        replay_completed += 1
                        row.update(source_result=requirement['result'],
                                   source_checks=dict(checks),
                                   independent_mg0=mg0['result'])
                rows[rid] = row
                family_rows.append(row)
            need(len(family_rows) == 10,
                 'C07_AAA200_MACRO_FAMILY_NOT_COMPLETE:' + family['family'])
            family_reports.append({
                'family':family['family'], 'rule_count':10,
                'code_reviewed':family['reviewed_native_code'],
                'source_result':summarize(family_rows),
                'source_replays_completed':sum(r['source_result'] in
                    ('PASS','FAIL','UNKNOWN') and r['code_reviewed']
                    for r in family_rows if r['source_checks']),
                'advancement_authorized':False,
            })
        macros.append({
            'phase':group['phase'],
            'family_count':len(family_reports),
            'rule_count':sum(f['rule_count'] for f in family_reports),
            'families':family_reports,
            'source_result':summarize(
                [rows['AAA-200-'+f['family']+'-'+str(n).zfill(3)]
                 for f in family_reports
                 for n in range((ord(f['family'])-65)*10+1,
                                (ord(f['family'])-65)*10+11)]),
            'independent_mg0':'UNVERIFIED',
            'advancement_authorized':False,
        })
    need(len(rows)==200 and len(macros)==registry['phase_macro_count'] and
         replay_completed<=replay_attempted<=registry['native_code_reviewed'],
         'C07_AAA200_MACRO_200_SOURCE_COVERAGE_DRIFT')
    return {
        'schema':'c07-aaa200-whole-phase-macro-original-replay-v1',
        'canonical_rule_count':200,'family_count':20,
        'macro_count':len(macros),'phase':stage,
        'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'native_code_reviewed':registry['native_code_reviewed'],
        'native_code_missing':registry['missing_native_code'],
        'source_replays_attempted':replay_attempted,
        'source_replays_completed':replay_completed,
        'macros':macros,'rows':rows,
        'independent_mg0':'UNVERIFIED',
        'owner_acceptance':'UNVERIFIED','fivem_runtime':'UNVERIFIED',
        'advancement_authorized':False,'c07_finished':False,
    }

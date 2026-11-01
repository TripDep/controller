"""P6/P7/P8 seven-ID residual family: original-byte source-specific replay.

P155/P160/S190 use independent collision and final-QA readers. Q167-Q170
already have original RAGE/Sollumz source replayers. None of these seven can
be FULL without real independent gameplay/tool/owner evidence. Never convert
a registered producer log, QA claim or fixture into that attestation.
"""
import hashlib
from c07_p6_walkability_semantics import inspect as walk_inspect
from c07_p8_final_qa_semantics import inspect as final_inspect
from c07_native_source_rule_replayers import P678_RESIDUAL_CANDIDATES

IDS = ('AAA-200-P-155', 'AAA-200-P-160', 'AAA-200-Q-167',
       'AAA-200-Q-168', 'AAA-200-Q-169', 'AAA-200-Q-170',
       'AAA-200-S-190')
SOURCE_CANDIDATES = frozenset(P678_RESIDUAL_CANDIDATES)

class ResidualP678Blocked(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise ResidualP678Blocked(reason)

def inspect(ctx, rule_id):
    need(type(ctx) is dict and
         set(ctx) == {'inventory', 'plan', 'controller', 'asset', 'step',
                      'work', 'source_loader'} and
         rule_id in SOURCE_CANDIDATES and callable(ctx.get('source_loader')),
         'C07_P678_RESIDUAL_TRUSTED_SOURCE_CONTEXT')
    inv, plan, controller, asset, step, work, loader = (
        ctx[k] for k in ('inventory', 'plan', 'controller', 'asset',
                         'step', 'work', 'source_loader'))
    need(plan.get('phase') == work.get('phase') and
         inv.get('canonical_master_sha256') == work.get('master_sha256'),
         'C07_P678_RESIDUAL_CURRENT_MASTER_OPERATION')
    reader = walk_inspect if rule_id.startswith('AAA-200-P-') else final_inspect
    report = reader(inv, plan, controller, asset, step, work,
                    source_loader=loader)
    need(type(report) is dict and
         report.get('source_rule_count') == (6 if reader is walk_inspect else 10)
         and report.get('attempt_id') == work['attempt_id'] and
         report.get('operation_sha256') == work['operation_sha256'] and
         report.get('advancement_authorized') is False and
         report.get('full_rule_semantic_passes') == 0 and
         report.get('individual_mg0_passes') == 0,
         'C07_P678_RESIDUAL_ORIGINAL_REPORT_BINDING')
    source = report.get('rules', {}).get(rule_id)
    row = inv['rules'][rule_id]
    need(type(source) is dict and
         source.get('requirement_sha256') == row['requirement_sha256'] and
         source.get('source_sha256') == row['source_sha256'] and
         source.get('exact_attempt_id') == work['attempt_id'] and
         source.get('operation_sha256') == work['operation_sha256'] and
         source.get('full_rule_semantics') == 'UNKNOWN' and
         source.get('individual_mg0') == 'UNKNOWN' and
         source.get('advancement_authorized') is False,
         'C07_P678_RESIDUAL_RULE_LITERAL_OR_ATTEMPT')
    primary = source.get('original_machine_checks')
    cross = source.get('original_cross_source_semantic')
    need(type(primary) is dict and len(primary) == 2 and
         type(cross) is dict and len(cross) == 1 and
         all(type(k) is str and type(v) is bool for k,v in
             list(primary.items()) + list(cross.items())) and
         not set(primary).intersection(cross),
         'C07_P678_RESIDUAL_DISTINCT_ORIGINAL_PREDICATES')
    checks = {**primary, **cross}
    need(set(checks) == set(P678_RESIDUAL_CANDIDATES[rule_id][1]) and
         hashlib.sha256(controller.audit_path(asset).read_bytes()).hexdigest()
            == report['original_audit_sha256'],
         'C07_P678_RESIDUAL_ORIGINAL_SHA_OR_CRITERIA_DRIFT')
    return {
        'rule_id': rule_id, 'checks': checks,
        'evidence_complete': False,
        'full_rule_semantics': 'UNKNOWN',
        'individual_mg0': 'UNKNOWN',
        'fivem_runtime': 'UNKNOWN',
        'owner_acceptance': 'UNKNOWN',
        'original_audit_sha256': report['original_audit_sha256'],
        'original_audit_tail': report['original_audit_tail'],
        'attempt_id': work['attempt_id'],
        'operation_sha256': work['operation_sha256'],
        'advancement_authorized': False,
    }

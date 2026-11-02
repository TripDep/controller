"""P1 D031-D040: ten literal-bound original-source replay candidates.

Three independent readers reopen the same Controller attempt and SHA-pinned
original native geometry and pixels. The 8 per-rule predicates are real source
measurements, not proof of artistic quality, renderer provenance or owner
approval. These candidates MUST NOT enter REVIEWED/dispatch without full proof.
"""
import hashlib

from c07_p1_design_source_review import inspect as design_inspect
from c07_p1_remaining_visual_review import inspect_family as quantitative_inspect
from c07_p1_native_raster_projection import inspect_family as raster_inspect
from c07_native_source_rule_replayers import P1_RESIDUAL_CANDIDATES

IDS = tuple('AAA-200-D-%03d' % n for n in range(31, 41))

class ResidualSourceBlocked(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise ResidualSourceBlocked(reason)

def inspect(ctx, rule_id):
    need(type(ctx) is dict and
         set(ctx) == {'inventory', 'plan', 'controller', 'asset', 'step',
                      'work', 'source_loader'} and rule_id in IDS and
         callable(ctx.get('source_loader')),
         'C07_P1_RESIDUAL_TRUSTED_CONTEXT_AND_LITERAL')
    inv, plan, controller, asset, step, work, loader = (
        ctx[k] for k in ('inventory', 'plan', 'controller', 'asset',
                         'step', 'work', 'source_loader'))
    need(plan.get('phase') == work.get('phase') and
         inv.get('canonical_master_sha256') == work.get('master_sha256'),
         'C07_P1_RESIDUAL_CURRENT_MASTER_OPERATION')
    design = design_inspect(inv, plan, controller, asset, step, work,
                            source_loader=loader)
    quantitative = quantitative_inspect(ctx)
    raster = raster_inspect(ctx)
    audit_sha = hashlib.sha256(controller.audit_path(asset).read_bytes()).hexdigest()
    expected = {
        'attempt_id': work['attempt_id'],
        'operation_sha256': work['operation_sha256'],
        'original_audit_sha256': audit_sha,
    }
    original = inv['rules'][rule_id]
    measured = {}
    for label, report, field, count in (
            ('DESIGN', design, 'original_pixel_geometry_checks', 13),
            ('QUANTITATIVE', quantitative, 'checks', 13),
            ('RASTER', raster, 'checks', 11)):
        need(type(report) is dict and report.get('rule_count') == count and
             all(report.get(k) == v for k, v in expected.items()) and
             report.get('advancement_authorized') is False and
             report.get('full_semantic_passes') == 0 and
             report.get('individual_mg0_passes') == 0,
             'C07_P1_RESIDUAL_SOURCE_REPORT_DRIFT:' + label)
        row = report.get('rules', {}).get(rule_id)
        need(type(row) is dict and
             row.get('requirement_sha256') == original['requirement_sha256'] and
             row.get('source_sha256') == original['source_sha256'] and
             row.get('full_rule_semantics') == 'UNKNOWN' and
             row.get('individual_mg0') == 'UNKNOWN' and
             row.get('advancement_authorized') is False,
             'C07_P1_RESIDUAL_LITERAL_BINDING_DRIFT:' + label)
        checks = row.get(field)
        need(type(checks) is dict and len(checks) == (3 if label != 'QUANTITATIVE' else 2) and
             all(type(k) is str and type(v) is bool for k, v in checks.items()) and
             not (set(measured) & set(checks)),
             'C07_P1_RESIDUAL_ORIGINAL_CHECK_COLLISION:' + label)
        measured.update(checks)
    need(set(measured) == set(P1_RESIDUAL_CANDIDATES[rule_id][1]) and
         len(measured) == 8 and
         len({report['original_audit_tail']
              for report in (design, quantitative, raster)}) == 1 and
         hashlib.sha256(controller.audit_path(asset).read_bytes()).hexdigest() == audit_sha,
         'C07_P1_RESIDUAL_EIGHT_ORIGINAL_SOURCE_REPLAY_MISMATCH')
    return {
        'rule_id': rule_id,
        'checks': measured,
        'evidence_complete': False,
        'full_rule_semantics': 'UNKNOWN',
        'individual_mg0': 'UNKNOWN',
        'artistic_acceptance': 'UNKNOWN',
        'renderer_provenance': 'UNKNOWN',
        'original_audit_sha256': audit_sha,
        'original_audit_tail': design['original_audit_tail'],
        'attempt_id': work['attempt_id'],
        'operation_sha256': work['operation_sha256'],
        'advancement_authorized': False,
    }

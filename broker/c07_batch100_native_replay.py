"""C07 exact 100-rule native evidence replay, NOT a 100-rule PASS shortcut.

The cohort is 30 P1, 40 P3-P5 and 30 P6-P8 *asset-agnostic*
canonical AAA-200 rules. Every source predicate is recomputed by its existing
original-byte reader, then compared to the same exact Controller attempt and
operation-bound individual MG0 audit. No signed producer verdict is trusted.

This is the consuming-side machine-evidence layer only. It does not turn a
partial predicate, synthetic test, missing independent full-literal review,
unknown MG0 or owner acceptance into REVIEWED or an operational PASS.
"""
import hashlib
import json
import re

import c07_p1_thirty_native_domain as p1
import c07_p345_forty_native_evidence as p345
import c07_p678_forty_native_domain as p678
import c07_mg0_individual as mg0

COHORT = tuple(p1.IDS) + tuple(p345.IDS) + tuple(p678.IDS[:30])
HEX64 = re.compile(r'[a-f0-9]{64}\Z')
FIELDS = (
    ('P1', 'original_native_measured_criteria', 3),
    ('P345', 'machine_observations', 2),
    ('P678', 'native_original_machine_evidence', 2),
)

class NativeBatchBlocked(ValueError):
    pass

def need(value, code):
    if not value:
        raise NativeBatchBlocked(code)

def digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(',', ':'),
        allow_nan=False).encode('utf-8')).hexdigest()

def _verify_p1_residual_source_macros(design, quantitative, raster,
                                       inventory, work, audit):
    """Consume ALL eleven residual P1 literals from three original readers.

    A synthetic positive in one reader never substitutes for an independent
    pixel/geometry predicate from another. Each result must be tied to the
    same original audit, attempt, operation, canonical source and literal.
    This checks source evidence only; no aesthetic, MG0 or owner PASS.
    """
    from c07_p1_design_source_review import IDS as DESIGN_IDS
    from c07_p1_remaining_visual_review import IDS as QUANT_IDS
    from c07_p1_native_raster_projection import IDS as RASTER_IDS
    need(len(DESIGN_IDS)==len(QUANT_IDS)==13 and
         len(RASTER_IDS)==11 and set(DESIGN_IDS)==set(QUANT_IDS) and
         set(RASTER_IDS)<set(DESIGN_IDS) and
         len(set(RASTER_IDS))==11,
         'C07_BATCH100_P1_RESIDUAL_FROZEN_LITERAL_SET_DRIFT')
    expected={
        'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'original_audit_sha256':audit['audit_sha256'],
        'original_audit_tail':audit['audit_tail_sha256'],
    }
    for label,report,ids in (
        ('DESIGN',design,DESIGN_IDS),
        ('QUANTITATIVE',quantitative,QUANT_IDS),
        ('RASTER',raster,RASTER_IDS),
    ):
        need(type(report) is dict and
             report.get('family_rule_count')==30 and
             report.get('rule_count')==len(ids) and
             set(report.get('rules',{}))==set(ids) and
             all(report.get(k)==v for k,v in expected.items()) and
             report.get('advancement_authorized') is False and
             report.get('full_semantic_passes')==0 and
             report.get('individual_mg0_passes')==0,
             'C07_BATCH100_P1_RESIDUAL_ORIGINAL_FAMILY_CONTEXT:'+label)
        observed=0
        for rid in ids:
            row=report['rules'][rid]
            checks=(row.get('original_pixel_geometry_checks') if label=='DESIGN'
                    else row.get('checks'))
            required=3 if label!='QUANTITATIVE' else 2
            need(type(row) is dict and type(checks) is dict and
                 len(checks)==required and
                 all(type(name) is str and bool(name) and type(value) is bool
                     for name,value in checks.items()) and
                 row.get('source_sha256')==
                     inventory['rules'][rid]['source_sha256'] and
                 row.get('requirement_sha256')==
                     inventory['rules'][rid]['requirement_sha256'] and
                 row.get('full_rule_semantics')=='UNKNOWN' and
                 row.get('individual_mg0')=='UNKNOWN' and
                 row.get('advancement_authorized') is False and
                 row.get('source_observed') is all(checks.values()),
                 'C07_BATCH100_P1_RESIDUAL_PER_LITERAL_ORIGINAL_PROOF:'+
                 label+':'+rid)
            observed+=row['source_observed']
        if label=='DESIGN':
            need(report.get('source_observed_count')==observed,
                 'C07_BATCH100_P1_RESIDUAL_DESIGN_POSITIVE_COUNT_FORGED')
    for rid in RASTER_IDS:
        checks=(
            design['rules'][rid]['original_pixel_geometry_checks'],
            quantitative['rules'][rid]['checks'],
            raster['rules'][rid]['checks'],
        )
        names=[name for group in checks for name in group]
        need(len(names)==8 and len(set(names))==8 and
             all(type(value) is bool
                 for group in checks for value in group.values()),
             'C07_BATCH100_P1_RESIDUAL_EIGHT_INDEPENDENT_CHECKS:'+rid)
    return {'residual_rules_replayed':11,'original_measured_checks':88,
            'full_semantics_verified':False,'individual_mg0_verified':False,
            'advancement_authorized':False}


def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    """Replay 100 exact original-source predicates on one P8+ operation.

    No source bytes are uploaded to Git; the loader must independently reopen
    the registered originals in the governed Controller environment.
    """
    need(len(COHORT) == 100 and len(set(COHORT)) == 100 and
         len(p1.IDS) == 30 and len(p345.IDS) == 40 and len(p678.IDS) == 40,
         'C07_BATCH100_FROZEN_SOURCE_COHORT_CHANGED')
    need(type(inventory) is dict and inventory.get('rule_count') == 763 and
         type(inventory.get('rules')) is dict and
         type(plan) is dict and type(work) is dict and
         plan.get('phase') == work.get('phase') and
         plan['phase'] in p678.PHASES and
         p678.PHASES[plan['phase']] >= 8 and
         plan.get('asset_type') == work.get('asset_type') and
         plan.get('master_sha256') == work.get('master_sha256') and
         type(asset) is str and asset and asset == asset.upper() and
         type(step) is str and bool(step) and callable(source_loader),
         'C07_BATCH100_TRUSTED_CURRENT_P8_OPERATION_REQUIRED')
    for key in ('master_sha256', 'attempt_id', 'operation_sha256'):
        need(type(work.get(key)) is str and HEX64.fullmatch(work[key]),
             'C07_BATCH100_WORK_BINDING_MISSING:' + key)
    need(inventory.get('canonical_master_sha256') == work['master_sha256'],
         'C07_BATCH100_CANONICAL_MASTER_DRIFT')
    # These are real original-byte readers. They reject canonical literal drift,
    # altered audit reservation, missing native files and unpinned source data.
    groups = (
        ('P1', p1.IDS, p1.inspect(inventory, plan, controller, asset, step, work,
                                source_loader=source_loader)),
        ('P345', p345.IDS, p345.inspect(inventory, plan, controller, asset, step, work,
                                      source_loader=source_loader)),
        ('P678', p678.IDS, p678.inspect(inventory, plan, controller, asset, step, work,
                                      source_loader=source_loader)),
    )
    master_raw = controller.master.read_bytes()
    audit_raw = controller.audit_path(asset).read_bytes()
    need(hashlib.sha256(master_raw).hexdigest() == work['master_sha256'],
         'C07_BATCH100_MASTER_BYTES_NOT_CURRENT')
    audit = mg0.inspect_batch(
        master_raw, audit_raw, asset, work['master_sha256'],
        sorted(COHORT), work['attempt_id'],
        operation_sha256=work['operation_sha256'])
    need(audit.get('rule_count') == 100 and
         audit.get('operation_bound') is True and
         audit.get('operation_sha256') == work['operation_sha256'] and
         audit.get('attempt_id') == work['attempt_id'] and
         audit.get('individual_mg0_passes') == 0 and
         audit.get('advancement_authorized') is False and
         set(audit.get('rules', {})) == set(COHORT),
         'C07_BATCH100_INDEPENDENT_OPERATION_MG0_UNTRUSTED')
    need(audit['audit_sha256'] == hashlib.sha256(audit_raw).hexdigest(),
         'C07_BATCH100_AUDIT_ORIGINAL_BYTES_DRIFT')
    all_rows = {}
    for label, ids, report in groups:
        need(type(report) is dict and
             set(report.get('rules', {})) == set(ids) and
             report.get('master_sha256') == work['master_sha256'] and
             report.get('attempt_id') == work['attempt_id'] and
             report.get('operation_sha256') == work['operation_sha256'] and
             report.get('original_audit_sha256') == audit['audit_sha256'] and
             report.get('original_audit_tail') == audit['audit_tail_sha256'] and
             report.get('advancement_authorized') is False,
             'C07_BATCH100_ORIGINAL_READER_CONTEXT_CHANGED:' + label)
        criterion_field, criterion_count = next(
            (field, count) for name, field, count in FIELDS if name == label)
        for rid in ids:
            if rid not in COHORT:
                continue
            row = report['rules'][rid]
            source = inventory['rules'].get(rid, {})
            checks = row.get(criterion_field)
            need(type(checks) is dict and len(checks) == criterion_count and
                 len(set(checks)) == criterion_count and
                 all(type(k) is str and k and type(v) is bool
                     for k, v in checks.items()) and
                 row.get('source_sha256') == source.get('source_sha256') and
                 row.get('requirement_sha256') == source.get('requirement_sha256') and
                 type(source.get('requirement_sha256')) is str and
                 HEX64.fullmatch(source['requirement_sha256']) and
                 row.get('full_rule_semantics') == 'UNKNOWN' and
                 row.get('individual_mg0') == 'UNKNOWN' and
                 row.get('advancement_authorized') is False,
                 'C07_BATCH100_PER_RULE_ORIGINAL_PROOF_UNTRUSTED:' + rid)
            verdict = audit['rules'][rid]['verdict']
            need(verdict in ('FAIL', 'UNKNOWN'),
                 'C07_BATCH100_MG0_FALSE_POSITIVE:' + rid)
            all_rows[rid] = {
                'source_sha256': source['source_sha256'],
                'requirement_sha256': source['requirement_sha256'],
                'native_reader': label,
                'original_source_predicates': checks,
                'source_predicates_observed': all(checks.values()),
                'individual_mg0': verdict,
                'full_literal_semantic_verdict': (
                    'FAIL' if verdict == 'FAIL' else 'UNKNOWN'),
                'missing_positive_proof': (
                    ['ORIGINAL_SOURCE_PREDICATE_UNPROVEN']
                    if not all(checks.values()) else []) +
                    ['INDEPENDENT_FULL_LITERAL_REVIEW_UNVERIFIED',
                     'INDEPENDENT_INDIVIDUAL_MG0_UNVERIFIED'],
                'reviewed_enrollment_authorized': False,
                'advancement_authorized': False,
            }
    need(len(all_rows) == 100 and set(all_rows) == set(COHORT),
         'C07_BATCH100_INCOMPLETE_SOURCE_COVERAGE')
    # P1 is a 30-rule family: the thirteen still-unreviewed visual, access
    # and composition literals must also receive their distinct original-byte
    # quantitative replay. No machine source observation is a FULL artistic PASS.
    from c07_p1_design_source_review import inspect as inspect_p1_design, IDS as P1_DESIGN_IDS
    p1_design=inspect_p1_design(inventory,plan,controller,asset,step,work,
                                source_loader=source_loader)
    need(p1_design.get('family_rule_count')==30 and
         p1_design.get('rule_count')==13 and
         p1_design.get('attempt_id')==work['attempt_id'] and
         p1_design.get('operation_sha256')==work['operation_sha256'] and
         p1_design.get('original_audit_sha256')==audit['audit_sha256'] and
         p1_design.get('original_audit_tail')==audit['audit_tail_sha256'] and
         p1_design.get('advancement_authorized') is False and
         p1_design.get('full_semantic_passes')==0 and
         p1_design.get('individual_mg0_passes')==0 and
         set(p1_design.get('rules',{}))==set(P1_DESIGN_IDS) and
         all(type(v.get('original_pixel_geometry_checks')) is dict and
             len(v['original_pixel_geometry_checks'])==3 and
             all(type(c) is bool for c in v['original_pixel_geometry_checks'].values())
             and v.get('requirement_sha256')==
                 inventory['rules'][rid]['requirement_sha256']
             and v.get('source_sha256')==inventory['rules'][rid]['source_sha256']
             and v.get('full_rule_semantics')=='UNKNOWN' and
             v.get('individual_mg0')=='UNKNOWN' and
             v.get('advancement_authorized') is False
             for rid,v in p1_design['rules'].items()),
         'C07_BATCH100_P1_DESIGN_THIRTEEN_ORIGINAL_RULES_UNTRUSTED')
    # Supplement the already-present 13-rule P1 design reader with
    # independent per-pixel silhouette, palette, focal contrast, native
    # void-triangle and path-endpoint measurements on ONE source snapshot.
    # This is a second source-specific measurement, never FULL or MG0.
    from c07_p1_remaining_visual_review import (
        inspect_family as inspect_p1_quantitative, IDS as P1_QUANT_IDS)
    p1_quantitative=inspect_p1_quantitative({
        'inventory':inventory,'plan':plan,'controller':controller,
        'asset':asset,'step':step,'work':work,
        'source_loader':source_loader})
    need(p1_quantitative.get('family_rule_count')==30 and
         p1_quantitative.get('rule_count')==13 and
         set(p1_quantitative.get('rules',{}))==set(P1_DESIGN_IDS)==set(P1_QUANT_IDS) and
         p1_quantitative.get('attempt_id')==work['attempt_id'] and
         p1_quantitative.get('operation_sha256')==work['operation_sha256'] and
         p1_quantitative.get('original_audit_sha256')==audit['audit_sha256'] and
         p1_quantitative.get('original_audit_tail')==audit['audit_tail_sha256'] and
         p1_quantitative.get('advancement_authorized') is False and
         p1_quantitative.get('full_semantic_passes')==0 and
         p1_quantitative.get('individual_mg0_passes')==0 and
         all(type(row.get('checks')) is dict and len(row['checks'])==2 and
             all(type(v) is bool for v in row['checks'].values()) and
             row.get('full_rule_semantics')=='UNKNOWN' and
             row.get('individual_mg0')=='UNKNOWN' and
             row.get('advancement_authorized') is False
             for row in p1_quantitative['rules'].values()),
         'C07_BATCH100_P1_QUANTITATIVE_SOURCE_REPLAY_UNTRUSTED')
    # A further independent native triangle-to-PNG raster replay covers
    # all eleven still-unreviewed P1 D031-D040/F056 source predicates.
    # The pixel projection is machine-measured, never renderer authentication,
    # independent MG0 or artistic approval.
    from c07_p1_native_raster_projection import (
        inspect_family as inspect_p1_raster, IDS as P1_RASTER_IDS)
    p1_raster=inspect_p1_raster({
        'inventory':inventory,'plan':plan,'controller':controller,
        'asset':asset,'step':step,'work':work,
        'source_loader':source_loader})
    need(p1_raster.get('family_rule_count')==30 and
         p1_raster.get('rule_count')==11 and
         set(p1_raster.get('rules',{}))==set(P1_RASTER_IDS) and
         p1_raster.get('attempt_id')==work['attempt_id'] and
         p1_raster.get('operation_sha256')==work['operation_sha256'] and
         p1_raster.get('original_audit_sha256')==audit['audit_sha256'] and
         p1_raster.get('original_audit_tail')==audit['audit_tail_sha256'] and
         p1_raster.get('full_semantic_passes')==0 and
         p1_raster.get('individual_mg0_passes')==0 and
         p1_raster.get('advancement_authorized') is False and
         all(type(row.get('checks')) is dict and len(row['checks'])==3 and
             all(type(v) is bool for v in row['checks'].values()) and
             row.get('source_sha256')==inventory['rules'][rid]['source_sha256'] and
             row.get('requirement_sha256')==
                 inventory['rules'][rid]['requirement_sha256'] and
             row.get('full_rule_semantics')=='UNKNOWN' and
             row.get('individual_mg0')=='UNKNOWN' and
             row.get('advancement_authorized') is False
             for rid,row in p1_raster['rules'].items()),
         'C07_BATCH100_P1_RASTER_ELEVEN_ORIGINAL_RULES_UNTRUSTED')
    # Consume the entire residual P1 visual family as one source-bound
    # macro; a green per-rule observation is never a FULL semantic verdict.
    _verify_p1_residual_source_macros(
        p1_design,p1_quantitative,p1_raster,inventory,work,audit)
    # The full forty-rule P3/P4/P5 macro is mandatory in the 100-rule
    # consuming-side operation. It explicitly visits each source-specific
    # replayer; this does not promote a source-only candidate to FULL or MG0.
    from c07_p345_macro_execution import (
        run as run_p345_macro,
        require_source_execution as certify_p345_source_execution,
    )
    p345_source_context={
        'inventory':inventory,'plan':plan,'controller':controller,
        'asset':asset,'step':step,'work':work,
        'source_loader':source_loader}
    p345_macro=run_p345_macro(p345_source_context)
    need(p345_macro.get('canonical_rule_count')==40 and
         p345_macro.get('due_count')==40 and
         p345_macro.get('visited_due_count')==40 and
         p345_macro.get('attempt_id')==work['attempt_id'] and
         p345_macro.get('operation_sha256')==work['operation_sha256'] and
         p345_macro.get('advancement_authorized') is False and
         p345_macro.get('individual_mg0_independently_approved') is False and
         p345_macro.get('fivem_runtime_approved') is False and
         p345_macro.get('owner_approved') is False and
         set(p345_macro.get('rows',{}))==set(p345.IDS),
         'C07_BATCH100_P345_MACRO_NOT_EXECUTED_OR_UNTRUSTED')
    # A 40/40 visit count can include 40 BLOCKED readers: it is NOT a
    # successful execution until every original reader actually finished.
    p345_execution_certificate=certify_p345_source_execution(
        p345_macro, source_context=p345_source_context)
    # Reopen the SAME original Controller attempt for the entire remaining
    # fourteen-rule P3-P5 family. This measures native bytes, NOT an external
    # renderer or game execution, and never upgrades REVIEWED/MG0.
    from c07_p345_remaining_crosssource_family import (
        inspect_family as inspect_remaining_p345, IDS as REMAINING_P345_IDS)
    remaining_p345=inspect_remaining_p345(p345_source_context)
    need(type(remaining_p345) is dict and
         remaining_p345.get('schema')=='c07-p345-remaining14-original-crosssource-v1' and
         remaining_p345.get('rule_count')==14 and
         set(remaining_p345.get('rules',{}))==set(REMAINING_P345_IDS) and
         remaining_p345.get('attempt_id')==work['attempt_id'] and
         remaining_p345.get('operation_sha256')==work['operation_sha256'] and
         remaining_p345.get('master_sha256')==work['master_sha256'] and
         remaining_p345.get('original_audit_sha256')==audit['audit_sha256'] and
         remaining_p345.get('original_audit_tail')==audit['audit_tail_sha256'] and
         remaining_p345.get('full_semantic_passes')==0 and
         remaining_p345.get('individual_mg0_passes')==0 and
         remaining_p345.get('advancement_authorized') is False and
         remaining_p345.get('original_measured_count')==sum(
             row.get('original_literal_measurement') is True
             for row in remaining_p345['rules'].values()),
         'C07_BATCH100_P345_REMAINING_FAMILY_UNTRUSTED')
    for rid,row in remaining_p345['rules'].items():
        need(type(row) is dict and
             type(row.get('source_pins_complete')) is bool and
             type(row.get('original_literal_measurement')) is bool and
             (not row['original_literal_measurement'] or
              row['source_pins_complete']) and
             row.get('source_sha256')==inventory['rules'][rid]['source_sha256'] and
             row.get('requirement_sha256')==inventory['rules'][rid]['requirement_sha256'] and
             row.get('external_provenance')=='UNKNOWN' and
             row.get('individual_mg0')=='UNKNOWN' and
             row.get('owner_acceptance')=='UNKNOWN' and
             row.get('fivem_runtime')=='UNKNOWN' and
             row.get('advancement_authorized') is False,
             'C07_BATCH100_P345_REMAINING_PER_LITERAL_UNTRUSTED:'+rid)
    # The P6-P8 thirty-rule family also has four genuinely rule-specific
    # original-byte readers (collision 4, walkability 6, RAGE 10, final QA 10).
    # They must all execute on the SAME original Controller attempt and audit.
    # A producer's CodeWalker/Sollumz/FiveM-labelled log remains untrusted.
    import c07_p6_collision_semantics as p6_collision
    import c07_p6_walkability_semantics as p6_walkability
    import c07_p7_rage_semantics as p7_rage
    import c07_p8_final_qa_semantics as p8_final
    family_readers=(
        ('P6_COLLISION',p6_collision),
        ('P6_WALKABILITY',p6_walkability),
        ('P7_RAGE',p7_rage),
        ('P8_FINAL',p8_final),
    )
    family_reports={}
    seen=set()
    for name,module in family_readers:
        report=module.inspect(inventory,plan,controller,asset,step,work,
                              source_loader=source_loader)
        ids=set(module.IDS)
        need(not seen.intersection(ids) and
             report.get('source_rule_count')==len(ids) and
             report.get('attempt_id')==work['attempt_id'] and
             report.get('operation_sha256')==work['operation_sha256'] and
             report.get('original_audit_sha256')==audit['audit_sha256'] and
             report.get('original_audit_tail')==audit['audit_tail_sha256'] and
             report.get('advancement_authorized') is False and
             report.get('full_rule_semantic_passes')==0 and
             report.get('individual_mg0_passes')==0 and
             set(report.get('rules',{}))==ids,
             'C07_BATCH100_P678_FAMILY_ORIGINAL_READER_UNTRUSTED:'+name)
        for rid,row in report['rules'].items():
            criteria=row.get('original_machine_checks')
            need(type(criteria) is dict and len(criteria) in (2,3) and
                 all(type(k) is str and k and type(v) is bool
                     for k,v in criteria.items()) and
                 row.get('requirement_sha256')==
                     inventory['rules'][rid]['requirement_sha256'] and
                 row.get('source_sha256')==
                     inventory['rules'][rid]['source_sha256'] and
                 row.get('exact_attempt_id')==work['attempt_id'] and
                 row.get('operation_sha256')==work['operation_sha256'] and
                 row.get('full_rule_semantics')=='UNKNOWN' and
                 row.get('individual_mg0')=='UNKNOWN' and
                 row.get('advancement_authorized') is False,
                 'C07_BATCH100_P678_PER_LITERAL_SOURCE_UNTRUSTED:'+rid)
        # Twenty-six additional source-specific P6/P7/P8 semantic predicates
        # are mandatory observations on the SAME original operation. A
        # negative is valid UNKNOWN evidence; absent/forged fields are not.
        if name in ('P6_WALKABILITY','P7_RAGE','P8_FINAL'):
            for rid,row in report['rules'].items():
                extra=row.get('original_cross_source_semantic')
                need(type(extra) is dict and len(extra)==1 and
                     all(type(key) is str and key and type(value) is bool
                         for key,value in extra.items()),
                     'C07_BATCH100_P678_CROSS_SOURCE_SEMANTIC_MISSING:'+rid)
            need(type(report.get('original_cross_source_positive_obligations'))
                 is int and
                 report['original_cross_source_positive_obligations']==sum(
                     next(iter(row['original_cross_source_semantic'].values()))
                     for row in report['rules'].values()),
                 'C07_BATCH100_P678_CROSS_SOURCE_COUNTS_UNTRUSTED:'+name)
        family_reports[name]=report
        seen.update(ids)
    need(len(seen)==30 and seen==set(p678.IDS[:30]),
         'C07_BATCH100_P678_THIRTY_EXACT_FAMILY_INCOMPLETE')
    # The observation report must expose the separately recomputed native
    # code-enrollment count; 100 examined rules are NOT 100 reviewed rules.
    from c07_cohort_completion_gate import snapshot as code_registry_snapshot
    code_registry = code_registry_snapshot()
    need(code_registry['cohort_count'] == 100 and
         code_registry['registry_inconsistent_ids'] == [],
         'C07_BATCH100_REVIEWED_NATIVE_DISPATCH_INCONSISTENT')
    # Macros are recomputed from the same reviewed native registry; a family
    # cannot be advertised as complete because one small predicate passed.
    from c07_cohort_completion_gate import macro_snapshot
    family_macros=macro_snapshot()
    need(family_macros['cohort_count']==100 and
         family_macros['macro_count']==3 and
         family_macros['family_count']==10 and
         family_macros['code_reviewed']==code_registry['code_reviewed_count'] and
         family_macros['code_missing']==code_registry['code_missing_count'] and
         family_macros['advancement_authorized'] is False,
         'C07_BATCH100_WHOLE_FAMILY_MACRO_RECOUNT_UNTRUSTED')
    return {
        'p678_thirty_rule_specific_original': family_reports,
        'p1_thirteen_original_design': p1_design,
        'p1_thirteen_original_quantitative': p1_quantitative,
        'p1_eleven_original_native_raster': p1_raster,
        'p345_forty_source_macro': p345_macro,
        'p345_execution_only_certificate': p345_execution_certificate,
        'p345_remaining_fourteen_original_crosssource': remaining_p345,
        'native_semantic_code_review': code_registry,
        'whole_family_macro_code_review': family_macros,
        'schema': 'gg-c07-exact100-original-native-replay-v1',
        'rule_count': 100, 'rule_ids': sorted(COHORT),
        'master_sha256': work['master_sha256'],
        'attempt_id': work['attempt_id'],
        'operation_sha256': work['operation_sha256'],
        'original_audit_sha256': audit['audit_sha256'],
        'original_audit_tail': audit['audit_tail_sha256'],
        'original_source_predicates_observed': sum(
            r['source_predicates_observed'] for r in all_rows.values()),
        'mg0_fail_count': sum(r['individual_mg0'] == 'FAIL'
                              for r in all_rows.values()),
        'full_reviewed_new': 0, 'full_semantic_passes': 0,
        'individual_mg0_passes': 0, 'advancement_authorized': False,
        'rules': all_rows,
        'results_sha256': digest(all_rows),
    }

"""Twenty source-specific native semantic replayers on ORIGINAL Controller bytes.

This module is a consuming-side implementation, not a batch observation gate.
Every result is reconstructed from the Controller's hash-chained current audit,
registered original binaries and pre-D SHA pins. No owner/FiveM/MG0 PASS is
inferred. A missing independent source context makes native replay UNKNOWN.
"""
import hashlib
import json

import supervisor_judgment as judgment

# Explicit original literal / rule / criterion contracts, no dynamic fallback.
NATIVE_RULES = {
    'AAA-200-E-044': ('p1', (
        'pre_D_path_line_strings_decoded',
        'main_and_secondary_path_ids_named',
        'original_path_geojson_sha_pinned')),
    'AAA-200-O-141': ('budget', (
        'original_platform_and_scene_budget_scoped',
        'real_native_scene_fits_declared_triangle_budget',
        'real_original_material_and_rgba_cost_within_pre_d_budget')),
    'AAA-200-P-151': ('collision', (
        'source_solid_surface_regions_explicit_and_valid',
        'each_original_solid_region_has_real_collision_faces',
        'each_declared_solid_region_exists_in_original_visual_geometry')),
    'AAA-200-P-152': ('collision', (
        'original_visual_and_collision_exports_distinct',
        'separate_actual_triangle_sets_independently_read',
        'collision_and_visual_triangle_geometry_independently_distinct')),
    'AAA-200-P-153': ('collision', (
        'original_collision_triangle_budget_explicit',
        'actual_collision_complexity_within_original_limits')),
    'AAA-200-L-117': ('uv', (
        'all_original_uv_triangle_pairs_compared',
        'no_positive_area_overlap_under_original_policy')),
    'AAA-200-M-124': ('texture', (
        'actual_embedded_original_pixels_have_distinct_colors',
        'original_pixel_luminance_variance_not_flat')),
    'AAA-200-M-128': ('texture', (
        'original_embedded_png_bytes_and_dimensions_within_budget',
        'all_original_embedded_images_independently_decoded')),
    'AAA-200-S-189': ('final_qa', (
        'original_critical_finding_present',
        'critical_finding_keeps_controller_delivery_blocked')),
    'AAA-200-T-197': ('closure', (
        'original_candidate_not_self_labelled_approved',
        'source_bound_candidate_and_export_exist')),
    'AAA-200-T-196': ('closure', (
        'original_test_matrix_explicitly_separates_run_and_not_run',
        'every_reported_run_references_registered_original_evidence')),
    'AAA-200-E-042': ('p1', (
        'original_xyz_coordinate_origin_declared',
        'original_coordinate_basis_named',
        'native_local_GLTF_positions_available')),
    'AAA-200-E-047': ('p1', (
        'expected_original_structural_envelope_declared',
        'native_original_bounds_recomputed',
        'actual_original_native_bbox_matches_envelope')),
    'AAA-200-F-052': ('p1', (
        'actual_original_local_extents_independently_decoded',
        'original_target_local_bounds_declared',
        'original_local_bounds_match_pre_D_expected_extent')),
    'AAA-200-L-111': ('topology', (
        'all_original_mesh_primitives_scanned', 'nonmanifold_edge_count_zero')),
    'AAA-200-L-112': ('topology', (
        'no_duplicate_geometric_faces', 'no_exact_duplicate_coordinate_vertices')),
    'AAA-200-O-142': ('budget', (
        'all_original_glb_triangles_counted',
        'measured_count_not_above_original_pre_d_limit')),
    'AAA-200-O-148': ('budget', (
        'all_embedded_original_png_dimensions_decoded',
        'actual_rgba_memory_bound_by_original_budget')),
    'AAA-200-T-192': ('delivery', (
        'original_required_delivery_member_set_explicit',
        'all_original_required_members_present')),
    'AAA-200-T-194': ('delivery', (
        'registered_source_export_bytes_equal_archive_members',
        'original_manifest_asset_version_and_hashes_match')),
}
VALIDATORS = {rid: 'native-original-rule-' + rid.lower().replace('-', '_') + '-v1'
              for rid in NATIVE_RULES}
# These sixteen literals have independently decidable original-byte acceptance
# conditions. The other four source readers are diagnostic CANDIDATES only;
# never enroll or dispatch them as full positive semantic validators.
FULL_LITERAL_REVIEWED = frozenset((
    'AAA-200-E-047', 'AAA-200-F-052', 'AAA-200-L-112',
    'AAA-200-L-117', 'AAA-200-M-124', 'AAA-200-M-128',
    'AAA-200-O-141', 'AAA-200-O-142',
    'AAA-200-P-151', 'AAA-200-P-152', 'AAA-200-P-153',
    'AAA-200-O-148', 'AAA-200-S-189', 'AAA-200-T-192', 'AAA-200-T-194',
    'AAA-200-T-197',
))
REVIEWED_RULES = {rid: NATIVE_RULES[rid] for rid in FULL_LITERAL_REVIEWED}
REVIEWED_VALIDATORS = {rid: VALIDATORS[rid] for rid in FULL_LITERAL_REVIEWED}

class NativeRuleEvidenceBlocked(ValueError):
    pass

def need(value, reason):
    if not value:
        raise NativeRuleEvidenceBlocked(reason)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def build_packet(source_context, rule_id, *, expected=None):
    """Generate an independently reproducible packet from real source bytes.

    source_context must be a trusted consuming-side Controller callback output;
    no signed producer observation is accepted as source_context.
    """
    need(rule_id in NATIVE_RULES and type(source_context) is dict and
         set(source_context) == {'inventory', 'plan', 'controller', 'asset',
                                 'step', 'work', 'source_loader'},
         'C07_REPLAYER_TRUSTED_CONTROLLER_SOURCE_REQUIRED')
    inv = source_context['inventory']
    plan = source_context['plan']
    controller = source_context['controller']
    asset = source_context['asset']
    step = source_context['step']
    work = source_context['work']
    loader = source_context['source_loader']
    need(callable(loader) and type(work) is dict and type(inv) is dict and
         type(plan) is dict and type(asset) is str and type(step) is str,
         'C07_REPLAYER_ORIGINAL_CONTEXT_SCHEMA')
    row = inv['rules'][rule_id]
    actual_binding = judgment.binding(work, row, rule_id)
    if expected is not None:
        need(actual_binding == expected, 'C07_REPLAYER_ATTEMPT_OPERATION_SOURCE_MISMATCH')
    domain, criteria = NATIVE_RULES[rule_id]
    # Import domain readers only after reviewed enrollment has initialized;
    # the existing evidence modules import approved_validators indirectly.
    if domain == 'p1':
        from c07_p1_thirty_native_domain import inspect
    elif domain == 'topology':
        from c07_p3_geometry_semantics import inspect
    elif domain == 'budget':
        from c07_p5_budget_semantics import inspect
    elif domain == 'collision':
        from c07_p6_collision_semantics import inspect
    elif domain == 'delivery':
        from c07_p8_delivery_semantics import inspect
    elif domain == 'uv':
        from c07_p3_uv_semantics import inspect
    elif domain == 'texture':
        from c07_p4_texture_semantics import inspect
    elif domain == 'final_qa':
        from c07_p8_final_qa_semantics import inspect
    elif domain == 'closure':
        from c07_p8_closure_semantics import inspect
    else:
        raise NativeRuleEvidenceBlocked('C07_REPLAYER_NO_LITERAL_DOMAIN')
    from c07_mg0_individual import inspect_batch
    report = inspect(inv, plan, controller, asset, step, work,
                     source_loader=loader)
    source = report['rules'][rule_id]
    checks = dict(source['original_native_measured_criteria'] if domain == 'p1'
                  else source['original_machine_checks'])
    if rule_id == 'AAA-200-S-189':
        # A critical from another attempt, operation, or a closed historical
        # step cannot establish the current delivery firewall. Re-read the
        # original hash chain and bind the critical to THIS operation window.
        from c07_positive_native_process import _original_attempt
        rows, tail, state, _ = _original_attempt(
            inv, plan, controller, asset, step, work)
        opens = [i for i, event in enumerate(rows)
                 if event.get('event') == 'SUPERVISOR_OPERATION_OPENED'
                 and event.get('step') == step]
        need(len(opens) == 1, 'C07_S189_EXACT_OPERATION_OPEN_REQUIRED')
        current_critical = [event for event in rows[opens[0]+1:]
            if event.get('event') == 'QUALITY_FINDING'
            and event.get('step') == step
            and event.get('attempt_id') == work['attempt_id']
            and event.get('operation_sha256') == work['operation_sha256']
            and event.get('severity') == 'CRITICAL'
            and event.get('status') in ('OPEN', 'FAIL', 'UNKNOWN')]
        checks['original_critical_finding_present'] = bool(current_critical)
        checks['critical_finding_keeps_controller_delivery_blocked'] = bool(
            current_critical and state.get('delivery_status') != 'DELIVERABLE')
    need(type(checks) is dict and set(checks) == set(criteria) and
         all(type(v) is bool for v in checks.values()) and
         source['requirement_sha256'] == row['requirement_sha256'] and
         source['source_sha256'] == row['source_sha256'] and
         report['attempt_id'] == work['attempt_id'] and
         report['operation_sha256'] == work['operation_sha256'] and
         report['original_audit_sha256'] ==
             digest(controller.audit_path(asset).read_bytes()) and
         report['advancement_authorized'] is False,
         'C07_REPLAYER_ORIGINAL_RULE_OR_AUDIT_CHANGED')
    # Re-evaluate the individual canonical MG0 triggers from the original
    # current operation audit, rather than copying a producer MG0 flag.
    audit = inspect_batch(controller.master.read_bytes(),
        controller.audit_path(asset).read_bytes(), asset,
        work['master_sha256'], [rule_id], work['attempt_id'],
        operation_sha256=work['operation_sha256'])
    verdict = audit['rules'][rule_id]['verdict']
    need(verdict in ('FAIL', 'UNKNOWN') and
         audit['individual_mg0_passes'] == 0 and
         audit['advancement_authorized'] is False,
         'C07_REPLAYER_UNPROVEN_MG0_CANNOT_PASS')
    proof = {
        'rule_id': rule_id, 'source_sha256': row['source_sha256'],
        'requirement_sha256': row['requirement_sha256'],
        'master_sha256': work['master_sha256'],
        'attempt_id': work['attempt_id'],
        'operation_sha256': work['operation_sha256'],
        'original_audit_sha256': report['original_audit_sha256'],
        'original_audit_tail': report['original_audit_tail'],
        'checks': checks, 'mg0_observation_sha256':
            audit['rules'][rule_id]['observation_sha256'],
    }
    mg_failed = verdict == 'FAIL'
    mg_checks = ({'cause_identified': False,
                  'affected_states_invalidated': False,
                  'correction_applied': False,
                  'reapplied_on_current_attempt': False}
                 if mg_failed else {'canonical_triggers_checked': False})
    packet = {
        'schema': 'gg-semantic-rule-v1',
        'scope': judgment.SEMANTIC_SCOPE,
        'validator_id': VALIDATORS[rule_id],
        'binding': actual_binding,
        'rule': {'result': ('PASS' if all(checks.values()) else 'FAIL')
                           if rule_id in FULL_LITERAL_REVIEWED else 'UNKNOWN',
                 'checks': checks,
                 'proof_digest': judgment.digest(proof)},
        'mg0': {'binding': actual_binding, 'triggered': True if mg_failed else None,
                'result': verdict, 'checks': mg_checks,
                'proof_digest': judgment.digest({
                    'rule_id': rule_id, 'mg0': audit['rules'][rule_id],
                    'original_audit_sha256': audit['audit_sha256'],
                    'operation_sha256': work['operation_sha256']})},
    }
    return packet

def native_rule_readback(api, packet, expected, spec, *, source_context=None):
    """Replay one whitelisted original literal; reject producer-only packets."""
    need(type(expected) is dict and type(packet) is dict and
         type(spec) is dict and callable(source_context),
         'C07_REPLAYER_NO_INDEPENDENT_ORIGINAL_SOURCE_READER')
    rule_id = expected.get('rule_id')
    need(rule_id in FULL_LITERAL_REVIEWED and
         spec.get('validator_id') == VALIDATORS[rule_id] and
         set(spec.get('criteria', ())) == set(NATIVE_RULES[rule_id][1]) and
         spec.get('requirement_sha256') == expected.get('requirement_sha256'),
         'C07_REPLAYER_UNREVIEWED_OR_WRONG_LITERAL')
    original = source_context(expected)
    computed = build_packet(original, rule_id, expected=expected)
    need(packet == computed, 'C07_REPLAYER_PRODUCER_PACKET_NOT_RECOMPUTED')
    return {'rule_id': rule_id,
            'documentary_result': computed['rule']['result'],
            'individual_rule_mg0': computed['mg0']['result'],
            'advancement_authorized': False,
            'asset_advancement_authorized': False}

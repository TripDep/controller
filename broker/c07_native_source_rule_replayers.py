"""Twenty-six source-specific native semantic replayers on ORIGINAL Controller bytes.

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
    'AAA-200-F-057': ('p1_composition_full', (
        'pre_d_composition_target_policy_and_original_qa_source_sha_bound',
        'reported_composition_defect_independently_recomputed_from_original_glb',
        'original_composition_qa_audited_before_first_detail_operation')),
    'AAA-200-E-046': ('p1_circulation_full', (
        'original_pre_d_entrance_exit_view_policy_and_native_source_sha_pinned',
        'both_real_path_endpoints_connected_and_inside_original_accessible_zone',
        'original_camera_faces_both_access_points_with_unobstructed_native_triangle_sightlines')),
    'AAA-200-L-118': ('p345_remaining_scoped', (
        'pre_d_original_atlas_and_baseline_contract_sha_bound',
        'actual_native_and_baseline_material_texture_bindings_recomputed',
        'measured_original_atlas_binding_reduction_and_texture_quality_retained')),
    'AAA-200-L-119': ('p345_remaining_scoped', (
        'pre_d_original_bake_necessity_and_source_normal_map_sha_bound',
        'actual_exported_normal_texture_and_baked_png_pixels_redecoded',
        'actual_baked_map_channels_and_exported_normal_image_match')),
    'AAA-200-L-120': ('p345_remaining_scoped', (
        'pre_d_original_approved_mesh_and_current_export_sha_bound',
        'actual_approved_and_current_native_triangle_geometry_compared',
        'trusted_original_visual_approval_and_renderer_equivalence_confirmed')),
    'AAA-200-N-133': ('p345_remaining_scoped', (
        'pre_d_original_lighting_defect_policy_and_capture_sha_bound',
        'actual_original_native_triangles_and_defect_report_recomputed',
        'trusted_lighting_renderer_and_geometry_defect_provenance_confirmed')),
    'AAA-200-N-134': ('p345_remaining_scoped', (
        'pre_d_original_direct_light_policy_and_view_sha_bound',
        'actual_direct_light_pixels_and_original_pbr_materials_recomputed',
        'trusted_direct_light_renderer_and_physical_material_response_confirmed')),
    'AAA-200-N-135': ('p345_remaining_scoped', (
        'pre_d_original_shadow_policy_and_view_sha_bound',
        'actual_shadow_and_neutral_pixels_and_materials_recomputed',
        'trusted_shadow_renderer_and_physical_material_response_confirmed')),
    'AAA-200-N-136': ('p345_remaining_scoped', (
        'pre_d_original_reflective_material_policy_and_view_sha_bound',
        'actual_original_metal_glass_pbr_and_reflection_pixels_recomputed',
        'trusted_reflection_renderer_and_real_material_behavior_confirmed')),
    'AAA-200-N-139': ('p345_remaining_scoped', (
        'pre_d_original_underside_qa_scope_and_view_sha_bound',
        'actual_underside_pixels_and_unresolved_qa_findings_recomputed',
        'trusted_renderer_provenance_and_complete_defect_coverage_confirmed')),
    'AAA-200-N-140': ('p345_remaining_scoped', (
        'pre_d_original_separate_presentation_and_technical_qa_sha_bound',
        'actual_distinct_original_visual_capture_and_machine_report_recomputed',
        'trusted_independent_artistic_vs_technical_review_confirmed')),
    'AAA-200-O-143': ('p345_remaining_scoped', (
        'pre_d_original_hidden_face_policy_and_baseline_sha_bound',
        'actual_before_after_native_triangle_counts_and_bounds_recomputed',
        'original_hidden_face_intent_and_nonessential_geometry_proven')),
    'AAA-200-O-145': ('p345_remaining_scoped', (
        'pre_d_original_lod_transition_policy_and_views_sha_bound',
        'actual_original_near_far_lod_geometry_and_pixels_recomputed',
        'trusted_renderer_continuity_and_no_visible_lod_popping_confirmed')),
    'AAA-200-O-147': ('p345_remaining_scoped', (
        'pre_d_original_texture_reuse_and_quality_policy_sha_bound',
        'actual_shared_original_glb_image_bindings_and_pixels_recomputed',
        'independent_scene_quality_not_degraded_by_reuse_confirmed')),
    'AAA-200-O-150': ('p345_remaining_scoped', (
        'pre_d_original_platform_scene_benchmark_contract_sha_bound',
        'actual_registered_frame_samples_and_source_scene_bytes_recomputed',
        'trusted_real_fivem_runtime_capture_provenance_confirmed')),
    'AAA-200-M-121': ('p4_material_macro_full', (
        'pre_d_original_physical_material_classification_sha_pinned',
        'every_actual_exported_primitive_material_has_canonical_class',
        'all_actual_original_roughness_and_metallic_values_in_physical_class_ranges')),
    'AAA-200-M-122': ('p4_material_macro_full', (
        'pre_d_light_response_and_pbr_factor_contract_sha_pinned',
        'all_original_exported_material_roughness_and_reflectance_measured',
        'real_original_direct_neutral_shadow_pixels_follow_source_bounds')),
    'AAA-200-M-125': ('p4_material_macro_full', (
        'pre_d_original_surface_variation_limits_sha_pinned',
        'actual_original_embedded_texture_quadrants_recomputed',
        'all_real_texture_variation_exceeds_original_local_contrast_limit')),
    'AAA-200-M-126': ('p4_material_macro_full', (
        'pre_d_five_physical_material_class_ranges_and_original_export_sha_pinned',
        'all_five_wood_stone_metal_glass_plaster_materials_bound_to_original_primitives',
        'five_original_materials_have_distinct_physical_pbr_and_alpha_properties')),
    'AAA-200-M-127': ('p4_material_macro_full', (
        'pre_d_weathering_purpose_and_original_reference_sha_pinned',
        'original_exported_texture_and_weathering_reference_pixels_recomputed',
        'actual_weathering_distribution_within_pre_d_motivated_limits')),
    'AAA-200-M-129': ('p4_material_macro_full', (
        'original_pre_d_target_rage_shader_and_native_export_source_sha_pinned',
        'original_native_rage_shader_descriptors_independently_parsed',
        'original_shaders_vertex_attributes_and_texture_channels_compatible')),
    'AAA-200-M-130': ('p4_material_macro_full', (
        'pre_d_original_multi_light_material_response_policy_sha_pinned',
        'actual_registered_neutral_direct_shadow_pixel_buffers_recomputed',
        'trusted_independent_renderer_provenance_and_real_material_response_verified')),
    'AAA-200-O-149': ('p5_alpha_cost_full', (
        'pre_d_complete_vegetation_transparency_cost_budget_and_roles_sha_pinned',
        'all_original_alpha_primitives_and_texture_bytes_independently_measured',
        'actual_original_vegetation_transparent_triangle_draw_and_rgba_costs_within_pre_d_budget')),
    'AAA-200-F-059': ('p1_structural_fix_full', (
        'pre_d_complete_structural_defect_correction_and_detail_gate_policy_sha_pinned',
        'every_original_structural_before_after_mesh_recomputed_and_correction_effective',
        'all_original_structural_rechecks_pass_before_first_detail_phase_event')),
    'AAA-200-S-182': ('p8_final_process_full', (
        'pre_d_complete_original_component_alignment_proportion_and_axis_policy_sha_pinned',
        'every_original_world_component_bounds_and_forward_axis_independently_measured',
        'all_original_anchor_alignments_and_dimension_ratios_meet_pre_d_limits')),
    'AAA-200-S-187': ('p8_final_process_full', (
        'pre_d_full_significant_correction_and_required_recheck_scope_sha_pinned',
        'every_current_audit_correction_bound_to_distinct_original_before_after_meshes',
        'all_required_after_correction_geometry_checks_replayed_and_audited_in_order')),
    'AAA-200-S-183': ('p8_intersection_full', (
        'pre_d_complete_component_roles_placement_and_intersection_policy_sha_pinned',
        'every_current_original_component_world_triangle_independently_recomputed',
        'all_original_component_pairs_decisively_nonintersecting_or_exact_duplicate_detected')),
    'AAA-200-S-181': ('camera_views_full', (
        'pre_d_six_original_view_roles_current_render_events_and_view_qa_sha_pinned',
        'six_original_view_pixel_arrays_and_native_geometry_independently_distinct',
        'six_original_camera_axes_and_individual_view_qa_checks_replayed')),
    'AAA-200-M-123': ('p4_pbr_maps_full', (
        'pre_d_gltf2_pbr_supported_normal_roughness_channels_and_original_export_sha_pinned',
        'every_original_native_material_references_two_valid_distinct_embedded_png_maps_with_uv',
        'independently_decoded_original_normal_and_roughness_pixel_channels_physically_nontrivial')),
    'AAA-200-N-131': ('p4_lighting_player_full', (
        'original_pre_d_neutral_light_policy_and_capture_event_sha_bound',
        'actual_neutral_view_pixels_redecoded_and_channel_balance_measured',
        'real_native_geometry_and_neutral_qa_luminance_in_source_range')),
    'AAA-200-N-132': ('p4_lighting_player_full', (
        'pre_d_distinct_neutral_cinematic_modes_and_two_original_events_bound',
        'actual_neutral_and_cinematic_pixel_arrays_independently_distinct',
        'two_original_capture_modes_have_separate_source_roles_and_luminance')),
    'AAA-200-N-137': ('p4_lighting_player_full', (
        'pre_d_player_eye_height_camera_and_original_capture_event_sha_bound',
        'actual_player_view_png_and_native_geometry_independently_reopened',
        'measured_original_camera_at_player_height_and_facing_actual_asset')),
    'AAA-200-F-056': ('camera_views_full', (
        'pre_d_four_camera_capture_roles_and_current_operation_events_sha_pinned',
        'four_distinct_original_png_pixel_arrays_and_native_geometry_reopened',
        'front_left_right_top_original_camera_positions_and_axes_verified')),
    'AAA-200-N-138': ('camera_views_full', (
        'pre_d_front_side_rear_top_capture_roles_and_current_operation_events_sha_pinned',
        'four_distinct_original_png_pixel_arrays_and_native_geometry_reopened',
        'front_side_rear_top_original_camera_positions_and_axes_verified')),
    'AAA-200-E-048': ('p1_terrain_full', (
        'pre_d_planar_terrain_contact_contract_and_both_original_meshes_sha_pinned',
        'entire_native_projected_footprint_inside_original_support_triangle',
        'all_original_native_vertices_above_ground_and_measured_contacts_within_tolerance')),
    'AAA-200-F-055': ('p1_terrain_full', (
        'pre_d_player_capsule_path_and_all_obstacle_roles_original_sha_pinned',
        'all_original_walkable_segments_inside_measured_support_terrain',
        'all_measured_player_swept_corridors_clear_of_original_blocking_triangles')),
    'AAA-200-E-049': ('p1_environment_full', (
        'pre_d_complete_existing_asset_placement_and_clearance_policy_sha_pinned',
        'original_native_and_every_existing_asset_world_bounds_independently_recomputed',
        'all_actual_world_aabbs_separated_by_source_required_clearance')),
    'AAA-200-E-050': ('p1_environment_full', (
        'pre_d_entire_asset_lock_and_original_baseline_sha_pinned',
        'current_native_and_baseline_original_export_bytes_identical',
        'current_and_baseline_original_world_placements_identical')),
    'AAA-200-F-053': ('p1_environment_full', (
        'pre_d_world_forward_and_original_native_anchor_contract_sha_pinned',
        'both_original_forward_anchor_points_present_in_actual_native_mesh',
        'measured_native_world_forward_and_up_match_source_target')),
    'AAA-200-E-041': ('p1_site_full', (
        'pre_d_site_survey_boundary_and_metric_dimensions_sha_pinned',
        'original_survey_polygon_area_and_extents_independently_measured',
        'native_original_mesh_extents_inside_measured_site_boundary')),
    'AAA-200-E-044': ('p1_paths_full', (
        'pre_d_original_geojson_and_path_class_contract_sha_pinned',
        'all_original_path_features_have_unique_ids_valid_nonzero_geometry_and_explicit_class',
        'measured_main_path_network_connected_and_every_secondary_joins_main')),
    'AAA-200-E-045': ('p1_paths_full', (
        'pre_d_access_zone_and_player_actor_policy_sha_pinned',
        'original_access_and_exclusion_polygons_nonzero_and_actor_labels_valid',
        'actual_original_access_exclusion_polygon_interiors_do_not_overlap')),
    'AAA-200-E-043': ('p1_spatial', (
        'pre_d_two_building_world_placements_and_ratio_targets_sha_pinned',
        'actual_original_world_space_building_extents_independently_measured',
        'real_building_clearance_footprint_and_height_ratios_meet_pre_d_limits')),
    'AAA-200-O-144': ('p5_full', (
        'pre_d_importance_specific_lod_distance_policy_authenticated',
        'original_native_and_lod_meshes_measured_and_spatially_coherent',
        'real_lod_reduction_and_switch_distances_match_importance_policy')),
    'AAA-200-O-146': ('p5_full', (
        'original_baseline_and_material_reduction_policy_sha_pinned',
        'original_before_after_material_bindings_independently_counted',
        'measured_material_binding_reduction_meets_pre_d_target')),
    'AAA-200-O-141': ('budget', (
        'original_platform_and_scene_budget_scoped',
        'real_native_scene_fits_declared_triangle_budget',
        'real_original_material_and_rgba_cost_within_pre_d_budget')),
    'AAA-200-P-154': ('p6_access_full', (
        'pre_d_four_access_kinds_and_clearance_limits_original_sha_pinned',
        'original_door_and_passage_free_and_stair_tread_rises_measured',
        'original_stair_and_side_rail_collision_and_visual_geometry_verified')),
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
    'AAA-200-P-156': ('p6_invisible_full', (
        'pre_d_invisible_collision_tolerance_and_original_exports_sha_pinned',
        'every_original_collision_triangle_normal_matches_a_visual_surface',
        'every_original_collision_triangle_vertex_and_centroid_on_visible_original_geometry')),
    'AAA-200-P-157': ('walkability', (
        'original_walkable_region_boxes_valid',
        'each_walkable_region_has_original_collision_surface',
        'every_walkable_region_has_source_pinned_player_width_clearance')),
    'AAA-200-P-158': ('walkability', (
        'original_collision_and_terrain_triangles_reopened',
        'original_terrain_collision_contact_centroids_measured',
        'every_pre_d_contact_region_has_independently_matched_source_geometry')),
    'AAA-200-P-159': ('walkability', (
        'original_vehicle_corridor_widths_measured',
        'actual_collision_faces_clear_of_vehicle_corridors',
        'every_vehicle_corridor_has_source_pinned_vertical_clearance')),
    'AAA-200-L-115': ('uv', (
        'all_original_uv_triangles_independently_measured',
        'uv_edge_anisotropy_within_pre_d_bound')),
    'AAA-200-L-116': ('uv', (
        'actual_embedded_png_and_uv_texel_density_measured',
        'real_texel_density_within_original_target',
        'distinct_original_related_asset_density_matches_pre_d_tolerance')),
    'AAA-200-L-117': ('uv', (
        'all_original_uv_triangle_pairs_compared',
        'no_positive_area_overlap_under_original_policy')),
    'AAA-200-M-124': ('texture', (
        'actual_embedded_original_pixels_have_distinct_colors',
        'original_pixel_luminance_variance_not_flat')),
    'AAA-200-M-128': ('texture', (
        'original_embedded_png_bytes_and_dimensions_within_budget',
        'all_original_embedded_images_independently_decoded')),
    'AAA-200-S-188': ('final_qa', (
        'original_machine_report_bound_to_real_export',
        'six_distinct_visual_views_separate_from_machine_report',
        'original_test_categories_and_unattested_engine_separated')),
    'AAA-200-S-189': ('final_qa', (
        'original_critical_finding_present',
        'critical_finding_keeps_controller_delivery_blocked')),
    'AAA-200-T-196': ('closure', (
        'original_test_matrix_explicitly_separates_run_and_not_run',
        'every_reported_run_references_registered_original_evidence',
        'declared_source_byte_test_replayed_from_originals')),
    'AAA-200-T-197': ('closure', (
        'original_candidate_not_self_labelled_approved',
        'source_bound_candidate_and_export_exist')),
    'AAA-200-E-042': ('p1_site_full', (
        'pre_d_metric_axis_contract_and_native_source_sha_pinned',
        'right_handed_axis_basis_origin_orientation_and_scale_verified',
        'actual_original_mesh_geometry_reopened_in_defined_local_coordinates')),
    'AAA-200-E-047': ('p1', (
        'expected_original_structural_envelope_declared',
        'native_original_bounds_recomputed',
        'actual_original_native_bbox_matches_envelope')),
    'AAA-200-F-051': ('p1_blockout_full', (
        'original_pre_d_blockout_source_budget_and_shape_contract_sha_pinned',
        'actual_original_major_form_mesh_faces_and_triangle_budget_measured',
        'first_blockout_export_precedes_all_original_detail_operations')),
    'AAA-200-F-060': ('p1_blockout_full', (
        'original_pre_d_blockout_acceptance_and_qa_sha_pinned',
        'all_original_blockout_acceptance_checks_recomputed_from_geometry',
        'no_detail_phase_or_open_qa_finding_before_verified_blockout')),
    'AAA-200-F-054': ('p1_spatial', (
        'pre_d_complete_module_alignment_pair_contract_sha_pinned',
        'every_alignment_anchor_recomputed_from_actual_original_mesh_vertices',
        'all_actual_world_space_module_anchor_gaps_within_original_tolerance')),
    'AAA-200-F-058': ('p1_spatial', (
        'pre_d_complete_module_connection_edge_contract_sha_pinned',
        'every_connection_edge_recomputed_as_real_original_mesh_edge',
        'all_world_connection_edges_share_length_and_opposite_side_contact')),
    'AAA-200-F-052': ('p1', (
        'actual_original_local_extents_independently_decoded',
        'original_target_local_bounds_declared',
        'original_local_bounds_match_pre_D_expected_extent')),
    'AAA-200-L-111': ('topology', (
        'all_original_mesh_primitives_topologically_inspected',
        'original_mesh_edges_no_nonmanifold_or_degenerate',
        'original_mesh_faces_unique')),
    'AAA-200-L-113': ('topology', (
        'all_original_triangle_areas_independently_recomputed',
        'no_original_degenerate_or_duplicate_faces',
        'original_geometry_matches_source_pinned_reference')),
    'AAA-200-L-114': ('topology', (
        'all_original_vertex_normals_finite_and_unit_length',
        'every_original_vertex_normal_matches_face_orientation',
        'original_face_orientation_matches_source_pinned_reference')),
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
# These twenty-two literals have independently decidable original-byte acceptance
# conditions. The other three source readers are diagnostic CANDIDATES only;
# never enroll or dispatch them as full positive semantic validators.
# Camera-angle labels and lighting-mode declarations are producer metadata.
# Their original pixels and audit rows are useful SCOPED observations, but
# cannot independently establish actual camera/lighting setup or full QA.
# Never enroll them as FULL until trusted renderer provenance is available.
FULL_LITERAL_REVIEWED = frozenset((
    # M121 physical identification, M122 real reflectance, M125 credible
    # variation and M127 motivated weathering are not provable by producer
    # labels and static pixel variance. Keep their SCOPED checks, no FULL.
    'AAA-200-M-126',
    'AAA-200-O-149',
    'AAA-200-F-059',
    'AAA-200-S-182', 'AAA-200-S-187',
    'AAA-200-S-183',
    'AAA-200-M-123',
    'AAA-200-E-048', 'AAA-200-F-055',
    'AAA-200-E-049', 'AAA-200-E-050', 'AAA-200-F-053',
    'AAA-200-E-041', 'AAA-200-E-042',
    'AAA-200-E-043', 'AAA-200-E-044', 'AAA-200-E-045', 'AAA-200-E-046', 'AAA-200-E-047',
    'AAA-200-F-052', 'AAA-200-F-054', 'AAA-200-F-058',
    'AAA-200-F-051', 'AAA-200-F-057', 'AAA-200-F-060',
    'AAA-200-L-111', 'AAA-200-L-112', 'AAA-200-L-113', 'AAA-200-L-114',
    'AAA-200-L-115', 'AAA-200-L-116', 'AAA-200-L-117', 'AAA-200-M-124', 'AAA-200-M-128',
    'AAA-200-O-141', 'AAA-200-O-142', 'AAA-200-O-144', 'AAA-200-O-146',
    'AAA-200-P-151', 'AAA-200-P-152', 'AAA-200-P-153', 'AAA-200-P-156',
    'AAA-200-P-157', 'AAA-200-P-158', 'AAA-200-P-159', 'AAA-200-P-154',
    'AAA-200-O-148', 'AAA-200-S-188', 'AAA-200-S-189', 'AAA-200-T-192', 'AAA-200-T-194',
    'AAA-200-T-196', 'AAA-200-T-197',
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
    elif domain == 'walkability':
        from c07_p6_walkability_semantics import inspect
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
    elif domain == 'p5_full':
        from c07_p5_full_review import inspect as inspect_p5_full
    elif domain == 'p5_alpha_cost_full':
        from c07_p5_alpha_cost_full_review import inspect as inspect_alpha_cost
    elif domain == 'p1_blockout_full':
        from c07_p1_blockout_full_review import inspect as inspect_blockout
    elif domain == 'p1_structural_fix_full':
        from c07_p1_structural_correction_full_review import inspect as inspect_structural_fix
    elif domain == 'p1_spatial':
        from c07_p1_spatial_full_review import inspect as inspect_p1_spatial
    elif domain == 'p1_paths_full':
        from c07_p1_paths_access_full_review import inspect as inspect_p1_paths
    elif domain == 'p1_circulation_full':
        from c07_p1_circulation_full_review import inspect as inspect_circulation
    elif domain == 'p1_composition_full':
        from c07_p1_composition_full_review import inspect as inspect_composition
    elif domain == 'p1_site_full':
        from c07_p1_site_contract_full_review import inspect as inspect_site
    elif domain == 'p1_environment_full':
        from c07_p1_environment_full_review import inspect as inspect_environment
    elif domain == 'p1_terrain_full':
        from c07_p1_terrain_full_review import inspect as inspect_terrain
    elif domain == 'camera_views_full':
        from c07_camera_views_full_review import inspect as inspect_camera_views
    elif domain == 'p4_lighting_player_full':
        from c07_p4_lighting_player_full_review import inspect as inspect_p4_lighting
    elif domain == 'p4_pbr_maps_full':
        from c07_p4_pbr_maps_full_review import inspect as inspect_pbr_maps
    elif domain == 'p4_material_macro_full':
        from c07_p4_material_macro_full_review import inspect as inspect_p4_material
    elif domain == 'p345_remaining_scoped':
        from c07_p345_remaining_original_review import inspect as inspect_remaining
    elif domain == 'p8_intersection_full':
        from c07_p8_intersection_full_review import inspect as inspect_intersections
    elif domain == 'p8_final_process_full':
        from c07_p8_final_process_full_review import inspect as inspect_final_process
    elif domain == 'p6_access_full':
        from c07_p6_access_full_review import inspect as inspect_access
    elif domain == 'p6_invisible_full':
        from c07_p6_invisible_collision_full_review import inspect as inspect_invisible
    else:
        raise NativeRuleEvidenceBlocked('C07_REPLAYER_NO_LITERAL_DOMAIN')
    from c07_mg0_individual import inspect_batch
    p5_review = inspect_p5_full(source_context, rule_id) if domain == 'p5_full' else None
    alpha_cost_review = (inspect_alpha_cost(source_context, rule_id)
                         if domain == 'p5_alpha_cost_full' else None)
    p1_blockout_review = (inspect_blockout(source_context, rule_id)
                          if domain == 'p1_blockout_full' else None)
    p1_structural_fix_review = (inspect_structural_fix(source_context, rule_id)
                                if domain == 'p1_structural_fix_full' else None)
    p1_spatial_review = (inspect_p1_spatial(source_context, rule_id)
                         if domain == 'p1_spatial' else None)
    p1_paths_review = (inspect_p1_paths(source_context, rule_id)
                       if domain == 'p1_paths_full' else None)
    p1_circulation_review = (inspect_circulation(source_context, rule_id)
                             if domain == 'p1_circulation_full' else None)
    p1_composition_review = (inspect_composition(source_context, rule_id)
                             if domain == 'p1_composition_full' else None)
    p1_site_review = (inspect_site(source_context, rule_id)
                      if domain == 'p1_site_full' else None)
    p1_environment_review = (inspect_environment(source_context, rule_id)
                             if domain == 'p1_environment_full' else None)
    p1_terrain_review = (inspect_terrain(source_context, rule_id)
                         if domain == 'p1_terrain_full' else None)
    camera_views_review = (inspect_camera_views(source_context, rule_id)
                           if domain == 'camera_views_full' else None)
    p4_lighting_review = (inspect_p4_lighting(source_context, rule_id)
                          if domain == 'p4_lighting_player_full' else None)
    p4_pbr_review = (inspect_pbr_maps(source_context, rule_id)
                     if domain == 'p4_pbr_maps_full' else None)
    p4_material_review = (inspect_p4_material(source_context, rule_id)
                          if domain == 'p4_material_macro_full' else None)
    p345_remaining_review = (inspect_remaining(source_context, rule_id)
                             if domain == 'p345_remaining_scoped' else None)
    p8_intersection_review = (inspect_intersections(source_context, rule_id)
                              if domain == 'p8_intersection_full' else None)
    p8_final_process_review = (inspect_final_process(source_context, rule_id)
                               if domain == 'p8_final_process_full' else None)
    p6_access_review = (inspect_access(source_context, rule_id)
                        if domain == 'p6_access_full' else None)
    p6_invisible_review = (inspect_invisible(source_context, rule_id)
                           if domain == 'p6_invisible_full' else None)
    full_review = next((review for review in
                        (alpha_cost_review, p1_structural_fix_review, p5_review, p1_spatial_review, p1_paths_review,
                         p1_circulation_review, p1_composition_review, p1_site_review, p1_environment_review, p1_terrain_review,
                         camera_views_review, p4_lighting_review,
                         p4_pbr_review, p4_material_review,
                         p345_remaining_review, p8_intersection_review,
                         p8_final_process_review,
                         p6_invisible_review,
                         p6_access_review, p1_blockout_review)
                        if review is not None), None)
    if full_review is not None:
        from c07_positive_native_process import _original_attempt
        _, tail, _, audit_sha = _original_attempt(
            inv, plan, controller, asset, step, work)
        report = {'rules': {rule_id: {
            'requirement_sha256': row['requirement_sha256'],
            'source_sha256': row['source_sha256'],
            'original_machine_checks': full_review['checks']}},
            'attempt_id': work['attempt_id'],
            'operation_sha256': work['operation_sha256'],
            'original_audit_sha256': audit_sha,
            'original_audit_tail': tail, 'advancement_authorized': False}
    else:
        report = inspect(inv, plan, controller, asset, step, work,
                         source_loader=loader)
    source = report['rules'][rule_id]
    checks = dict(source['original_native_measured_criteria'] if domain == 'p1'
                  else source['original_machine_checks'])
    topology_review = None
    if domain == 'topology' and rule_id in (
            'AAA-200-L-111', 'AAA-200-L-113', 'AAA-200-L-114'):
        from c07_p3_topology_full_review import inspect as review_topology
        topology_review = review_topology(source_context, rule_id)
        checks = topology_review['checks']
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
    if topology_review is not None:
        proof['original_topology_review'] = topology_review
    if p5_review is not None:
        proof['original_p5_full_review'] = p5_review
    if alpha_cost_review is not None:
        proof['original_p5_alpha_cost_review'] = alpha_cost_review
    if p1_spatial_review is not None:
        proof['original_p1_spatial_review'] = p1_spatial_review
    if p1_blockout_review is not None:
        proof['original_p1_blockout_review'] = p1_blockout_review
    if p1_structural_fix_review is not None:
        proof['original_p1_structural_fix_review'] = p1_structural_fix_review
    if p1_paths_review is not None:
        proof['original_p1_paths_access_review'] = p1_paths_review
    if p1_circulation_review is not None:
        proof['original_p1_circulation_review'] = p1_circulation_review
    if p1_composition_review is not None:
        proof['original_p1_composition_review'] = p1_composition_review
    if p1_site_review is not None:
        proof['original_p1_site_contract_review'] = p1_site_review
    if p1_environment_review is not None:
        proof['original_p1_environment_review'] = p1_environment_review
    if p1_terrain_review is not None:
        proof['original_p1_terrain_review'] = p1_terrain_review
    if camera_views_review is not None:
        proof['original_camera_views_review'] = camera_views_review
    if p4_lighting_review is not None:
        proof['original_p4_lighting_review'] = p4_lighting_review
    if p4_pbr_review is not None:
        proof['original_p4_pbr_review'] = p4_pbr_review
    if p4_material_review is not None:
        proof['original_p4_material_macro_review'] = p4_material_review
    if p345_remaining_review is not None:
        proof['original_p345_remaining_scoped_review'] = p345_remaining_review
    if p8_intersection_review is not None:
        proof['original_p8_intersection_review'] = p8_intersection_review
    if p8_final_process_review is not None:
        proof['original_p8_final_process_review'] = p8_final_process_review
    if p6_invisible_review is not None:
        proof['original_p6_invisible_collision_review'] = p6_invisible_review
    if p6_access_review is not None:
        proof['original_p6_access_review'] = p6_access_review
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
        'rule': {'result': (
                     'UNKNOWN' if (
                         (topology_review is not None and
                          not topology_review['evidence_complete']) or
                         (full_review is not None and
                          not full_review['evidence_complete']))
                     else ('PASS' if all(checks.values()) else 'FAIL')
                     if rule_id in FULL_LITERAL_REVIEWED else 'UNKNOWN'),
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

"""C07 P7 ten-literal original-byte replayers, on one immutable Controller audit.

Q161-166 test resource structure and actual relationships between the original
native-format sources. These six are source-decidable structural competencies.
Q167-170 additionally demand independent Sollumz/RAGE/CodeWalker/FiveM
provenance: their XML, screenshots, and producer logs are NOT that proof.
No reader in this module asserts MG0, owner approval or gameplay success.
"""
from c07_p7_rage_semantics import inspect as read_original_ten, IDS
from c07_positive_native_process import _original_attempt
from c07_native_source_rule_replayers import digest

STRUCTURAL = frozenset(IDS[:6])
CANDIDATE = frozenset(IDS[6:])
RULES = frozenset(IDS)
CRITERIA = {
    161: ('actual_resource_manifest_declares_gta5_map',
          'source_manifest_references_archetype_dictionary',
          'manifest_ytyp_entries_unique_and_confined_to_stream'),
    162: ('original_codewalker_drawable_name_parsed',
          'drawable_is_cross_referenced_by_original_archetype',
          'drawable_bound_to_exactly_one_original_archetype'),
    163: ('original_texture_dictionary_has_distinct_named_entries',
          'drawable_referenced_texture_names_resolve_in_dictionary',
          'every_original_drawable_texture_resolves_once'),
    164: ('original_archetype_names_and_asset_names_parsed',
          'archetype_asset_matches_actual_drawable_source',
          'all_placed_original_archetypes_have_drawable_binding'),
    165: ('original_ymap_entity_positions_parsed',
          'all_placed_archetypes_resolve_in_original_ytyp',
          'all_original_map_positions_match_current_codewalker_source'),
    166: ('original_ybn_bound_children_structurally_parsed',
          'original_ytyp_and_ybn_source_both_present',
          'original_collision_children_have_supported_bound_types_and_native_coverage'),
    167: ('registered_blend_and_glb_bytes_match_original_sollumz_trace',
          'independent_sollumz_execution_provenance_confirmed',
          'independent_sollumz_execution_provenance'),
    168: ('original_export_vertex_attributes_have_position_normal_uv',
          'original_drawable_shader_names_match_pre_d_allowlist',
          'actual_native_vertex_normals_normalized_and_uv_finite'),
    169: ('codewalker_report_entity_positions_match_original_ymap',
          'source_lod_distances_and_three_original_views_recorded',
          'three_original_views_have_distinct_decoded_pixels'),
    170: ('source_fivem_log_contains_numeric_samples',
          'independent_in_game_execution_and_owner_provenance',
          'independent_fivem_engine_execution_provenance'),
}

class P7SourceBlocked(ValueError):
    pass

def need(ok,why):
    if not ok:
        raise P7SourceBlocked(why)

def inspect(source_context,rule_id):
    need(type(source_context) is dict and
         set(source_context)=={'inventory','plan','controller','asset',
                               'step','work','source_loader'} and
         rule_id in RULES,
         'C07_P7_TEN_TRUSTED_CONTEXT_AND_LITERAL_REQUIRED')
    inv,plan,controller,asset,step,work,loader=(
        source_context[k] for k in ('inventory','plan','controller',
                                    'asset','step','work','source_loader'))
    # Original Q source reader checks all ten canonical literals, their
    # catalog hashes, SHA-pinned pre-D artifact roles, GLB binary geometry,
    # XML cross-references, current master and append-only operation audit.
    original=read_original_ten(inv,plan,controller,asset,step,work,
                              source_loader=loader)
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(original['original_audit_sha256']==audit_sha and
         original['original_audit_tail']==tail and
         original['attempt_id']==work['attempt_id'] and
         original['operation_sha256']==work['operation_sha256'] and
         state.get('last_audit_hash')==tail and
         digest(controller.master.read_bytes())==work['master_sha256'] and
         (state.get('active_step') or {}).get('step')==step,
         'C07_P7_TEN_CURRENT_CONTROLLER_AUDIT_REQUIRED')
    number=int(rule_id.rsplit('-',1)[1])
    measured=original['rules'][rule_id]
    source=measured['original_machine_checks']
    cross=measured['original_cross_source_semantic']
    criteria=CRITERIA[number]
    need(type(source) is dict and len(source)==2 and
         type(cross) is dict and len(cross)==1 and
         set(source)|set(cross)==set(criteria) and
         all(type(v) is bool for v in list(source.values())+list(cross.values())) and
         measured['requirement_sha256']==
             inv['rules'][rule_id]['requirement_sha256'] and
         measured['source_sha256']==inv['rules'][rule_id]['source_sha256'] and
         measured['exact_attempt_id']==work['attempt_id'] and
         measured['operation_sha256']==work['operation_sha256'] and
         measured['full_rule_semantics']=='UNKNOWN' and
         measured['individual_mg0']=='UNKNOWN' and
         measured['advancement_authorized'] is False,
         'C07_P7_TEN_EXACT_ORIGINAL_SOURCE_CHECKS_REQUIRED')
    checks={k:source[k] if k in source else cross[k] for k in criteria}
    complete=rule_id in STRUCTURAL and all(checks.values())
    # Shader allowlist is a pre-D claim, not engine support. CodeWalker
    # output and Sollumz/FiveM-labelled JSON are not independent execution.
    need(not (rule_id in CANDIDATE and complete),
         'C07_P7_TEN_EXTERNAL_PROVENANCE_MUST_REMAIN_UNKNOWN')
    return {'rule_id':rule_id,'checks':checks,
            'evidence_complete':complete,
            'source_scope':'FULL_STRUCTURAL_ORIGINAL' if complete else
                           'UNKNOWN_OR_UNATTESTED_EXTERNAL_EXECUTION',
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'individual_mg0':'UNKNOWN','owner_acceptance':'UNKNOWN',
            'fivem_runtime':'UNKNOWN','advancement_authorized':False}

"""C07 R144: 30 distinct P1 design/site/blockout native domain evidence probes.

Canonical original AAA-200-D-031..F-060 source texts are pinned byte-for-byte;
actual Controller audit, artifact bytes, native GLB positions and image bytes
are independently read. Machine facts != artistic quality, valid FiveM scale,
world transforms, copyright approval, individual MG0 or work authorization.
"""
import hashlib
import json
import math
import re
from pathlib import Path

from c07_positive_native_process import _original_attempt, _registered_artifacts, sha
from c07_a10_c10_original_evidence import original_image
from c07_native_output_oracle import read_mesh_geometry, OriginalGeometryBlocked
from c07_positive200_evidence import R122_FROZEN_IDS

SCHEMA='gg-c07-r144-thirty-p1-original-domain-v1'
TEXT={
  "31": "Identificare il linguaggio visivo dell’intero progetto.",
  "32": "Mantenere coerenza tra asset appartenenti alla stessa area.",
  "33": "Definire palette dei colori e gerarchia dei materiali.",
  "34": "Studiare il rapporto tra pieni e vuoti.",
  "35": "Controllare silhouette e forme principali.",
  "36": "Progettare punti focali leggibili.",
  "37": "Evitare ripetizioni visive troppo evidenti.",
  "38": "Utilizzare variazioni credibili senza perdere coerenza stilistica.",
  "39": "Valutare la composizione dal punto di vista del giocatore.",
  "40": "Verificare che ogni elemento contribuisca alla scena e non sia semplice riempitivo.",
  "41": "Stabilire le dimensioni reali dello spazio disponibile.",
  "42": "Definire sistemi di coordinate, orientamento e origini.",
  "43": "Verificare distanze e rapporti dimensionali tra gli edifici.",
  "44": "Identificare percorsi principali e secondari.",
  "45": "Separare aree accessibili e non accessibili.",
  "46": "Considerare visuali, ingressi e uscite.",
  "47": "Prevedere gli ingombri delle strutture prima di costruirle.",
  "48": "Controllare la relazione tra strutture e terreno.",
  "49": "Verificare eventuali sovrapposizioni con asset già presenti.",
  "50": "Conservare gli elementi progettuali bloccati senza spostarli arbitrariamente.",
  "51": "Creare prima le forme principali con geometria semplice.",
  "52": "Verificare scala e proporzioni rispetto al progetto.",
  "53": "Controllare che i modelli siano orientati correttamente.",
  "54": "Verificare gli allineamenti tra moduli e strutture.",
  "55": "Controllare gli spazi attraversabili dal giocatore.",
  "56": "Provare più inquadrature, incluse quelle dall’alto.",
  "57": "Identificare problemi di composizione prima dei dettagli.",
  "58": "Verificare i collegamenti tra elementi adiacenti.",
  "59": "Correggere errori strutturali prima della modellazione definitiva.",
  "60": "Non avanzare al dettaglio se il blockout non soddisfa i requisiti."
}
IDS=tuple('AAA-200-'+('D' if n<=40 else 'E' if n<=50 else 'F')+
    '-'+str(n).zfill(3) for n in range(31,61))
REQUIRED_PHASES=('P1','P2','P3','P4','P5','P6','P7','P8','VERIFY','G2','G3','G4','DELIVERY')
class P1EvidenceBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise P1EvidenceBlocked(why)
def has_text(v):return type(v) is str and bool(v.strip())
def text_list(v):return type(v) is list and bool(v) and all(has_text(x) for x in v)
def positive(v):return type(v) in (int,float) and math.isfinite(v) and v>0
def valid_sha(v):return type(v) is str and bool(re.fullmatch(r'[a-f0-9]{64}',v))
def pairs(v):return type(v) is list and len(v)>=2 and all(
    type(x) is list and len(x)>=2 and all(type(c) in (float,int) and math.isfinite(c) for c in x[:2]) for x in v)
def jbytes(raw):
    if type(raw) is not bytes or len(raw)>2_000_000:return {}
    try:
        out=json.loads(raw)
        return out if type(out) is dict else {}
    except (TypeError,ValueError,UnicodeDecodeError):return {}

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and
         inventory.get('schema')=='gg-effective-family-inventory-v1' and
         inventory.get('rule_count')==763 and
         plan.get('phase') in REQUIRED_PHASES and
         work.get('phase') in REQUIRED_PHASES and
         len(IDS)==30 and set(IDS).isdisjoint(set(R122_FROZEN_IDS)) and
         callable(source_loader),
         'R144_P1_ORIGINAL_PHASE_OR_30_SOURCE_IDS_REQUIRED')
    source=inventory.get('source_digests',{}).get('aaa_catalog')
    need(valid_sha(source),'R144_CANONICAL_CATALOG_NOT_PINNED')
    for n in range(31,61):
        rid='AAA-200-'+('D' if n<=40 else 'E' if n<=50 else 'F')+'-'+str(n).zfill(3)
        r=inventory['rules'].get(rid,{})
        clause=TEXT[str(n)]
        need(r.get('family')=='AAA-200' and r.get('catalog_number')==n and
             r.get('catalog_phase')=='P1' and
             r.get('catalog_section')==('D' if n<=40 else 'E' if n<=50 else 'F') and
             r.get('requirement')==clause and
             r.get('requirement_sha256')==sha(clause.encode('utf-8')) and
             r.get('source_sha256')==source,
             'R144_CANONICAL_P1_RULE_CHANGED:'+rid)
    rows,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R144_MASTER_OR_CURRENT_ORIGINAL_AUDIT_CHANGED')
    artifact_rows=_registered_artifacts(rows,state,step,source_loader,work)
    items={}
    for role,path,digest,raw in artifact_rows:
        need(role not in items,'R144_DUPLICATE_ORIGINAL_ARTIFACT_ROLE:'+role)
        items[role]={'path':path,'sha256':digest,'bytes':raw}
    def exists(role):return role in items and len(items[role]['bytes'])>0 and sha(items[role]['bytes'])==items[role]['sha256']
    def jf(role):return jbytes(items[role]['bytes']) if exists(role) else {}
    def im(role):return original_image(items[role]['bytes']) if exists(role) else None
    def geom(role):
        if not exists(role) or not items[role]['path'].lower().endswith('.glb'):return None
        try:return read_mesh_geometry(items[role]['bytes'])
        except (OriginalGeometryBlocked,ValueError,TypeError,KeyError,IndexError):return None
    actual=geom('NATIVE_EXPORT')
    secondary=geom('SECONDARY_EXPORT')
    baseline=geom('BASELINE_SNAPSHOT')
    scene=jf('P1_SCENE_CONTRACT')
    palette=jf('P1_PALETTE')
    paths=jf('P1_PATHS_GEOJSON')
    qa=jf('P1_QA_REPORT')
    field=jf('P1_TERRAIN_SAMPLES')
    plan_source=plan.get('p1_evidence_contract',{})
    if type(plan_source) is not dict:plan_source={}
    sha_pins=plan_source.get('original_artifact_sha256',{})
    if type(sha_pins) is not dict:sha_pins={}
    bound={role:role in items and sha_pins.get(role)==items[role]['sha256']
           for role in items}
    def source(role):return bool(bound.get(role))
    def photo(role):return im(role) if source(role) else None
    c_scene=scene if source('P1_SCENE_CONTRACT') else {}
    c_palette=palette if source('P1_PALETTE') else {}
    c_paths=paths if source('P1_PATHS_GEOJSON') else {}
    c_qa=qa if source('P1_QA_REPORT') else {}
    c_field=field if source('P1_TERRAIN_SAMPLES') else {}
    renderer={'FRONT':photo('VISUAL_VIEW_FRONT'),'LEFT':photo('VISUAL_VIEW_LEFT'),
       'RIGHT':photo('VISUAL_VIEW_RIGHT'),'TOP':photo('VISUAL_VIEW_TOP')}
    multiple_views=all(renderer.values()) and len({x['sha256'] for x in renderer.values()})==4
    current=[r for r in rows if r.get('step')==step]
    audit=lambda kind:any(r.get('event')==kind for r in current)
    geo=c_paths.get('features')
    path_lines=type(geo) is list and bool(geo) and all(
       type(e) is dict and type(e.get('geometry')) is dict and
       e['geometry'].get('type')=='LineString' and
       pairs(e['geometry'].get('coordinates')) for e in geo)
    zones=c_paths.get('zones')
    polygon_zones=type(zones) is list and bool(zones) and all(
       type(z) is dict and text_list(z.get('allowed_actors')) and
       pairs(z.get('polygon')) for z in zones)
    bbox=actual is not None
    bounds_ok=bbox and all(math.isfinite(x) for x in actual['bbox_min']+actual['bbox_max'])
    origin=c_scene.get('origin_xyz')
    valid_origin=type(origin) is list and len(origin)==3 and all(type(x) in (int,float) and math.isfinite(x) for x in origin)
    envelope=c_scene.get('expected_bbox_local')
    bbox_contract=(type(envelope) is dict and
       type(envelope.get('min')) is list and type(envelope.get('max')) is list and
       len(envelope['min'])==len(envelope['max'])==3 and
       all(type(x) in (int,float) and math.isfinite(x) for x in envelope['min']+envelope['max']))
    measured_envelope=bbox_contract and bounds_ok and all(
       abs(actual['bbox_min'][axis]-envelope['min'][axis])<=0.1 and
       abs(actual['bbox_max'][axis]-envelope['max'][axis])<=0.1
       for axis in range(3))
    footprint=c_scene.get('footprint_m')
    measured_footprint=(bounds_ok and type(footprint) is list and
        len(footprint)==2 and all(positive(t) for t in footprint) and
        abs(actual['bbox_max'][0]-actual['bbox_min'][0]-footprint[0])<=0.1 and
        abs(actual['bbox_max'][1]-actual['bbox_min'][1]-footprint[1])<=0.1)
    contract_epoch=c_scene.get('source_scope')
    sample_z=c_field.get('samples_z')
    terrain_samples=(type(sample_z) is list and len(sample_z)>=3 and
         all(type(n) in (int,float) and math.isfinite(n) for n in sample_z))
    known_meshes=bool(actual and actual['mesh_definitions']>0 and actual['triangles']>0)
    new_bytes=bool(actual and baseline and items['NATIVE_EXPORT']['sha256']!=
        items['BASELINE_SNAPSHOT']['sha256'])
    labels=c_scene.get('named_anchors')
    anchors=(type(labels) is dict and len(labels)>=2 and
        all(has_text(k) and type(v) is list and len(v)==3 and
        all(type(x) in (int,float) and math.isfinite(x) for x in v)
        for k,v in labels.items()))
    locked=c_scene.get('locked_original_sha256')
    lock_verified=(valid_sha(locked) and source('SOURCE_EDITABLE') and
        locked==items['SOURCE_EDITABLE']['sha256'])
    failures=c_qa.get('open_findings')
    real_issues=type(failures) is list and bool(failures)
    source_img=photo('REFERENCE_IMAGE')
    material_img=photo('IMAGE_MATERIAL')
    checks={
      31:{'original_style_language_named_pre_D':has_text(c_scene.get('style_language')),
          'original_style_reference_image_decoded':source_img is not None,
          'source_reference_asset_sha_bound':source('REFERENCE_IMAGE')},
      32:{'original_peer_area_reference_image_reopened':photo('SCENE_PEER_REFERENCE') is not None,
          'current_scene_original_front_view_decoded':renderer['FRONT'] is not None,
          'scene_original_area_identity_named':has_text(c_scene.get('area_id'))},
      33:{'original_palette_source_bytes_authenticated':source('P1_PALETTE'),
          'palette_color_slots_declared':type(c_palette.get('colors')) is list and len(c_palette['colors'])>=2,
          'real_material_reference_image_decoded':material_img is not None},
      34:{'actual_local_geometry_AABB_recomputed':bool(bounds_ok),
          'original_void_space_polygons_declared':type(c_scene.get('void_zones')) is list and bool(c_scene['void_zones']),
          'local_bbox_matches_original_scope':bool(measured_envelope)},
      35:{'native_export_scene_mesh_triangles_parsed':known_meshes,
          'real_front_view_raster_decoded':renderer['FRONT'] is not None,
          'original_silhouette_reference_raster_decoded':source_img is not None},
      36:{'pre_D_focal_anchor_positions_recorded':anchors,
          'current_original_camera_frame_decoded':renderer['FRONT'] is not None,
          'actual_local_AABB_available_for_anchor_inspection':bool(bounds_ok)},
      37:{'original_repetition_policy_listed':text_list(c_scene.get('repeat_patterns')),
          'nonidentical_source_images_confirmed':bool(multiple_views),
          'independent_visual_qa_issue_log_present':source('P1_QA_REPORT')},
      38:{'original_variation_rules_declared':text_list(c_scene.get('variation_rules')),
          'more_than_one_palette_original_entry':type(c_palette.get('colors')) is list and len(c_palette['colors'])>=2,
          'actual_material_reference_pixels_decoded':material_img is not None},
      39:{'original_player_height_numeric':positive(c_scene.get('player_height_m')),
          'actual_front_camera_image_decoded':renderer['FRONT'] is not None,
          'original_player_view_camera_definition':type(c_scene.get('player_camera')) is dict and bool(c_scene['player_camera'])},
      40:{'original_scene_component_reason_listed':text_list(c_scene.get('component_roles')),
          'actual_nonempty_native_glb_triangles_verified':known_meshes,
          'original_nondecorative_qa_check_read':source('P1_QA_REPORT')},
      41:{'original_footprint_dimensions_declared':type(footprint) is list and len(footprint)==2 and all(positive(t) for t in footprint),
          'actual_native_local_footprint_measured':bool(bounds_ok),
          'footprint_matches_registered_local_geometry':bool(measured_footprint)},
      42:{'original_xyz_coordinate_origin_declared':valid_origin,
          'original_coordinate_basis_named':has_text(c_scene.get('coordinate_basis')),
          'native_local_GLTF_positions_available':bool(bounds_ok)},
      43:{'two_distinct_original_GLTF_asset_bounds_read':bool(actual and secondary),
          'planned_building_separation_m_declared':positive(c_scene.get('building_clearance_m')),
          'original_registered_secondary_binary_bound':source('SECONDARY_EXPORT')},
      44:{'pre_D_path_line_strings_decoded':bool(path_lines),
          'main_and_secondary_path_ids_named':text_list(c_paths.get('path_classes')),
          'original_path_geojson_sha_pinned':source('P1_PATHS_GEOJSON')},
      45:{'original_accessible_zone_polygons_parsed':bool(polygon_zones),
          'player_access_class_named_before_D':text_list(c_scene.get('allowed_zone_classes')),
          'original_access_zone_file_sha_pinned':source('P1_PATHS_GEOJSON')},
      46:{'original_entrance_exit_labels_defined':text_list(c_scene.get('entrances')) and text_list(c_scene.get('exits')),
          'actual_original_front_view_raster_decoded':renderer['FRONT'] is not None,
          'native_original_local_geometry_read':bool(bounds_ok)},
      47:{'expected_original_structural_envelope_declared':bool(bbox_contract),
          'native_original_bounds_recomputed':bool(bounds_ok),
          'actual_original_native_bbox_matches_envelope':bool(measured_envelope)},
      48:{'original_terrain_sample_file_sha_pinned':source('P1_TERRAIN_SAMPLES'),
          'original_terrain_elevations_numeric':bool(terrain_samples),
          'native_local_z_span_recomputed':bool(bounds_ok)},
      49:{'two_native_source_AABBs_independently_reopened':bool(actual and secondary),
          'independent_overlap_qa_report_original_bytes':source('P1_QA_REPORT'),
          'unverified_overlap_not_called_collision_pass':not bool(c_qa.get('collision_approved',False))},
      50:{'original_protected_editable_source_reopened':source('SOURCE_EDITABLE'),
          'locked_original_sha_matches_real_editable_file':bool(lock_verified),
          'no_owner_authorization_fabricated_from_lock':state.get('delivery_status')!='DELIVERABLE'},
      51:{'original_simple_blockout_binary_reopened':bool(bounds_ok),
          'pre_D_blockout_triangle_budget_numeric':type(c_scene.get('blockout_triangle_budget')) is int and c_scene['blockout_triangle_budget']>0,
          'actual_GLTF_triangle_count_within_budget':bool(known_meshes and type(c_scene.get('blockout_triangle_budget')) is int and actual['triangles']<=c_scene['blockout_triangle_budget'])},
      52:{'actual_original_local_extents_independently_decoded':bool(bounds_ok),
          'original_target_local_bounds_declared':bool(bbox_contract),
          'original_local_bounds_match_pre_D_expected_extent':bool(measured_envelope)},
      53:{'native_geometry_from_actual_GLTF_vertex_bytes':bool(bounds_ok),
          'original_rotation_target_contract_stored':type(c_scene.get('orientation_xyz_deg')) is list and len(c_scene['orientation_xyz_deg'])==3,
          'independent_top_camera_original_raster_present':renderer['TOP'] is not None},
      54:{'original_named_anchor_coordinates_verified_as_numeric':anchors,
          'native_export_original_local_bbox_verified':bool(bounds_ok),
          'real_top_down_qa_raster_reopened':renderer['TOP'] is not None},
      55:{'original_access_zone_paths_geometrically_parsed':bool(path_lines and polygon_zones),
          'player_width_source_contract_numeric':positive(c_scene.get('player_width_m')),
          'native_blockout_local_geometry_present':bool(bounds_ok)},
      56:{'real_original_four_views_decoded':bool(multiple_views),
          'top_original_raster_decoded':renderer['TOP'] is not None,
          'camera_target_definitions_declared':type(c_scene.get('cameras')) is dict and len(c_scene['cameras'])>=4},
      57:{'original_blockout_issue_file_reopened':source('P1_QA_REPORT'),
          'original_defect_entries_not_silent':bool(real_issues),
          'native_original_geometry_present_for_review':bool(bounds_ok)},
      58:{'original_two_GLTF_adjacent_geometry_files_read':bool(actual and secondary),
          'original_linking_anchor_contract_present':anchors,
          'original_link_QA_report_source_sha_bound':source('P1_QA_REPORT')},
      59:{'original_open_structural_defect_entries_read':bool(real_issues),
          'original_baseline_binary_reopened':bool(baseline),
          'native_blockout_output_changed_vs_old_binary':bool(new_bytes)},
      60:{'original_pre_D_blockout_acceptance_criteria_listed':text_list(c_scene.get('blockout_acceptance_criteria')),
          'native_original_blockout_geometry_reopened':bool(known_meshes),
          'original_QA_blockout_result_does_not_fake_owner_approval':not bool(c_qa.get('owner_approved',False))}
    }
    need(len(checks)==30 and
         len({key for group in checks.values() for key in group})==90 and
         all(type(group) is dict and len(group)==3 and all(type(v) is bool
            for v in group.values()) for group in checks.values()),
         'R144_NINETY_NAMED_PER_SOURCE_DOMAIN_PROBES_INCOMPLETE')
    outcomes={}
    for n,criteria in checks.items():
        rid='AAA-200-'+('D' if n<=40 else 'E' if n<=50 else 'F')+'-'+str(n).zfill(3)
        canonical=inventory['rules'][rid]
        outcomes[rid]={'rule_id':rid,'source_sha256':canonical['source_sha256'],
          'requirement_sha256':canonical['requirement_sha256'],
          'original_native_measured_criteria':criteria,
          'positive_domain_observations':sorted(k for k,v in criteria.items() if v),
          'missing_native_measures':sorted(k for k,v in criteria.items() if not v),
          'native_scope':'SOURCE_SCOPE_OBSERVED' if all(criteria.values()) else 'UNKNOWN',
          'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
          'artistic_approval':'UNKNOWN','advancement_authorized':False}
    return {'schema':SCHEMA,'source_rules_examined':30,'native_domain_criteria':90,
       'original_catalog_sha256':source,
       'asset':asset,'step':step,'master_sha256':work['master_sha256'],
       'attempt_id':work['attempt_id'],'operation_sha256':work['operation_sha256'],
       'original_audit_sha256':audit_sha,'original_audit_tail':tail,
       'source_scope_observed':sum(item['native_scope']=='SOURCE_SCOPE_OBSERVED' for item in outcomes.values()),
       'full_semantic_passes':0,'individual_mg0_passes':0,'advancement_authorized':False,
       'rules':outcomes}

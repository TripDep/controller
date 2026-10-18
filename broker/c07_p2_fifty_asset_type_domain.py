"""C07 R145: 50 literal P2 source/type-specific technical evidence probes.

Read original canonical source clauses, exact Controller work audit, native GLB,
original survey and image bytes; author-defined expectations are contracts,
never an independent certification. For each of architecture, organic,
vegetation, terrain inspect only genuinely applicable rules. The other types
are NOT_APPLICABLE_ASSET_TYPE, never semantic PASS or MG0.
"""
import hashlib
import json
import math
import re
from pathlib import Path
from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from c07_native_output_oracle import read_mesh_geometry,OriginalGeometryBlocked
from c07_a10_c10_original_evidence import original_image
from c07_positive200_evidence import R122_FROZEN_IDS
TEXT={
  "61": [
    "Utilizzare geometria coerente con la forma reale dell’oggetto.",
    "architecture"
  ],
  "62": [
    "Costruire silhouette corrette prima dei dettagli secondari.",
    "architecture"
  ],
  "63": [
    "Utilizzare bevel con dimensioni realistiche.",
    "architecture"
  ],
  "64": [
    "Evitare spigoli involontariamente taglienti o arrotondati.",
    "architecture"
  ],
  "65": [
    "Controllare normali e direzione delle superfici.",
    "architecture"
  ],
  "66": [
    "Prevenire geometria duplicata o inutilmente sovrapposta.",
    "architecture"
  ],
  "67": [
    "Individuare e correggere compenetrazioni.",
    "architecture"
  ],
  "68": [
    "Mantenere trasformazioni, pivot e origini coerenti.",
    "architecture"
  ],
  "69": [
    "Utilizzare tecniche modulari quando migliorano precisione e produttività.",
    "architecture"
  ],
  "70": [
    "Conservare la geometria editabile fino alla validazione delle forme principali.",
    "architecture"
  ],
  "71": [
    "Studiare la logica costruttiva dell’edificio.",
    "architecture"
  ],
  "72": [
    "Riprodurre correttamente travi, pilastri e strutture portanti visibili.",
    "architecture"
  ],
  "73": [
    "Verificare l’effettivo collegamento tra gli elementi.",
    "architecture"
  ],
  "74": [
    "Controllare simmetrie quando richieste dal progetto.",
    "architecture"
  ],
  "75": [
    "Inserire asimmetrie soltanto quando intenzionali.",
    "architecture"
  ],
  "76": [
    "Modellare coperture con pendenze e curvature coerenti.",
    "architecture"
  ],
  "77": [
    "Costruire raccordi credibili tra tetti, pareti e colonne.",
    "architecture"
  ],
  "78": [
    "Evitare il cosiddetto effetto Lego: volumi semplicemente sovrapposti e giunzioni artificiali.",
    "architecture"
  ],
  "79": [
    "Curare proporzioni e dettagli di porte, finestre, scale, corrimano e ornamenti.",
    "architecture"
  ],
  "80": [
    "Verificare la struttura sia singolarmente sia inserita nel contesto architettonico.",
    "architecture"
  ],
  "81": [
    "Studiare l’aspetto naturale dell’elemento da riprodurre.",
    "organic"
  ],
  "82": [
    "Partire dalle forme organiche principali.",
    "organic"
  ],
  "83": [
    "Utilizzare sculpting o modellazione procedurale quando appropriato.",
    "organic"
  ],
  "84": [
    "Evitare distribuzioni casuali prive di logica naturale.",
    "organic"
  ],
  "85": [
    "Introdurre variazioni di silhouette e superficie.",
    "organic"
  ],
  "86": [
    "Modellare erosioni coerenti con il materiale rappresentato.",
    "organic"
  ],
  "87": [
    "Evitare rocce ripetitive o dall’aspetto artificiale.",
    "organic"
  ],
  "88": [
    "Verificare che i punti di contatto con il terreno siano credibili.",
    "organic"
  ],
  "89": [
    "Ottimizzare la geometria preservando le caratteristiche visive importanti.",
    "organic"
  ],
  "90": [
    "Controllare la composizione dei gruppi di rocce su scala ravvicinata e panoramica.",
    "organic"
  ],
  "91": [
    "Studiare specie botaniche realmente compatibili con l’ambiente.",
    "vegetation"
  ],
  "92": [
    "Verificare altezza, struttura e silhouette della pianta.",
    "vegetation"
  ],
  "93": [
    "Costruire tronco e rami con gerarchia naturale.",
    "vegetation"
  ],
  "94": [
    "Distribuire i rami secondo una struttura botanicamente plausibile.",
    "vegetation"
  ],
  "95": [
    "Utilizzare foglie modellate, alpha cards o combinazioni appropriate al target.",
    "vegetation"
  ],
  "96": [
    "Preparare texture di foglie con trasparenza corretta.",
    "vegetation"
  ],
  "97": [
    "Evitare chiome piatte o con ripetizioni evidenti.",
    "vegetation"
  ],
  "98": [
    "Prevedere varianti di alberi, cespugli, bambù e piante ornamentali.",
    "vegetation"
  ],
  "99": [
    "Preparare livelli di dettaglio adatti alla distanza.",
    "vegetation"
  ],
  "100": [
    "Verificare effettivamente nel motore il movimento del vento e il comportamento dei materiali.",
    "vegetation"
  ],
  "101": [
    "Partire da dati affidabili delle quote del terreno.",
    "terrain"
  ],
  "102": [
    "Non inventare quote, pendenze o profondità mancanti.",
    "terrain"
  ],
  "103": [
    "Separare terreno naturale, superfici costruite e superfici d’acqua.",
    "terrain"
  ],
  "104": [
    "Modellare variazioni naturali senza produrre rilievi arbitrari.",
    "terrain"
  ],
  "105": [
    "Evitare sentieri dall’andamento eccessivamente regolare e artificiale.",
    "terrain"
  ],
  "106": [
    "Progettare raccordi corretti tra sentieri, scale e ponti.",
    "terrain"
  ],
  "107": [
    "Costruire sponde con transizioni credibili.",
    "terrain"
  ],
  "108": [
    "Verificare il contatto tra acqua, terreno, rocce e strutture.",
    "terrain"
  ],
  "109": [
    "Controllare ponti, bordi, fondali e superfici percorribili rispetto alle quote note.",
    "terrain"
  ],
  "110": [
    "Testare visivamente e tecnicamente l’ambiente con l’acqua inserita nella scena.",
    "terrain"
  ]
}
IDS=tuple('AAA-200-'+chr(ord('G')+(n-61)//10)+'-'+str(n).zfill(3)
    for n in range(61,111))
SCHEMA='gg-c07-r145-fifty-p2-source-type-native-v1'
DUE=('P2','P3','P4','P5','P6','P7','P8','VERIFY','G2','G3','G4','DELIVERY')
class SourceBlocked(ValueError):pass
def need(b,reason):
    if not b:raise SourceBlocked(reason)
def nonempty(x):return type(x) is str and bool(x.strip())
def listed(x):return type(x) is list and bool(x) and all(nonempty(v) for v in x)
def npos(x):return type(x) in (int,float) and math.isfinite(x) and x>0
def dict_nonempty(x):return type(x) is dict and bool(x)
def aabb(g):return type(g) is dict and all(k in g for k in ('bbox_min','bbox_max','triangles'))
def binary_json(raw):
    if type(raw) is not bytes or len(raw)>2_000_000:return {}
    try:
        x=json.loads(raw)
        return x if type(x) is dict else {}
    except (UnicodeError,ValueError,TypeError):return {}

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get('schema')==
        'gg-effective-family-inventory-v1' and
        inventory.get('rule_count')==763 and
        plan.get('phase') in DUE and work.get('phase') in DUE and
        plan.get('asset_type')==work.get('asset_type') and
        work.get('asset_type') in ('architecture','organic','vegetation','terrain') and
        callable(source_loader) and len(IDS)==50 and
        set(IDS).isdisjoint(set(R122_FROZEN_IDS)),
        'R145_CANONICAL_P2_OR_TYPE_UNTRUSTED')
    catalog=inventory.get('source_digests',{}).get('aaa_catalog')
    need(type(catalog) is str and re.fullmatch('[a-f0-9]{64}',catalog),
         'R145_SOURCE_CATALOG_SHA_MISSING')
    for n in range(61,111):
        rid='AAA-200-'+chr(ord('G')+(n-61)//10)+'-'+str(n).zfill(3)
        item=inventory['rules'].get(rid,{})
        text,kind=TEXT[str(n)]
        need(item.get('family')=='AAA-200' and
             item.get('catalog_number')==n and
             item.get('catalog_section')==chr(ord('G')+(n-61)//10) and
             item.get('catalog_phase')=='P2' and
             item.get('asset_type')==kind and
             item.get('source_sha256')==catalog and
             item.get('requirement')==text and
             item.get('requirement_sha256')==sha(text.encode('utf-8')),
             'R145_CANONICAL_EXACT_P2_RULE_CHANGED:'+rid)
    rows,tail,state,audit_sha=_original_attempt(inventory,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R145_ORIGINAL_MASTER_OR_AUDIT_CHANGED')
    entries=_registered_artifacts(rows,state,step,source_loader,work)
    files={}
    for role,path,source_hash,bytes_ in entries:
        need(role not in files,'R145_DUPLICATE_ORIGINAL_ARTIFACT_ROLE:'+role)
        files[role]=(path,source_hash,bytes_)
    pins=plan.get('p2_evidence_contract',{})
    if type(pins) is not dict:pins={}
    registered_shas=pins.get('original_artifact_sha256',{})
    if type(registered_shas) is not dict:registered_shas={}
    def exists(role):
        return (role in files and registered_shas.get(role)==files[role][1] and
                type(files[role][2]) is bytes and
                sha(files[role][2])==files[role][1])
    def d(role):return binary_json(files[role][2]) if exists(role) else {}
    def g(role):
        if not exists(role) or not files[role][0].lower().endswith('.glb'):return None
        try:return read_mesh_geometry(files[role][2])
        except (OriginalGeometryBlocked,ValueError,IndexError,TypeError,KeyError):return None
    def im(role):
        return original_image(files[role][2]) if exists(role) else None
    geom=g('NATIVE_EXPORT')
    comparison=g('SECONDARY_EXPORT')
    previous=g('BASELINE_SNAPSHOT')
    architecture=d('P2_ARCH_CONTRACT')
    organic=d('P2_ORGANIC_CONTRACT')
    flora=d('P2_BOTANICAL_CONTRACT')
    terrain=d('P2_TERRAIN_CONTRACT')
    issues=d('P2_QA_REPORT')
    survey=d('P2_SURVEY')
    ref=im('REFERENCE_IMAGE')
    front=im('VISUAL_VIEW_FRONT')
    side=im('VISUAL_VIEW_SIDE')
    above=im('VISUAL_VIEW_TOP')
    below=im('VISUAL_VIEW_UNDERSIDE')
    leaf=im('P2_LEAF_CARD_PNG')
    current=[r for r in rows if r.get('step')==step]
    event=lambda name:any(r.get('event')==name for r in current)
    nonzero=aabb(geom) and geom['triangles']>0
    zspan=(geom['bbox_max'][2]-geom['bbox_min'][2]) if nonzero else None
    xspan=(geom['bbox_max'][0]-geom['bbox_min'][0]) if nonzero else None
    prev_ok=aabb(previous) and previous['triangles']>0
    pixel_set=bool(ref and front and side and above)
    original_geometry_source=exists('SOURCE_EDITABLE')
    glb_changed=bool(nonzero and prev_ok and files['NATIVE_EXPORT'][1]!=files['BASELINE_SNAPSHOT'][1])
    triangle_budget=architecture.get('triangle_budget')
    budget_valid=type(triangle_budget) is int and triangle_budget>0
    rock_budget=organic.get('triangle_budget')
    flora_budget=flora.get('triangle_budget')
    terrain_budget=terrain.get('triangle_budget')
    survey_rows=survey.get('samples')
    survey_valid=(type(survey_rows) is list and len(survey_rows)>=4 and
         all(type(x) is dict and all(type(x.get(k)) in (int,float) and
             math.isfinite(x[k]) for k in ('x','y','z')) for x in survey_rows))
    water_z=terrain.get('water_level_z')
    real_water=type(water_z) in (float,int) and math.isfinite(water_z)
    issue_ids=issues.get('open_issues')
    result_checks={
      61:{'native_original_hardsurface_triangle_bytes_reparsed':bool(nonzero),
          'original_target_reference_raster_decoded':ref is not None},
      62:{'actual_original_model_local_envelope_read':bool(nonzero),
          'front_reference_and_actual_front_rasters_decoded':bool(ref and front)},
      63:{'original_explicit_bevel_radius_mm_in_arch_contract':npos(architecture.get('bevel_radius_mm')),
          'original_native_geometry_read_for_edge_inspection':bool(nonzero)},
      64:{'source_original_edge_policy_named':listed(architecture.get('edge_preservation_rules')),
          'original_closeup_front_image_decoded':front is not None},
      65:{'real_GLTF_vertex_position_data_parsed':bool(nonzero),
          'native_original_normals_QA_receipt_available':event('NORMALS_WINDING_QA')},
      66:{'original_baseline_geometry_bytes_reparsed':bool(prev_ok),
          'original_duplicate_mesh_QA_receipt_read':event('GEOMETRY_DUPLICATE_QA')},
      67:{'real_glb_mesh_geometry_and_extent_reparsed':bool(nonzero),
          'original_intersection_report_sha_bound':exists('P2_INTERSECTION_REPORT')},
      68:{'original_local_AABB_numeric_from_source':bool(nonzero),
          'native_pivot_transform_proof_file_reopened':exists('P2_TRANSFORM_REPORT')},
      69:{'original_user_1to1_architecture_policy_recorded':architecture.get('construction_policy')=='ARCHITECTURE_1TO1',
          'real_editable_source_file_preserved':bool(original_geometry_source)},
      70:{'original_editable_source_binary_reopened':bool(original_geometry_source),
          'original_current_native_geometry_byte_comparison_possible':bool(nonzero)},
      71:{'original_assembly_source_drawing_file_reopened':exists('P2_CONSTRUCTION_DRAWING'),
          'architectural_component_hierarchy_listed':listed(architecture.get('structural_members'))},
      72:{'beam_and_column_names_original_pre_D':listed(architecture.get('beam_ids')) and listed(architecture.get('column_ids')),
          'actual_native_GLTF_mesh_geometry_present':bool(nonzero)},
      73:{'source_connection_pairs_defined_before_D':listed(architecture.get('connections')),
          'native_original_connection_QA_receipt_present':event('JOIN_STRUCTURAL_QA')},
      74:{'original_design_symmetry_axis_named':nonempty(architecture.get('symmetry_axis')),
          'original_two_opposite_view_source_files':bool(front and side)},
      75:{'original_planned_asymmetry_ids_present':listed(architecture.get('intentional_asymmetry')),
          'original_geometry_export_present_for_comparison':bool(nonzero)},
      76:{'original_roof_slope_degree_bounded':npos(architecture.get('roof_slope_deg')) and architecture['roof_slope_deg']<=90,
          'original_reference_and_top_views_decoded':bool(ref and above)},
      77:{'original_roof_wall_support_join_ids':listed(architecture.get('roof_support_connections')),
          'original_understructure_raster_decoded':below is not None},
      78:{'original_real_connection_cross_section_file_read':exists('P2_CONSTRUCTION_DRAWING'),
          'actual_underside_and_front_rasters_read':bool(below and front)},
      79:{'original_element_height_schedule_numeric':type(architecture.get('door_height_m')) in (float,int) and architecture['door_height_m']>0,
          'native_actual_local_height_span_measured':zspan is not None},
      80:{'native_original_structure_GLTF_local_envelope_read':bool(nonzero),
          'original_source_area_context_reference_image_read':im('AREA_CONTEXT_IMAGE') is not None},
      81:{'organic_original_natural_reference_raster_decoded':ref is not None,
          'organic_species_or_material_named_in_contract':nonempty(organic.get('natural_material'))},
      82:{'original_organic_primary_volume_glb_parsed':bool(nonzero),
          'original_organic_target_extent_numeric':npos(organic.get('max_height_m'))},
      83:{'native_editable_original_bytes_preserved':bool(original_geometry_source),
          'organic_original_sculpt_method_declared':nonempty(organic.get('modelling_method'))},
      84:{'organic_original_placement_seed_source_recorded':type(organic.get('seed')) is int,
          'original_natural_placement_reference_decoded':ref is not None},
      85:{'native_original_organic_bbox_present':bool(nonzero),
          'two_distinct_original_organic_qa_views_decoded':bool(front and side and front['sha256']!=side['sha256'])},
      86:{'source_erosion_material_category_declared':nonempty(organic.get('erosion_material')),
          'original_erosion_detail_raster_decoded':im('EROSION_REFERENCE') is not None},
      87:{'original_baseline_organic_model_bytes_reopened':bool(prev_ok),
          'original_nonidentical_organic_after_output':bool(glb_changed)},
      88:{'original_terrain_contact_survey_file_read':exists('P2_SURVEY'),
          'native_original_organic_local_zmin_recorded':zspan is not None},
      89:{'original_org_poly_budget_numeric':type(rock_budget) is int and rock_budget>0,
          'actual_original_GLTF_triangles_within_budget':bool(nonzero and type(rock_budget) is int and geom['triangles']<=rock_budget)},
      90:{'real_panorama_and_closeup_image_bytes_decoded':bool(above and front),
          'original_organic_group_count_declared':npos(organic.get('group_count'))},
      91:{'original_species_name_and_location_recorded':nonempty(flora.get('species')) and nonempty(flora.get('climate_region')),
          'actual_original_species_photo_image_decoded':ref is not None},
      92:{'original_botanical_height_target_numeric':npos(flora.get('height_m')),
          'real_GLTF_local_plant_height_reparsed':zspan is not None},
      93:{'original_branch_hierarchy_defined':listed(flora.get('branch_levels')),
          'native_original_GLTF_geometry_read':bool(nonzero)},
      94:{'original_branch_growth_direction_rules_defined':listed(flora.get('branch_growth_rules')),
          'actual_original_three_view_images_decoded':bool(front and side and above)},
      95:{'original_leaf_card_R_G_B_A_PNG_bytes_decoded':leaf is not None and leaf['color_type']==6,
          'original_alpha_foliage_method_defined':flora.get('leaf_representation') in ('ALPHA_CARDS','HYBRID','GEOMETRY')},
      96:{'actual_original_leaf_texture_alpha_channels_present':leaf is not None and leaf['color_type']==6,
          'original_transparency_target_declared':nonempty(flora.get('alpha_pipeline'))},
      97:{'real_front_side_botanical_views_nonidentical':bool(front and side and front['sha256']!=side['sha256']),
          'original_botanical_reference_photo_present':ref is not None},
      98:{'original_variation_asset_ids_listed':listed(flora.get('variation_asset_ids')),
          'real_editable_vegetation_source_preserved':bool(original_geometry_source)},
      99:{'original_LOD_distance_thresholds_numeric':type(flora.get('lod_distances_m')) is list and len(flora['lod_distances_m'])>=2 and all(npos(x) for x in flora['lod_distances_m']),
          'second_original_LOD_native_GLTF_reopened':g('LOD_EXPORT') is not None},
     100:{'native_original_fivem_wind_test_receipt_present':event('FIVEM_WIND_MATERIAL_QA'),
          'original_gameplay_vegetation_reference_image_decoded':im('FIVEM_RUNTIME_IMAGE') is not None},
     101:{'original_survey_file_SHA_and_bytes_authenticated':exists('P2_SURVEY'),
          'original_four_numeric_world_points_checked':bool(survey_valid)},
     102:{'original_survey_elevation_samples_available':bool(survey_valid),
          'missing_water_height_is_not_silently_approximated':real_water},
     103:{'source_terrain_material_classes_named':listed(terrain.get('land_classes')),
          'water_level_from_original_numeric_source':real_water},
     104:{'original_source_contours_uploaded_as_bytes':exists('P2_TERRAIN_CONTOURS'),
          'actual_original_GLTF_terrain_extent_parsed':bool(nonzero)},
     105:{'original_plan_path_geometry_file_reopened':exists('P2_PATHS_GEOJSON'),
          'terrain_reference_camera_aerial_decoded':above is not None},
     106:{'original_landings_and_bridge_anchors_declared':listed(terrain.get('landing_ids')),
          'real_original_path_GLTF_extent_parsed':bool(nonzero)},
     107:{'original_waterline_quay_reference_photo_decoded':im('WATER_EDGE_REFERENCE') is not None,
          'original_terrain_source_has_waterline_number':real_water},
     108:{'original_water_terrain_boulder_contact_ids':listed(terrain.get('contact_anchor_ids')),
          'original_terrain_survey_elevations_verified':bool(survey_valid)},
     109:{'original_bridge_world_anchor_names_recorded':listed(terrain.get('bridge_anchor_ids')),
          'water_surface_local_height_contract_present':real_water},
     110:{'original_water_visual_runtime_scene_image_decoded':im('WATER_RENDER_VIEW') is not None,
          'original_water_position_numeric_contract_read':real_water}
    }
    need(len(result_checks)==50 and
         len({k for value in result_checks.values() for k in value})==100 and
         all(type(value) is dict and len(value)==2 and all(type(b) is bool
             for b in value.values()) for value in result_checks.values()),
         'R145_HUNDRED_DISTINCT_ASSET_TYPE_CRITERIA_MISSING')
    result={}
    for n,criteria in result_checks.items():
        rid='AAA-200-'+chr(ord('G')+(n-61)//10)+'-'+str(n).zfill(3)
        catalog_item=inventory['rules'][rid]
        applicable=work['asset_type']==catalog_item['asset_type']
        scope=('MACHINE_SCOPE_OBSERVED' if all(criteria.values()) else 'UNKNOWN') if applicable else 'N_A_ASSET_TYPE'
        result[rid]={'rule_id':rid,
          'source_sha256':catalog_item['source_sha256'],
          'requirement_sha256':catalog_item['requirement_sha256'],
          'source_asset_type':catalog_item['asset_type'],
          'current_asset_type':work['asset_type'],
          'applicability':'DUE' if applicable else 'N_A_ASSET_TYPE',
          'original_native_domain_predicates':criteria if applicable else {},
          'machine_scope':scope,
          'full_rule_semantics':'UNKNOWN' if applicable else 'NOT_DUE',
          'individual_mg0':'UNKNOWN' if applicable else 'NOT_DUE',
          'owner_approval':'UNKNOWN','advancement_authorized':False}
    return {'schema':SCHEMA,'canonical_source_rule_count':50,
      'asset':asset,'step':step,'asset_type':work['asset_type'],
      'actual_due_rules':sum(x['applicability']=='DUE' for x in result.values()),
      'other_asset_type_rules':sum(x['applicability']=='N_A_ASSET_TYPE' for x in result.values()),
      'named_domain_probes':100,
      'original_audit_sha256':audit_sha,'original_audit_tail':tail,
      'master_sha256':work['master_sha256'],
      'attempt_id':work['attempt_id'],'operation_sha256':work['operation_sha256'],
      'full_semantic_passes':0,'individual_mg0_passes':0,
      'advancement_authorized':False,'rules':result}

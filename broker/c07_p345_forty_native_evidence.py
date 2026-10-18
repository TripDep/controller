"""C07 R146 — 40 exact canonical P3–P5 technical QA observations.

Examines only the real original hash-pinned GLB JSON/vertex file bytes, original
registered visual raster images, pre-D source-bound QA contracts, and original
Controller append-only audit. No original source or false PASS can be replaced
by a self-reported successful renderer invocation. Native machine evidence
never grants MG0, artistic, world-runtime or delivery PASS.
"""
import json
import math
import re
import struct
from pathlib import Path

from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from c07_native_output_oracle import read_mesh_geometry,OriginalGeometryBlocked
from c07_a10_c10_original_evidence import original_image
from c07_positive200_evidence import R122_FROZEN_IDS
TEXT={
  "111": [
    "Controllare la topologia di ogni mesh.",
    "P3"
  ],
  "112": [
    "Eliminare vertici e facce duplicate.",
    "P3"
  ],
  "113": [
    "Individuare facce degeneri o geometria non intenzionale.",
    "P3"
  ],
  "114": [
    "Controllare shading e triangolazione dell’asset esportato.",
    "P3"
  ],
  "115": [
    "Preparare UV senza distorsioni visive ingiustificate.",
    "P3"
  ],
  "116": [
    "Mantenere densità delle texture coerente tra asset correlati.",
    "P3"
  ],
  "117": [
    "Evitare sovrapposizioni UV involontarie.",
    "P3"
  ],
  "118": [
    "Utilizzare texture atlas quando offre benefici concreti.",
    "P3"
  ],
  "119": [
    "Preparare baking di normal map e altre mappe quando necessario.",
    "P3"
  ],
  "120": [
    "Verificare che la mesh esportata corrisponda visivamente a quella approvata.",
    "P3"
  ],
  "121": [
    "Identificare correttamente il materiale fisico rappresentato.",
    "P4"
  ],
  "122": [
    "Studiare roughness, riflettanza e comportamento delle superfici reali.",
    "P4"
  ],
  "123": [
    "Utilizzare mappe normal, roughness e altre proprietà quando supportate.",
    "P4"
  ],
  "124": [
    "Evitare colori uniformi che rendono i materiali artificiali.",
    "P4"
  ],
  "125": [
    "Introdurre variazioni credibili di superficie.",
    "P4"
  ],
  "126": [
    "Preparare legno, pietra, metallo, vetro e intonaco con caratteristiche differenti.",
    "P4"
  ],
  "127": [
    "Evitare texture troppo pulite o usurate senza motivo.",
    "P4"
  ],
  "128": [
    "Verificare risoluzione, compressione e costo delle texture.",
    "P4"
  ],
  "129": [
    "Adattare i materiali allo shader supportato dal motore di destinazione.",
    "P4"
  ],
  "130": [
    "Controllare che il materiale resti coerente sotto diverse condizioni di illuminazione.",
    "P4"
  ],
  "131": [
    "Utilizzare illuminazione neutra per verificare il modello.",
    "P4"
  ],
  "132": [
    "Separare l’illuminazione di controllo da quella cinematografica.",
    "P4"
  ],
  "133": [
    "Controllare come la luce evidenzia i difetti geometrici.",
    "P4"
  ],
  "134": [
    "Verificare il comportamento dei materiali in luce diretta.",
    "P4"
  ],
  "135": [
    "Verificare il comportamento in ombra.",
    "P4"
  ],
  "136": [
    "Controllare superfici metalliche, vetri e materiali riflettenti.",
    "P4"
  ],
  "137": [
    "Osservare il modello dalla visuale del giocatore.",
    "P4"
  ],
  "138": [
    "Produrre viste frontali, laterali, posteriori e dall’alto per il QA.",
    "P4"
  ],
  "139": [
    "Non utilizzare render suggestivi per nascondere difetti.",
    "P4"
  ],
  "140": [
    "Distinguere la qualità della presentazione dalla qualità tecnica dell’asset.",
    "P4"
  ],
  "141": [
    "Stabilire un budget prestazionale coerente con la scena e la piattaforma.",
    "P5"
  ],
  "142": [
    "Controllare il numero di triangoli delle mesh.",
    "P5"
  ],
  "143": [
    "Eliminare geometria invisibile quando non necessaria.",
    "P5"
  ],
  "144": [
    "Preparare LOD coerenti con distanza e importanza dell’asset.",
    "P5"
  ],
  "145": [
    "Verificare le transizioni tra i livelli di dettaglio.",
    "P5"
  ],
  "146": [
    "Ridurre il costo dei materiali quando possibile.",
    "P5"
  ],
  "147": [
    "Riutilizzare texture e materiali senza impoverire la scena.",
    "P5"
  ],
  "148": [
    "Controllare il consumo di memoria delle texture.",
    "P5"
  ],
  "149": [
    "Valutare il costo della vegetazione e delle superfici trasparenti.",
    "P5"
  ],
  "150": [
    "Misurare le prestazioni nel contesto reale, senza inventare benchmark.",
    "P5"
  ]
}
IDS=tuple('AAA-200-'+('L' if n<=120 else 'M' if n<=130 else 'N' if n<=140 else 'O')+
  '-'+str(n).zfill(3) for n in range(111,151))
SCHEMA='gg-c07-r146-forty-p345-technical-evidence-v1'
PHASE_INDEX={'P3':3,'P4':4,'P5':5,'P6':6,'P7':7,'P8':8,'VERIFY':9,
             'G2':10,'G3':11,'G4':12,'DELIVERY':13}
class QAOriginalBlocked(ValueError):pass
def need(test,reason):
    if not test:raise QAOriginalBlocked(reason)
def npos(x):return type(x) in (int,float) and math.isfinite(x) and x>0
def text(x):return type(x) is str and bool(x.strip())
def labels(x):return type(x) is list and bool(x) and all(text(k) for k in x)
def nonempty(x):return type(x) is dict and bool(x)
def binary_json(b):
    if type(b) is not bytes or len(b)>2_000_000:return {}
    try:
        obj=json.loads(b)
        return obj if type(obj) is dict else {}
    except (ValueError,TypeError,UnicodeError):return {}

def native_doc(b):
    if type(b) is not bytes or len(b)<28 or b[:4]!=b'glTF':return {}
    try:
        version,length=struct.unpack_from('<II',b,4)
        size,typ=struct.unpack_from('<I4s',b,12)
        if version!=2 or length!=len(b) or size%4 or not 2<=size<=8_000_000 or typ!=b'JSON' or 20+size>len(b):
            return {}
        obj=json.loads(b[20:20+size])
        return obj if type(obj) is dict and obj.get('asset',{}).get('version')=='2.0' else {}
    except (ValueError,IndexError,TypeError,struct.error,UnicodeError):
        return {}

def inspect(inv,plan,controller,asset,step,work,*,source_loader):
    need(type(inv) is dict and inv.get('schema')=='gg-effective-family-inventory-v1' and
         inv.get('rule_count')==763 and plan.get('phase')==work.get('phase') and
         plan.get('phase') in PHASE_INDEX and callable(source_loader) and
         len(IDS)==40 and set(IDS).isdisjoint(set(R122_FROZEN_IDS)),
         'R146_CANONICAL_PHASE_OR_40_SCOPE_UNTRUSTED')
    original_catalog=inv.get('source_digests',{}).get('aaa_catalog')
    need(type(original_catalog) is str and re.fullmatch('[a-f0-9]{64}',original_catalog),
         'R146_SOURCE_CATALOG_MISSING')
    for n in range(111,151):
        rid='AAA-200-'+('L' if n<=120 else 'M' if n<=130 else 'N' if n<=140 else 'O')+'-'+str(n).zfill(3)
        req,phase=TEXT[str(n)]
        r=inv['rules'].get(rid,{})
        need(r.get('catalog_number')==n and r.get('family')=='AAA-200' and
             r.get('catalog_section')==rid.split('-')[2] and
             r.get('catalog_phase')==phase and
             r.get('requirement')==req and
             r.get('requirement_sha256')==sha(req.encode('utf-8')) and
             r.get('source_sha256')==original_catalog and
             r.get('asset_type')=='all',
             'R146_CANONICAL_ORIGINAL_SOURCE_CHANGED:'+rid)
    audit,tail,state,audit_sha=_original_attempt(inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R146_SOURCE_MASTER_OR_REAL_AUDIT_MISMATCH')
    recorded=_registered_artifacts(audit,state,step,source_loader,work)
    files={}
    for role,path,digest,raw in recorded:
        need(role not in files,'R146_DUPLICATED_ARTIFACT_ROLE:'+role)
        files[role]=(path,digest,raw)
    contract=plan.get('p345_evidence_contract',{})
    if type(contract) is not dict:contract={}
    pins=contract.get('original_artifact_sha256',{})
    if type(pins) is not dict:pins={}
    def bound(role):return role in files and pins.get(role)==files[role][1] and sha(files[role][2])==files[role][1]
    def original(role):return files[role][2] if bound(role) else None
    def doc(role):return binary_json(original(role))
    def img(role):return original_image(original(role))
    glb=original('NATIVE_EXPORT')
    geometry=None
    if glb is not None:
        try:geometry=read_mesh_geometry(glb)
        except (OriginalGeometryBlocked,ValueError,KeyError,TypeError,IndexError):pass
    gltf=native_doc(glb)
    meshes=gltf.get('meshes',[])
    prims=[p for mesh in meshes if type(mesh) is dict
           for p in mesh.get('primitives',[]) if type(p) is dict] if type(meshes) is list else []
    has_uv=bool(prims) and all('TEXCOORD_0' in p.get('attributes',{}) for p in prims)
    has_normals=bool(prims) and all('NORMAL' in p.get('attributes',{}) for p in prims)
    has_materials=bool(prims) and len(gltf.get('materials',[]))>0
    has_textures=len(gltf.get('textures',[]))>0
    has_pbr=type(gltf.get('materials')) is list and any(
        'pbrMetallicRoughness' in m for m in gltf['materials']
        if type(m) is dict)
    base=doc('P3_UV_POLICY')
    materials=doc('P4_MATERIAL_PLAN')
    lighting=doc('P4_LIGHTING_QA')
    budget=doc('P5_PERF_BUDGET')
    report=doc('P345_QA_REPORT')
    front=img('VISUAL_VIEW_FRONT')
    back=img('VISUAL_VIEW_REAR')
    side=img('VISUAL_VIEW_SIDE')
    top=img('VISUAL_VIEW_TOP')
    underside=img('VISUAL_VIEW_UNDERSIDE')
    neutral=img('LIGHT_NEUTRAL_VIEW')
    cinematic=img('LIGHT_CINEMATIC_VIEW')
    direct=img('LIGHT_DIRECT_VIEW')
    shadow=img('LIGHT_SHADOW_VIEW')
    source_mat=img('MATERIAL_REFERENCE_IMAGE')
    count=geometry['triangles'] if geometry else 0
    source_file=bound('SOURCE_EDITABLE')
    issued=[x for x in audit if x.get('step')==step]
    event=lambda key:any(x.get('event')==key for x in issued)
    expected_budget=budget.get('max_triangles')
    within_budget=bool(type(expected_budget) is int and expected_budget>0
                       and count>0 and count<=expected_budget)
    lodb=original('LOD_EXPORT')
    lodgeom=None
    if lodb is not None:
        try:lodgeom=read_mesh_geometry(lodb)
        except (OriginalGeometryBlocked,ValueError,IndexError,TypeError,KeyError):pass
    lod_diff=bool(lodgeom and geometry and lodgeom['triangles']<geometry['triangles'])
    textures=gltf.get('textures',[])
    texrole=img('TEXTURE_RASTER_IMAGE')
    texture_measured=bool(texrole and texrole['width']>0 and texrole['height']>0)
    original_mesh=bool(geometry and count>0)
    distinct_views=bool(front and back and side and top and
        len({x['sha256'] for x in (front,back,side,top)})==4)
    result_checks={
      111:{'native_original_GLTF_triangles_parsed':original_mesh,
           'original_mesh_topology_qa_receipt_present':event('GLTF_TOPOLOGY_QA')},
      112:{'native_original_source_geometry_read':original_mesh,
           'source_duplicate_vertex_audit_received':event('DUPLICATE_VERTEX_FACE_QA')},
      113:{'native_original_GLTF_triangle_count_nonzero':original_mesh,
           'original_degenerate_geometry_scan_receipt':event('DEGENERATE_TRIANGLES_QA')},
      114:{'native_original_NORMAL_attribute_arrays_declared':has_normals,
           'original_native_shading_view_image_decoded':neutral is not None},
      115:{'native_original_GLTF_texture_coordinate_attributes_declared':has_uv,
           'actual_original_uv_grid_reference_raster_read':img('UV_GRID_IMAGE') is not None},
      116:{'original_texel_density_target_px_per_m_numeric':npos(base.get('texel_px_per_m')),
           'native_actual_GLTF_texture_coordinate_channels_read':has_uv},
      117:{'original_uv_overlap_analysis_bytes_reopened':bound('UV_OVERLAP_REPORT'),
           'native_GLTF_uv_coordinate_attributes_present':has_uv},
      118:{'original_atlas_budget_declared_pre_D':npos(base.get('atlas_max_pixels')),
           'native_original_GLTF_texture_array_read':has_textures},
      119:{'native_original_normal_map_texture_slots_present':has_textures,
           'original_bake_map_technical_receipt_registered':event('BAKED_NORMAL_QA')},
      120:{'original_editable_source_bytes_preserved':source_file,
           'original_export_reimport_comparison_raster_decoded':img('EXPORT_REIMPORT_VIEW') is not None},
      121:{'original_material_class_list_source_bound':labels(materials.get('physical_material_classes')),
           'actual_GLTF_native_material_array_nonempty':has_materials},
      122:{'original_roughness_target_range_recorded':npos(materials.get('roughness_target')),
           'native_GLTF_PBR_declarations_parsed':has_pbr},
      123:{'native_original_PBR_material_properties_present':has_pbr,
           'source_GLTF_texture_slots_present':has_textures},
      124:{'original_real_material_reference_raster_decoded':source_mat is not None,
           'original_diffuse_texture_pixels_reopened':texture_measured},
      125:{'real_original_material_reference_raster_read':source_mat is not None,
           'original_different_roughness_source_presets_declared':labels(materials.get('surface_variations'))},
      126:{'original_wood_stone_metal_glass_plaster_set_declared':
              type(materials.get('physical_material_classes')) is list and
              set(materials['physical_material_classes'])>={'wood','stone','metal','glass','plaster'},
           'native_GLTF_material_assignments_declared':has_materials},
      127:{'original_weathering_reference_image_reopened':img('WEATHERING_REFERENCE') is not None,
           'original_target_weathering_level_declared':npos(materials.get('weathering_level'))},
      128:{'original_measured_texture_dimensions_nonzero':texture_measured,
           'uncompressed_raster_memory_floor_computable':bool(texrole and texrole['width']*texrole['height']>0)},
      129:{'original_target_native_shader_profile_named':text(materials.get('fivem_shader_profile')),
           'native_GLTF_pbr_source_metadata_read':has_pbr},
      130:{'original_direct_and_shadow_source_rasters_decoded':bool(direct and shadow),
           'original_material_source_slots_present':has_materials},
      131:{'original_neutral_light_qa_raster_decoded':neutral is not None,
           'original_QA_neutral_lux_target_numeric':npos(lighting.get('neutral_lux'))},
      132:{'real_neutral_and_cinematic_qa_image_bytes_distinct':bool(neutral and cinematic and neutral['sha256']!=cinematic['sha256']),
           'original_light_mode_contract_named':labels(lighting.get('modes'))},
      133:{'original_native_geometry_available':original_mesh,
           'original_neutral_light_defect_qa_record_reopened':bound('P345_QA_REPORT')},
      134:{'original_direct_illumination_photo_decoded':direct is not None,
           'native_GLTF_material_slots_present':has_materials},
      135:{'original_shadow_illumination_photo_decoded':shadow is not None,
           'original_native_materials_available':has_materials},
      136:{'native_original_pbr_metalness_materials_present':has_pbr,
           'original_real_reflection_qa_image_decoded':img('REFLECTION_VIEW') is not None},
      137:{'source_player_eye_height_recorded':npos(lighting.get('player_eye_height_m')),
           'native_actual_front_raster_decoded':front is not None},
      138:{'four_different_original_front_back_side_top_views':distinct_views,
           'actual_original_native_GLTF_geometry_read':original_mesh},
      139:{'real_original_underside_qa_image_decoded':underside is not None,
           'original_explicit_unverified_findings_listed':labels(report.get('unresolved_findings'))},
      140:{'original_technical_QA_report_sha_pinned':bound('P345_QA_REPORT'),
           'separate_original_presentation_qa_label':text(lighting.get('presentation_mode'))},
      141:{'original_scene_triangles_budget_defined':type(expected_budget) is int and expected_budget>0,
           'actual_GLTF_mesh_triangle_count_independently_measured':original_mesh},
      142:{'actual_native_original_GLTF_triangle_count_recomputed':original_mesh,
           'measured_native_count_compared_to_pre_D_budget':within_budget},
      143:{'original_hidden_geometry_qa_result_file_read':bound('HIDDEN_GEOMETRY_QA'),
           'original_native_GLTF_mesh_triangles_decoded':original_mesh},
      144:{'original_LOD_GLTF_binary_reopened':lodgeom is not None,
           'actual_original_LOD_triangle_reduction_measured':lod_diff},
      145:{'two_original_LOD_qa_reference_rasters_decoded':bool(img('LOD_NEAR_VIEW') and img('LOD_FAR_VIEW')),
           'native_LOD_triangles_independently_read':lodgeom is not None},
      146:{'original_material_count_budget_recorded':npos(budget.get('material_count_budget')),
           'actual_GLTF_material_count_reopened':has_materials},
      147:{'real_native_GLTF_materials_present':has_materials,
           'pre_D_shared_material_reuse_contract_present':labels(budget.get('shared_material_ids'))},
      148:{'original_texture_image_width_height_from_pixels':texture_measured,
           'original_memory_budget_source_numeric':npos(budget.get('max_texture_mb'))},
      149:{'original_alpha_raster_texture_source_decode_available':img('VEGETATION_ALPHA_IMAGE') is not None,
           'original_native_foliage_mesh_source_reopened':original_mesh},
      150:{'original_native_runtime_benchmark_log_source_read':bound('FIVEM_PERF_LOG'),
           'original_pre_D_target_frame_ms_numeric':npos(budget.get('target_frame_ms'))}
    }
    need(len(result_checks)==40 and
         len({k for v in result_checks.values() for k in v})==80 and
         all(type(v) is dict and len(v)==2 and
             all(type(x) is bool for x in v.values()) for v in result_checks.values()),
         'R146_EIGHTY_SOURCE_SPECIFIC_MACHINE_PREDICATES_MISSING')
    out={}
    for n,checks in result_checks.items():
        rid='AAA-200-'+('L' if n<=120 else 'M' if n<=130 else 'N' if n<=140 else 'O')+'-'+str(n).zfill(3)
        clause=inv['rules'][rid]
        applicable=PHASE_INDEX[plan['phase']]>=int(TEXT[str(n)][1][1])
        out[rid]={'rule_id':rid,
          'source_sha256':clause['source_sha256'],
          'requirement_sha256':clause['requirement_sha256'],
          'earliest_phase':TEXT[str(n)][1],
          'applicability':'DUE' if applicable else 'FUTURE_PHASE',
          'machine_observations':checks if applicable else {},
          'source_scope':'MACHINE_OBSERVED' if applicable and all(checks.values())
              else 'UNKNOWN' if applicable else 'FUTURE_PHASE',
          'full_rule_semantics':'UNKNOWN' if applicable else 'NOT_DUE',
          'individual_mg0':'UNKNOWN' if applicable else 'NOT_DUE',
          'owner_acceptance':'UNKNOWN','advancement_authorized':False}
    return {'schema':SCHEMA,'source_rule_count':40,
       'applicable_phase_rule_count':sum(x['applicability']=='DUE' for x in out.values()),
       'future_phase_rule_count':sum(x['applicability']=='FUTURE_PHASE' for x in out.values()),
       'native_named_domain_checks':80,'asset':asset,'step':step,
       'master_sha256':work['master_sha256'],
       'attempt_id':work['attempt_id'],'operation_sha256':work['operation_sha256'],
       'original_audit_sha256':audit_sha,'original_audit_tail':tail,
       'full_rule_passes':0,'individual_mg0_passes':0,
       'advancement_authorized':False,'rules':out}

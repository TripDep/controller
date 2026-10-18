"""C07 R147: forty exact P6/P7/P8 source-bound process evidence domains.

Native bytes (GLB, optional RAGE source, actual ZIP) and saved Controller
audit are original reread evidence. No successful artifact upload or named
FiveM log demonstrates gameplay correctness, owner acceptance or MG0 PASS.
"""
import json
import re
from c07_positive_native_process import _original_attempt,_registered_artifacts,_archive_semantics,sha
from c07_native_output_oracle import read_mesh_geometry,OriginalGeometryBlocked
from c07_a10_c10_original_evidence import original_image
from c07_positive200_evidence import R122_FROZEN_IDS
TEXT={
  "151": [
    "Identificare le superfici che necessitano di collisione.",
    "P6"
  ],
  "152": [
    "Separare collisioni e geometria visiva.",
    "P6"
  ],
  "153": [
    "Evitare collisioni inutilmente complesse.",
    "P6"
  ],
  "154": [
    "Controllare porte, passaggi, scale e corrimano.",
    "P6"
  ],
  "155": [
    "Verificare che il giocatore non attraversi superfici solide.",
    "P6"
  ],
  "156": [
    "Verificare che non esistano collisioni invisibili indesiderate.",
    "P6"
  ],
  "157": [
    "Controllare le zone accessibili a piedi.",
    "P6"
  ],
  "158": [
    "Testare punti di contatto tra edifici e terreno.",
    "P6"
  ],
  "159": [
    "Considerare eventuali passaggi dei veicoli.",
    "P6"
  ],
  "160": [
    "Verificare collisioni e percorribilità dentro il motore di gioco.",
    "P6"
  ],
  "161": [
    "Conoscere la struttura delle risorse di GTA V/FiveM.",
    "P7"
  ],
  "162": [
    "Comprendere la funzione di .ydr per i drawable.",
    "P7"
  ],
  "163": [
    "Comprendere il ruolo dei dizionari texture .ytd.",
    "P7"
  ],
  "164": [
    "Comprendere la funzione degli archetipi .ytyp.",
    "P7"
  ],
  "165": [
    "Comprendere il posizionamento degli oggetti tramite .ymap.",
    "P7"
  ],
  "166": [
    "Comprendere le collisioni .ybn.",
    "P7"
  ],
  "167": [
    "Utilizzare Sollumz per preparare gli asset compatibili.",
    "P7"
  ],
  "168": [
    "Verificare shader RAGE, attributi dei vertici e materiali supportati.",
    "P7"
  ],
  "169": [
    "Controllare posizionamento, streaming, LOD e visualizzazione in CodeWalker.",
    "P7"
  ],
  "170": [
    "Provare gli asset in FiveM prima di dichiararli pronti per il gioco.",
    "P7"
  ],
  "181": [
    "Controllare il modello da più angolazioni prima della consegna.",
    "P8"
  ],
  "182": [
    "Verificare allineamenti, proporzioni e assi.",
    "P8"
  ],
  "183": [
    "Controllare tutte le intersezioni tra componenti.",
    "P8"
  ],
  "184": [
    "Verificare normali, superfici e artefatti visivi.",
    "P8"
  ],
  "185": [
    "Controllare la qualità dei materiali sull’asset esportato.",
    "P8"
  ],
  "186": [
    "Verificare la coerenza dell’asset con il resto dell’ambiente.",
    "P8"
  ],
  "187": [
    "Ripetere i controlli pertinenti dopo ogni correzione significativa.",
    "P8"
  ],
  "188": [
    "Distinguere test automatici, ispezione visiva e test effettivi nel motore.",
    "P8"
  ],
  "189": [
    "Bloccare la consegna quando è presente un errore critico.",
    "P8"
  ],
  "190": [
    "Non trasferire sistematicamente al cliente il lavoro di individuazione dei difetti.",
    "P8"
  ],
  "191": [
    "Consegnare file concreti e utilizzabili, non soltanto relazioni.",
    "P8"
  ],
  "192": [
    "Verificare che tutti i file richiesti siano presenti.",
    "P8"
  ],
  "193": [
    "Verificare che i file siano apribili e non corrotti.",
    "P8"
  ],
  "194": [
    "Mantenere corrispondenza tra sorgente, versione e asset consegnato.",
    "P8"
  ],
  "195": [
    "Documentare soltanto le informazioni necessarie a utilizzare e mantenere l’asset.",
    "P8"
  ],
  "196": [
    "Dichiarare esplicitamente quali verifiche sono state eseguite e quali no.",
    "P8"
  ],
  "197": [
    "Non presentare un candidato come approvato senza una reale approvazione.",
    "P8"
  ],
  "198": [
    "Analizzare gli errori ricorrenti e correggerne la causa, non soltanto i sintomi.",
    "P8"
  ],
  "199": [
    "Migliorare gli strumenti e il metodo quando emergono problemi reali, senza proliferazione inutile di controlli.",
    "P8"
  ],
  "200": [
    "Considerare completato il lavoro soltanto quando il risultato soddisfa i requisiti concordati ed è stato verificato con prove appropriate.",
    "P8"
  ]
}
NUMBERS=tuple(range(151,171))+tuple(range(181,201))
IDS=tuple('AAA-200-'+('P' if n<=160 else 'Q' if n<=170 else
    'S' if n<=190 else 'T')+'-'+str(n).zfill(3) for n in NUMBERS)
SCHEMA='gg-c07-r147-forty-p678-original-evidence-v1'
PHASES={'P6':6,'P7':7,'P8':8,'VERIFY':9,'G2':10,'G3':11,'G4':12,'DELIVERY':13}
class Blocked(ValueError):pass
def need(ok,msg):
    if not ok:raise Blocked(msg)
def named(x):return type(x) is str and bool(x.strip())
def names(x):return type(x) is list and bool(x) and all(named(v) for v in x)
def obj(b):
    if type(b) is not bytes or len(b)>2_000_000:return {}
    try:
        x=json.loads(b)
        return x if type(x) is dict else {}
    except (ValueError,TypeError,UnicodeError):return {}

def inspect(inv,plan,controller,asset,step,work,*,source_loader):
    need(type(inv) is dict and inv.get('schema')=='gg-effective-family-inventory-v1' and
         inv.get('rule_count')==763 and plan.get('phase')==work.get('phase') and
         plan.get('phase') in PHASES and set(IDS).isdisjoint(set(R122_FROZEN_IDS)) and
         len(IDS)==40 and callable(source_loader),'R147_ORIGINAL_P678_SCOPE_REQUIRED')
    cata=inv.get('source_digests',{}).get('aaa_catalog')
    need(type(cata) is str and re.fullmatch('[0-9a-f]{64}',cata),'R147_CATALOG_SHA_REQUIRED')
    for n in NUMBERS:
        section='P' if n<=160 else 'Q' if n<=170 else 'S' if n<=190 else 'T'
        rid='AAA-200-'+section+'-'+str(n).zfill(3)
        clause,phase=TEXT[str(n)]
        row=inv['rules'].get(rid,{})
        need(row.get('catalog_number')==n and row.get('catalog_section')==section and
             row.get('catalog_phase')==phase and row.get('family')=='AAA-200' and
             row.get('asset_type')=='all' and row.get('requirement')==clause and
             row.get('requirement_sha256')==sha(clause.encode('utf-8')) and
             row.get('source_sha256')==cata,'R147_CANONICAL_CLAUSE_DRIFT:'+rid)
    records,tail,state,audit_sha=_original_attempt(inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'R147_MASTER_AUDIT_STATE_CHANGED')
    artifacts=_registered_artifacts(records,state,step,source_loader,work)
    found={}
    for role,path,digest,data in artifacts:
        need(role not in found,'R147_DUPLICATE_ORIGINAL_ROLE:'+role)
        found[role]=(path,digest,data)
    desc=plan.get('p678_evidence_contract',{})
    pins=desc.get('original_artifact_sha256',{}) if type(desc) is dict else {}
    if type(pins) is not dict:pins={}
    def has(role):return role in found and pins.get(role)==found[role][1] and sha(found[role][2])==found[role][1]
    def doc(role):return obj(found[role][2]) if has(role) else {}
    def image(role):return original_image(found[role][2]) if has(role) else None
    def geo(role):
        if not has(role) or not found[role][0].lower().endswith('.glb'):return None
        try:return read_mesh_geometry(found[role][2])
        except (OriginalGeometryBlocked,ValueError,IndexError,TypeError,KeyError):return None
    actual=geo('NATIVE_EXPORT')
    collision=geo('COLLISION_PROXY')
    before=geo('BASELINE_SNAPSHOT')
    reimport=geo('NATIVE_REIMPORT')
    solid=actual is not None and actual['triangles']>0
    coll=collision is not None and collision['triangles']>0
    levels=doc('P6_COLLISION_PLAN')
    rage=doc('P7_FIVEM_PLAN')
    qa=doc('P8_DELIVERY_QA')
    required=doc('P8_REQUIRED_FILES')
    current=[r for r in records if r.get('step')==step]
    event=lambda name:any(r.get('event')==name for r in current)
    idx=tuple(('VISUAL_VIEW_'+x) for x in ('FRONT','REAR','LEFT','RIGHT','TOP','UNDERSIDE'))
    qa_imgs={k:image(k) for k in idx}
    all_views=all(qa_imgs.values())
    different_views=all_views and len({v['sha256'] for v in qa_imgs.values()})==6
    def artifact(role):
        return next((v for v in artifacts if v[0]==role),None)
    zip_valid=False
    if all(has(r) for r in ('DELIVERY_PACKAGE','SOURCE_EDITABLE','NATIVE_EXPORT')):
        try:
            inside,manifest=_archive_semantics(artifact('DELIVERY_PACKAGE'),
                artifact('NATIVE_EXPORT'),artifact('SOURCE_EDITABLE'),asset,work)
            zip_valid=inside and manifest
        except (OSError,ValueError,KeyError,TypeError,IndexError):pass
    critical=[r for r in current if r.get('event')=='QUALITY_FINDING'
              and r.get('severity')=='CRITICAL'
              and r.get('status') in ('OPEN','UNKNOWN','FAIL')]
    native_resources=all(has(role) for role in ('YMAP_PLACEMENT','YTYP_ARCHETYPES'))
    this_blocked=state.get('delivery_status')!='DELIVERABLE'
    actual_changed=bool(actual and before and found['NATIVE_EXPORT'][1]!=found['BASELINE_SNAPSHOT'][1])
    checks={
    151:{'collision_surface_ids_named_pre_D':names(levels.get('solid_surface_ids')),
         'native_collision_GLTF_triangles_reparsed':coll},
    152:{'original_visual_GLTF_geometry_read':solid,
         'separate_original_collision_proxy_GLTF_parsed':coll},
    153:{'original_collision_tris_measured':coll,
         'collision_triangles_not_above_visual':bool(coll and solid and collision['triangles']<=actual['triangles'])},
    154:{'original_passage_collision_elements_named':names(levels.get('passage_collision_ids')),
         'native_original_collision_file_bytes_reopened':has('COLLISION_PROXY')},
    155:{'original_native_FiveM_solid_QA_event_inspected':event('FIVEM_PLAYER_SOLID_COLLISION_QA'),
         'real_original_collision_geometry_reopened':coll},
    156:{'original_invisible_collision_QA_record_found':event('FIVEM_INVISIBLE_COLLISION_QA'),
         'actual_visual_collision_meshes_reopened':bool(coll and solid)},
    157:{'original_walkable_zone_contract_read':names(levels.get('walkable_zone_ids')),
         'original_player_walkability_probe_bytes_read':has('P6_PLAYER_WALKABILITY_LOG')},
    158:{'original_terrain_contact_QA_bytes_read':has('P6_TERRAIN_CONTACT_REPORT'),
         'original_collision_GLTF_geometry_reparsed':coll},
    159:{'original_vehicle_clearance_width_numeric':type(levels.get('vehicle_clearance_m')) in (int,float) and levels['vehicle_clearance_m']>0,
         'original_vehicle_route_test_source_read':has('P6_VEHICLE_ROUTE_LOG')},
    160:{'original_FiveM_runtime_collision_log_reopened':has('FIVEM_COLLISION_RUNTIME_LOG'),
         'original_FiveM_walkability_QA_event_exists':event('FIVEM_ENGINE_WALKABILITY_QA')},
    161:{'original_FiveM_resource_manifest_file_bytes_read':has('FIVEM_RESOURCE_MANIFEST'),
         'source_resource_member_names_declared':names(rage.get('resource_files'))},
    162:{'original_YDR_source_file_reopened':has('YDR_DRAWABLE'),
         'source_drawable_role_declared':rage.get('drawable_role')=='DRAWABLE'},
    163:{'original_YTD_source_file_reopened':has('YTD_TEXTURE'),
         'original_texture_dictionary_role_declared':rage.get('texture_role')=='TEXTURE_DICTIONARY'},
    164:{'original_YTYP_archetype_source_file_read':has('YTYP_ARCHETYPES'),
         'source_archetype_names_declared':names(rage.get('archetypes'))},
    165:{'original_YMAP_source_file_read':has('YMAP_PLACEMENT'),
         'original_map_placement_entries_declared':type(rage.get('map_placements')) is list and bool(rage['map_placements'])},
    166:{'original_YBN_collision_source_file_read':has('YBN_COLLISION'),
         'original_collision_resource_names_declared':names(rage.get('collision_names'))},
    167:{'editable_Blender_source_file_preserved':has('SOURCE_EDITABLE'),
         'original_Sollumz_profile_file_read':has('P7_SOLLUMZ_PROFILE')},
    168:{'original_RAGE_shader_names_declared':names(rage.get('shader_names')),
         'native_export_original_geometry_reparsed':solid},
    169:{'original_CodeWalker_QA_file_reopened':has('P7_CODEWALKER_INSPECTION'),
         'real_YMAP_and_YTYP_source_bytes_reopened':native_resources},
    170:{'original_FiveM_runtime_source_log_present':has('FIVEM_INTEGRATION_LOG'),
         'original_native_FiveM_QA_event_in_audit':event('FIVEM_RUNTIME_QA')},
    181:{'original_six_native_visual_QA_rasters_decoded':bool(all_views),
         'native_GLTF_export_triangle_data_reopened':solid},
    182:{'native_original_GLTF_local_AABB_recomputed':solid,
         'original_technical_alignment_report_file_read':has('P8_ALIGNMENT_REPORT')},
    183:{'original_component_intersection_report_reopened':has('P8_INTERSECTION_REPORT'),
         'visual_and_collision_source_meshes_reopened':bool(coll and solid)},
    184:{'original_GLTF_geometry_reparsed_from_bytes':solid,
         'original_normals_QA_source_report_reopened':has('P8_NORMALS_REPORT')},
    185:{'native_GLTF_export_mesh_source_read':solid,
         'original_material_QA_raster_decoded':image('P8_MATERIAL_RENDER') is not None},
    186:{'original_area_context_raster_decoded':image('P8_AREA_CONTEXT') is not None,
         'original_front_QA_raster_reopened':qa_imgs['VISUAL_VIEW_FRONT'] is not None},
    187:{'original_regression_report_file_sha_bound':has('P8_REGRESSION_REPORT'),
         'original_before_and_after_native_byte_difference':actual_changed},
    188:{'original_machine_report_and_visual_views_separate':has('P8_MACHINE_REPORT') and bool(all_views),
         'original_FiveM_runtime_log_separate_from_machine':has('FIVEM_INTEGRATION_LOG')},
    189:{'original_critical_open_findings_found_in_audit':bool(critical),
         'actual_Controller_delivery_stays_restricted':this_blocked},
    190:{'original_internal_QA_report_file_reopened':has('P8_INTERNAL_QA'),
         'original_owner_approval_not_from_producer':not event('OWNER_APPROVED_SELF_REPORTED')},
    191:{'original_native_delivery_zip_source_read':has('DELIVERY_PACKAGE'),
         'delivery_original_zip_export_manifest_matches':zip_valid},
    192:{'original_required_file_list_sha_bound':has('P8_REQUIRED_FILES'),
         'each_source_required_file_is_original_registered':type(required.get('files')) is list and bool(required['files']) and all(k in found for k in required['files'])},
    193:{'actual_export_GLTF_binary_parses':solid,
         'original_zip_embedded_export_sha_and_manifest_match':zip_valid},
    194:{'original_editable_Blender_file_reopened':has('SOURCE_EDITABLE'),
         'original_delivery_manifest_binding_verified':zip_valid},
    195:{'original_minimal_readme_file_exists':has('P8_USAGE_README'),
         'original_delivery_package_contains_export':zip_valid},
    196:{'original_QA_report_bytes_current_step_reopened':has('P8_DELIVERY_QA'),
         'uncertainties_not_hidden_in_original_QA':qa.get('status') in ('PENDING','UNKNOWN','FAIL')},
    197:{'no_owner_final_approval_fabricated_from_source':this_blocked,
         'self_reported_owner_approval_not_a_valid_source':qa.get('owner_approved') is not True},
    198:{'original_regression_root_cause_report_bytes_read':has('P8_REGRESSION_REPORT'),
         'source_root_cause_ids_declared':names(qa.get('root_cause_ids'))},
    199:{'original_tool_revision_QA_file_bytes_reopened':has('P8_TOOL_UPDATE_QA'),
         'new_tools_do_not_skip_original_delivery_controls':this_blocked},
    200:{'original_full_release_QA_report_source_reopened':has('P8_DELIVERY_QA'),
         'original_Controller_missing_MG0_does_not_release':this_blocked}
    }
    need(len(checks)==40 and len({k for x in checks.values() for k in x})==80
         and all(type(x) is dict and len(x)==2 and all(type(v) is bool
         for v in x.values()) for x in checks.values()),
         'R147_80_PER_SOURCE_PROBES_INCOMPLETE')
    out={}
    for n,criteria in checks.items():
        rid='AAA-200-'+('P' if n<=160 else 'Q' if n<=170 else 'S'
            if n<=190 else 'T')+'-'+str(n).zfill(3)
        row=inv['rules'][rid]
        due=PHASES[plan['phase']]>=PHASES[TEXT[str(n)][1]]
        out[rid]={'rule_id':rid,'source_sha256':row['source_sha256'],
          'requirement_sha256':row['requirement_sha256'],
          'earliest_phase':TEXT[str(n)][1],
          'applicability':'DUE' if due else 'FUTURE_PHASE',
          'native_original_machine_evidence':criteria if due else {},
          'source_scope':'MACHINE_OBSERVED' if due and all(criteria.values())
              else 'UNKNOWN' if due else 'FUTURE_PHASE',
          'full_rule_semantics':'UNKNOWN' if due else 'NOT_DUE',
          'individual_mg0':'UNKNOWN' if due else 'NOT_DUE',
          'owner_acceptance':'UNKNOWN','advancement_authorized':False}
    return {'schema':SCHEMA,'source_rule_count':40,'named_machine_criteria':80,
      'due_rule_count':sum(x['applicability']=='DUE' for x in out.values()),
      'future_rule_count':sum(x['applicability']=='FUTURE_PHASE' for x in out.values()),
      'asset':asset,'step':step,'master_sha256':work['master_sha256'],
      'attempt_id':work['attempt_id'],'operation_sha256':work['operation_sha256'],
      'original_audit_sha256':audit_sha,'original_audit_tail':tail,
      'full_semantic_passes':0,'individual_mg0_passes':0,
      'advancement_authorized':False,'rules':out}

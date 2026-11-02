"""C07 P7 Q167-Q170 macro: source-specific tool/engine provenance firewall.

Four original-source preflight readers share one Controller attempt and
cross-check GLB, editable Blender blocks, XML shader/source bindings, YMAP
positions, decoded renders, budgets and numeric samples. An addon name in
JSON or a FiveM-labelled log is NEVER independent execution provenance.
No source-only evidence may yield a full operational PASS.
"""
import hashlib
import math
import re

from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p7_rage_semantics import (
    inspect as original_ten, IDS, _xml, _entities, _archetypes, value, nodes)
from c07_p8_delivery_macro_full_review import blender_blocks
from c07_p4_material_macro_full_review import original_drawable_shader_compatibility
from c07_p4_texture_semantics import _embedded
from c07_p5_budget_semantics import _glb_parts
from c07_p1_thirty_native_domain import jbytes
from visual_content_metrics import decode_grid,VisualContentBlocked

RULES=frozenset(IDS[6:])
METRICS={
167:('original_editable_blend_has_structural_dna_and_current_source_hash',
     'original_sollumz_export_trace_binds_native_geometry_to_exact_editable',
     'independent_sollumz_application_execution_provenance'),
168:('original_drawable_and_export_shader_sources_sha_pinned',
     'all_native_materials_textures_and_vertices_match_original_shader_map',
     'independent_rage_runtime_supported_material_execution_provenance'),
169:('original_ymap_ytyp_native_placement_and_codewalker_positions_agree',
     'three_original_visual_rasters_distinct_and_lod_valid',
     'independent_codewalker_preview_session_provenance'),
170:('original_fivem_log_current_operation_and_perf_budget_sha_pinned',
     'original_numeric_frames_satisfy_precommitted_performance_budget',
     'independent_fivem_engine_execution_and_player_acceptance_provenance')}
class P7FourProvenanceBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise P7FourProvenanceBlocked(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def finite(x):return type(x) in (int,float) and math.isfinite(x)
def inspect(ctx,rid):
    need(type(ctx) is dict and set(ctx)=={
        'inventory','plan','controller','asset','step','work','source_loader'}
        and rid in RULES,'C07_Q_FOUR_CURRENT_SOURCE_CONTEXT')
    inv,plan,controller,asset,step,work,loader=(
        ctx[k] for k in ('inventory','plan','controller','asset',
                         'step','work','source_loader'))
    baseline=original_ten(inv,plan,controller,asset,step,work,
                          source_loader=loader)
    audit,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(baseline['original_audit_sha256']==audit_sha and
         baseline['original_audit_tail']==tail and
         state.get('last_audit_hash')==tail and
         sha(controller.master.read_bytes())==work['master_sha256'],
         'C07_Q_FOUR_CURRENT_AUDIT_OR_MASTER_INVALID')
    pins=plan.get('p678_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_Q_FOUR_ORIGINAL_SHA_PINS_REQUIRED')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,loader,work):
        need(role not in found,'C07_Q_FOUR_DUPLICATE_SOURCE_ROLE')
        found[role]=(path,digest,raw)
    def original(role,extension):
        v=found.get(role)
        return v[2] if (v and v[0].lower().endswith(extension)
            and pins.get(role)==v[1] and sha(v[2])==v[1]) else None
    number=int(rid[-3:])
    native=original('NATIVE_EXPORT','.glb')
    drawable=original('P7_YDR_XML','.xml')
    ytyp=original('P7_YTYP_XML','.xml')
    ymap=original('P7_YMAP_XML','.xml')
    trace=original('P7_EXPORT_TRACE','.json')
    editable=original('SOURCE_EDITABLE','.blend')
    checks=[False,False,False]
    complete=False
    measurements={}
    if number==167:
        complete=bool(native and editable and trace)
        data=jbytes(trace) if trace else {}
        actual=bool(complete and blender_blocks(editable))
        matched=bool(actual and data.get('addon')=='Sollumz'
            and data.get('source_sha256')==sha(editable)
            and data.get('export_sha256')==sha(native)
            and data.get('asset')==asset)
        if native:
            try:
                glb,_=_glb_parts(native)
                matched=bool(matched and glb.get('meshes') and
                             glb.get('accessors'))
            except (ValueError,TypeError,KeyError,IndexError):
                matched=False
        checks=[actual,matched,False]
        measurements={'blender_sdna_structure_reopened':actual,
                      'source_export_trace_sha_matches':matched}
    elif number==168:
        policy=original('P7_SHADER_POLICY','.json')
        complete=bool(native and drawable and policy)
        data=jbytes(policy) if policy else {}
        xml=_xml(drawable,'Drawable') if drawable else None
        good=False;bindings=False
        if complete:
            try:
                doc,binary=_glb_parts(native)
                images=_embedded(doc,binary)
                good,bindings=original_drawable_shader_compatibility(
                    drawable,doc,data,images)
            except (ValueError,TypeError,KeyError,IndexError):
                pass
        checks=[bool(complete and good),bool(bindings),False]
        measurements={'drawable_shader_source_valid':good,
                      'all_native_material_bindings_valid':bindings}
    elif number==169:
        cw=original('P7_CODEWALKER_REPORT','.json')
        policy=original('P7_SHADER_POLICY','.json')
        photos=[original('P7_VIEW_'+name,'.png')
                for name in ('FRONT','SIDE','TOP')]
        complete=bool(native and ytyp and ymap and cw and policy
                      and all(photos))
        positions_ok=False
        pixel_ok=False
        if complete:
            data=jbytes(cw)
            archetypes=_archetypes(_xml(ytyp,'CMapTypes'))
            entities=_entities(_xml(ymap,'CMapData'))
            reported=data.get('entity_positions')
            places=bool(archetypes and entities and
                all(name in archetypes for name,_ in entities) and
                type(reported) is list and
                len(reported)==len(entities) and
                all(type(x) is dict and type(x.get('archetype')) is str
                    and type(x.get('xyz')) is list and len(x['xyz'])==3
                    and all(finite(k) for k in x['xyz']) for x in reported))
            positions_ok=bool(places and sorted(
                (x['archetype'].casefold(),tuple(x['xyz'])) for x in reported
                )==sorted((n,tuple(v)) for n,v in entities))
            try:
                decoded=[decode_grid(raw,step=1) for raw in photos]
                pixel_ok=bool(positions_ok and
                    all(w>=2 and h>=2 and len(pixels)==w*h
                        for w,h,pixels in decoded) and
                    len({sha(bytes(v for p in colors for v in p))
                         for _,_,colors in decoded})==3 and
                    finite(data.get('lod_near_m')) and
                    finite(data.get('lod_far_m')) and
                    0<=data['lod_near_m']<data['lod_far_m'])
            except (VisualContentBlocked,ValueError,TypeError,KeyError):
                pass
        checks=[positions_ok,pixel_ok,False]
        measurements={'original_ymap_codewalker_labels_match':positions_ok,
                      'three_original_raster_pixels_and_lod':pixel_ok}
    else:
        log=original('P7_FIVEM_LOG','.json')
        budget=original('P7_RUNTIME_BUDGET','.json')
        complete=bool(native and log and budget)
        data=jbytes(log) if log else {}
        limits=jbytes(budget) if budget else {}
        frames=data.get('frame_ms_samples')
        structured=bool(complete and data.get('engine')=='FiveM'
            and data.get('asset')==asset
            and type(frames) is list and 10<=len(frames)<=2000 and
            all(finite(x) and 0<x<10000 for x in frames)
            and finite(limits.get('target_frame_ms'))
            and 0<limits['target_frame_ms']<=100)
        within=bool(structured and
            sorted(frames)[math.ceil(.95*len(frames))-1] <=
                limits['target_frame_ms'])
        checks=[structured,within,False]
        measurements={'source_log_structurally_valid':structured,
                      'source_claimed_p95_within_budget':within}
    need(len(checks)==3 and all(type(x) is bool for x in checks)
         and checks[2] is False,
         'C07_Q_FOUR_UNATTESTED_TOOL_RUNTIME_CANNOT_PASS')
    return dict(rule_id=rid,checks=dict(zip(METRICS[number],checks)),
       evidence_complete=complete,source_qa_measurements=measurements,
       actual_tool_execution_provenance='UNVERIFIED',
       source_scope='STATIC_PREFLIGHT_ONLY',full_rule_semantics='UNKNOWN',
       individual_mg0='UNKNOWN',owner_approval='UNKNOWN',
       fivem_runtime='UNVERIFIED',advancement_authorized=False,
       attempt_id=work['attempt_id'],
       operation_sha256=work['operation_sha256'],
       original_audit_sha256=audit_sha,original_audit_tail=tail)

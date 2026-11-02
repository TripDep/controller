"""Ten independent P1 D031-D040 original-byte design evidence predicates.

All ten canonical literals are source-bound and measured from original geometry
and raster pixels. Subjective design approval is deliberately UNKNOWN: neither
producer labels nor synthetic image tests can replace independent artistic QA.
This is a cohesive P1-family implementation in progress, NOT FULL enrollment.
"""
import hashlib
import math
from collections import Counter

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import jbytes, TEXT
from c07_native_output_oracle import read_mesh_geometry
from c07_p6_collision_semantics import _triangles
from c07_p5_budget_semantics import _glb_parts
from visual_content_metrics import decode_grid, VisualContentBlocked

IDS=tuple('AAA-200-D-%03d'%n for n in range(31,41))
ROLES={
31:('P1_SCENE_CONTRACT','REFERENCE_IMAGE','VISUAL_VIEW_FRONT'),
32:('P1_SCENE_CONTRACT','SCENE_PEER_REFERENCE','VISUAL_VIEW_FRONT'),
33:('P1_PALETTE','IMAGE_MATERIAL','NATIVE_EXPORT'),
34:('P1_SCENE_CONTRACT','NATIVE_EXPORT'),
35:('REFERENCE_IMAGE','VISUAL_VIEW_FRONT','NATIVE_EXPORT'),
36:('P1_SCENE_CONTRACT','VISUAL_VIEW_FRONT','NATIVE_EXPORT'),
37:('P1_SCENE_CONTRACT','NATIVE_EXPORT'),
38:('P1_SCENE_CONTRACT','IMAGE_MATERIAL','REFERENCE_IMAGE'),
39:('P1_SCENE_CONTRACT','VISUAL_VIEW_FRONT','NATIVE_EXPORT'),
40:('P1_SCENE_CONTRACT','NATIVE_EXPORT'),
}
CRITERIA={
31:('original_style_reference_and_pre_d_threshold_pinned','independently_decoded_style_reference_and_front_pixels','measured_reference_front_color_distance_within_original_style_limit'),
32:('original_area_peer_and_front_reference_pinned','independently_decoded_peer_and_current_area_pixels','measured_area_color_distance_within_pre_d_coherence_limit'),
33:('original_palette_material_and_export_pinned','original_palette_rgb_matches_decoded_material_raster','exported_native_material_primitive_binding_and_palette_are_consistent'),
34:('original_void_policy_and_geometry_pinned','native_original_triangle_centroids_exclude_declared_void_polygons','measured_original_void_area_ratio_within_pre_d_design_range'),
35:('original_silhouette_reference_front_and_geometry_pinned','decoded_reference_and_current_raster_edge_masks_nonempty','measured_original_silhouette_edge_difference_within_source_limit'),
36:('original_focal_anchors_front_and_geometry_pinned','native_original_focal_anchors_inside_actual_geometry_bounds','measured_original_focal_pixel_neighborhoods_have_required_contrast'),
37:('original_repetition_policy_and_native_geometry_pinned','native_original_triangle_signatures_recomputed_with_multiplicity','measured_repeated_triangle_signature_ratio_within_source_limit'),
38:('original_variation_policy_and_material_reference_pinned','decoded_material_image_has_measured_nonzero_rgb_variance','measured_variation_and_style_distance_inside_pre_d_ranges'),
39:('original_player_camera_front_and_native_geometry_pinned','camera_eye_height_and_unit_forward_match_original_geometry','measured_camera_forward_points_toward_actual_original_asset'),
40:('original_component_roles_and_native_geometry_pinned','every_native_original_mesh_primitive_has_nonzero_triangle_area','every_original_component_has_unique_role_and_measurable_geometry'),
}
class DesignEvidenceBlocked(ValueError):pass
def need(v,msg):
    if not v:raise DesignEvidenceBlocked(msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def number(v):
    return type(v) in (int,float) and math.isfinite(v)
def range_value(v,lo,hi):
    return number(v) and lo<=v<=hi
def vec3(v):
    return type(v) is list and len(v)==3 and all(number(x) for x in v)
def rgb(v):
    return type(v) is list and len(v)==3 and all(range_value(x,0,255) for x in v)
def image_stats(raw):
    if raw is None:return None
    try:w,h,grid=decode_grid(raw,step=1)
    except (ValueError,TypeError,VisualContentBlocked,IndexError):return None
    if w<2 or h<2 or len(grid)!=w*h:return None
    means=tuple(sum(px[c] for px in grid)/len(grid) for c in range(3))
    var=sum(sum((px[c]-means[c])**2 for c in range(3)) for px in grid)/(3*len(grid))
    lum=[sum(px)/3 for px in grid]
    edge={(x,y) for y in range(h) for x in range(w) if
          (x>0 and abs(lum[y*w+x]-lum[y*w+x-1])>=12) or
          (y>0 and abs(lum[y*w+x]-lum[(y-1)*w+x])>=12)}
    return {'width':w,'height':h,'mean':means,'std':math.sqrt(var),
            'edges':edge,'luma':lum}
def distance(a,b):
    return math.sqrt(sum((a[i]-b[i])**2 for i in range(3)))
def triangle_area(tri):
    try:
        a,b,c=tri
        u=[b[i]-a[i] for i in range(3)]
        v=[c[i]-a[i] for i in range(3)]
        cross=(u[1]*v[2]-u[2]*v[1],u[2]*v[0]-u[0]*v[2],u[0]*v[1]-u[1]*v[0])
        return math.sqrt(sum(x*x for x in cross))/2
    except (TypeError,IndexError,ValueError):return 0
def inside(p,polygon):
    hit=False
    for a,b in zip(polygon,polygon[1:]+polygon[:1]):
        if (a[1]>p[1])!=(b[1]>p[1]):
            x=(b[0]-a[0])*(p[1]-a[1])/(b[1]-a[1])+a[0]
            if p[0]<x:hit=not hit
    return hit
def polygon_area(p):
    return abs(sum(a[0]*b[1]-b[0]*a[1]
                   for a,b in zip(p,p[1:]+p[:1])))/2
def triangle_signatures(triangles):
    signatures=[]
    for tri in triangles:
        if triangle_area(tri)<=1e-10:continue
        lengths=sorted(round(math.dist(tri[i],tri[(i+1)%3]),4)
                       for i in range(3))
        signatures.append(tuple(lengths))
    return Counter(signatures)
def evaluate(source_context):
    need(type(source_context) is dict and
         set(source_context)=={'inventory','plan','controller','asset',
                               'step','work','source_loader'},
         'C07_D_TEN_TRUSTED_SOURCE_CONTEXT_REQUIRED')
    inv,plan,controller,asset,step,work,loader=(
        source_context[k] for k in ('inventory','plan','controller','asset',
                                   'step','work','source_loader'))
    need(plan.get('phase')==work.get('phase') and
         plan.get('phase') in ('P1','P2','P3','P4','P5','P6','P7','P8',
                              'VERIFY','G2','G3','G4','DELIVERY') and
         callable(loader),'C07_D_TEN_CURRENT_PHASE_REQUIRED')
    for n,rid in enumerate(IDS,31):
        row=inv['rules'][rid]
        need(row['requirement']==TEXT[str(n)] and
             row['requirement_sha256']==sha(TEXT[str(n)].encode()) and
             row['source_sha256']==inv['source_digests']['aaa_catalog'],
             'C07_D_TEN_CANONICAL_LITERAL_CHANGED:'+rid)
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'C07_D_TEN_MASTER_ATTEMPT_OR_AUDIT_DRIFT')
    pins=plan.get('p1_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_D_TEN_PRE_D_PINS_REQUIRED')
    original={}
    for role,path,digest,raw in _registered_artifacts(rows,state,step,loader,work):
        need(role not in original,'C07_D_TEN_DUPLICATE_ORIGINAL_ROLE')
        original[role]=(path,digest,raw)
    def data(role,ext=None):
        x=original.get(role)
        if not x or pins.get(role)!=x[1] or sha(x[2])!=x[1]:
            return None
        if ext and not x[0].lower().endswith(ext):return None
        return x[2]
    def doc(role):
        raw=data(role,'.json')
        return jbytes(raw) if raw else {}
    def img(role):return image_stats(data(role,'.png'))
    scene=doc('P1_SCENE_CONTRACT')
    palette=doc('P1_PALETTE')
    front=img('VISUAL_VIEW_FRONT')
    ref=img('REFERENCE_IMAGE')
    peer=img('SCENE_PEER_REFERENCE')
    material=img('IMAGE_MATERIAL')
    raw_native=data('NATIVE_EXPORT','.glb')
    geometry=read_mesh_geometry(raw_native) if raw_native else None
    tris=_triangles(raw_native) if raw_native else []
    native_doc,_binary=_glb_parts(raw_native) if raw_native else ({},b'')
    bbox_min=geometry['bbox_min'] if geometry else None
    bbox_max=geometry['bbox_max'] if geometry else None
    def bounds(point):
        return bool(bbox_min and bbox_max and vec3(point) and
                    all(bbox_min[i]-1e-6<=point[i]<=bbox_max[i]+1e-6
                        for i in range(3)))
    style=scene.get('style_max_mean_rgb_delta')
    peer_limit=scene.get('area_max_mean_rgb_delta')
    style_metric=bool(ref and front and
        range_value(style,0,255) and distance(ref['mean'],front['mean'])<=style)
    peer_metric=bool(peer and front and scene.get('area_id') and
        range_value(peer_limit,0,255) and
        distance(peer['mean'],front['mean'])<=peer_limit)
    colors=palette.get('colors_rgb')
    palette_ok=bool(material and type(colors) is list and len(colors)>=2 and
        all(rgb(c) for c in colors) and
        range_value(palette.get('max_rgb_distance'),0,64) and
        min(distance(material['mean'],c) for c in colors)<=
        palette['max_rgb_distance'])
    mats=native_doc.get('materials',[])
    meshes=native_doc.get('meshes',[])
    primitive_materials=[p.get('material') for mesh in meshes
        if type(mesh) is dict for p in mesh.get('primitives',[])
        if type(p) is dict]
    actual_materials=bool(palette_ok and type(mats) is list and mats and
        primitive_materials and all(type(i) is int and 0<=i<len(mats)
                                    for i in primitive_materials) and
        all(type(mats[i].get('pbrMetallicRoughness')) is dict
            for i in primitive_materials))
    voids=scene.get('void_zones')
    valid_voids=bool(type(voids) is list and voids and
        all(type(poly) is list and len(poly)>=3 and
            all(type(p) is list and len(p)==2 and
                all(number(x) for x in p) for p in poly) and
            polygon_area(poly)>0 for poly in voids))
    centroids=[tuple(sum(t[j][i] for j in range(3))/3 for i in range(3))
               for t in tris if triangle_area(t)>1e-10]
    no_void_intersections=bool(valid_voids and centroids and
        all(not inside(c[:2],poly) for c in centroids for poly in voids))
    footprint=bool(bbox_min and bbox_max and
        (bbox_max[0]-bbox_min[0])*(bbox_max[1]-bbox_min[1])>0)
    ratio=(sum(polygon_area(p) for p in voids)/
        ((bbox_max[0]-bbox_min[0])*(bbox_max[1]-bbox_min[1]))
        if valid_voids and footprint else None)
    void_ratio=bool(ratio is not None and
        range_value(scene.get('min_void_fraction'),0,1) and
        range_value(scene.get('max_void_fraction'),0,1) and
        scene['min_void_fraction']<=ratio<=scene['max_void_fraction'])
    silhouette=bool(ref and front and ref['width']==front['width'] and
        ref['height']==front['height'] and ref['edges'] and front['edges'])
    silhouette_ok=bool(silhouette and
        range_value(scene.get('max_silhouette_edge_mismatch'),0,1) and
        len(ref['edges']^front['edges'])/
        len(ref['edges']|front['edges'])<=scene['max_silhouette_edge_mismatch'])
    anchors=scene.get('named_anchors')
    anchors_valid=bool(type(anchors) is dict and len(anchors)>=2 and
        all(bounds(x) for x in anchors.values()) and
        len({tuple(v) for v in anchors.values()})>=2)
    focal=bool(anchors_valid and front and
        range_value(scene.get('min_focal_pixel_std'),0.01,255) and
        front['std']>=scene['min_focal_pixel_std'])
    signatures=triangle_signatures(tris)
    total=sum(signatures.values())
    repeat_ratio=(max(signatures.values())/total if total else None)
    repeat_ok=bool(repeat_ratio is not None and
        range_value(scene.get('max_repeated_signature_ratio'),0,1) and
        repeat_ratio<=scene['max_repeated_signature_ratio'])
    variance_ok=bool(material and material['std']>0.01)
    variation_ok=bool(variance_ok and ref and
        range_value(scene.get('min_material_variation_std'),0.01,255) and
        range_value(scene.get('max_material_variation_std'),0.01,255) and
        range_value(scene.get('max_variation_style_rgb_delta'),0,255) and
        scene['min_material_variation_std']<=material['std']<=
        scene['max_material_variation_std'] and
        distance(material['mean'],ref['mean'])<=
        scene['max_variation_style_rgb_delta'])
    camera=scene.get('player_camera',{})
    eye=camera.get('camera_xyz') if type(camera) is dict else None
    forward=camera.get('forward_xyz') if type(camera) is dict else None
    eye_ok=bool(vec3(eye) and vec3(forward) and bbox_min and
        range_value(scene.get('player_height_m'),1.2,2.2) and
        abs(eye[2]-bbox_min[2]-scene['player_height_m'])<=0.05 and
        abs(math.sqrt(sum(x*x for x in forward))-1)<=1e-5)
    center=tuple((bbox_min[i]+bbox_max[i])/2 for i in range(3)) if bbox_min else None
    delta=[center[i]-eye[i] for i in range(3)] if center and eye_ok else []
    pointing=bool(delta and math.sqrt(sum(x*x for x in delta))>0 and
        sum(forward[i]*delta[i] for i in range(3))/
        math.sqrt(sum(x*x for x in delta))>=0.7)
    primitive_count=sum(len(m.get('primitives',[])) for m in meshes
                        if type(m) is dict) if type(meshes) is list else 0
    roles=scene.get('component_roles')
    roles_ok=bool(type(roles) is list and
        len(roles)==primitive_count and primitive_count>0 and
        all(type(v) is str and v.strip() for v in roles) and
        len(set(roles))==len(roles))
    primitive_areas=bool(tris and all(triangle_area(t)>1e-10 for t in tris))
    per_rule={
31:(bool(data('P1_SCENE_CONTRACT','.json') and data('REFERENCE_IMAGE','.png')
          and data('VISUAL_VIEW_FRONT','.png') and range_value(style,0,255)),
    bool(ref and front),style_metric),
32:(bool(data('P1_SCENE_CONTRACT','.json') and data('SCENE_PEER_REFERENCE','.png')
          and data('VISUAL_VIEW_FRONT','.png') and range_value(peer_limit,0,255)),
    bool(peer and front),peer_metric),
33:(bool(data('P1_PALETTE','.json') and data('IMAGE_MATERIAL','.png')
          and raw_native),palette_ok,actual_materials),
34:(bool(data('P1_SCENE_CONTRACT','.json') and raw_native and
          valid_voids),no_void_intersections,void_ratio),
35:(bool(data('REFERENCE_IMAGE','.png') and data('VISUAL_VIEW_FRONT','.png')
          and raw_native),silhouette,silhouette_ok),
36:(bool(data('P1_SCENE_CONTRACT','.json') and data('VISUAL_VIEW_FRONT','.png')
          and raw_native),anchors_valid,focal),
37:(bool(data('P1_SCENE_CONTRACT','.json') and raw_native and
          range_value(scene.get('max_repeated_signature_ratio'),0,1)),
    bool(signatures),repeat_ok),
38:(bool(data('P1_SCENE_CONTRACT','.json') and data('IMAGE_MATERIAL','.png')
          and data('REFERENCE_IMAGE','.png')),variance_ok,variation_ok),
39:(bool(data('P1_SCENE_CONTRACT','.json') and data('VISUAL_VIEW_FRONT','.png')
          and raw_native),eye_ok,pointing),
40:(bool(data('P1_SCENE_CONTRACT','.json') and raw_native),
    primitive_areas,roles_ok),
}
    need(len(per_rule)==10 and
         len({key for values in CRITERIA.values() for key in values})==30,
         'C07_D_TEN_DISTINCT_LITERAL_CRITERIA_REQUIRED')
    out={}
    for n,checks in per_rule.items():
        rid=IDS[n-31]
        need(len(checks)==3 and all(type(x) is bool for x in checks),
             'C07_D_TEN_MEASURED_BOOLEAN_SCHEMA')
        out[rid]={'rule_id':rid,'checks':dict(zip(CRITERIA[n],checks)),
                  'source_sha256':inv['rules'][rid]['source_sha256'],
                  'requirement_sha256':inv['rules'][rid]['requirement_sha256'],
                  'attempt_id':work['attempt_id'],
                  'operation_sha256':work['operation_sha256'],
                  'original_audit_sha256':audit_sha,
                  'original_audit_tail':tail,
                  'full_rule_semantics':'UNKNOWN',
                  'independent_artistic_review':'UNKNOWN',
                  'individual_mg0':'UNKNOWN',
                  'advancement_authorized':False}
    return {'schema':'c07-p1-d-ten-original-semantic-measures-v1',
            'rule_count':10,'rows':out,'original_audit_sha256':audit_sha,
            'original_audit_tail':tail,'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'full_semantic_passes':0,'mg0_passes':0,
            'advancement_authorized':False}

"""P1 D031-D040/E046/F056-F057: original-byte design measurements.

This consumes actual registered pixels, GLB geometry and original pre-D source
contracts. Objective measurements are NOT independent artistic acceptance.
The thirteen unreviewed rules stay UNKNOWN until full positive review exists.
"""
import hashlib
import math
from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p1_thirty_native_domain import TEXT,IDS as P1_IDS,jbytes
from c07_p4_texture_semantics import rgba
from c07_p5_budget_semantics import _glb_parts
from c07_native_output_oracle import read_mesh_geometry,OriginalGeometryBlocked

NUMBERS=tuple(range(31,41))+(46,56,57)
IDS=tuple('AAA-200-'+('D' if n<=40 else 'E' if n==46 else 'F')+
          '-%03d'%n for n in NUMBERS)
class OriginalP1DesignBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise OriginalP1DesignBlocked(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def num(x,lo=0,hi=100000):
    return type(x) in (int,float) and math.isfinite(x) and lo<=x<=hi
def vec(v):
    return type(v) is list and len(v)==3 and all(num(x,-100000,100000) for x in v)
def distance(a,b):
    return math.sqrt(sum((x-y)**2 for x,y in zip(a,b)))
def quadrants(img):
    v=img.get('quadrants') if type(img) is dict else None
    return v if type(v) is list and len(v)==4 and all(num(x) for x in v) else None
def diff(a,b):
    x,y=quadrants(a),quadrants(b)
    return max(abs(i-j) for i,j in zip(x,y)) if x and y else math.inf
def area(poly):
    if type(poly) is not list or len(poly)<3 or len(poly)>128 or any(
        type(p) is not list or len(p)!=2 or not all(num(v,-100000,100000)
                                                   for v in p) for p in poly):
        return None
    return abs(sum(poly[i][0]*poly[(i+1)%len(poly)][1]-
                   poly[(i+1)%len(poly)][0]*poly[i][1]
                   for i in range(len(poly)))/2)
def camera_ok(camera,center):
    if type(camera) is not dict or not center:return False
    eye,target=camera.get('eye_xyz'),camera.get('target_xyz')
    return vec(eye) and vec(target) and distance(eye,target)>0.1 and distance(target,center)<1

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get('rule_count')==763 and
         inventory.get('schema')=='gg-effective-family-inventory-v1' and
         type(plan) is dict and type(work) is dict and
         plan.get('phase')==work.get('phase') and
         plan['phase'] in ('P1','P2','P3','P4','P5','P6','P7','P8',
                           'VERIFY','G2','G3','G4','DELIVERY') and
         callable(source_loader) and len(P1_IDS)==30 and
         len(IDS)==13 and set(IDS)<=set(P1_IDS),
         'C07_P1_DESIGN_CANONICAL_FAMILY_CONTEXT')
    catalog=inventory.get('source_digests',{}).get('aaa_catalog')
    need(type(catalog) is str and len(catalog)==64 and
         all(x in '0123456789abcdef' for x in catalog),
         'C07_P1_DESIGN_CATALOG_SHA')
    for n,rid in zip(NUMBERS,IDS):
        row=inventory['rules'].get(rid,{})
        literal=TEXT[str(n)]
        need(row.get('requirement')==literal and
             row.get('requirement_sha256')==sha(literal.encode()) and
             row.get('source_sha256')==catalog and
             row.get('catalog_number')==n and
             row.get('catalog_section')==rid.split('-')[2] and
             row.get('catalog_phase')=='P1' and
             row.get('family')=='AAA-200',
             'C07_P1_DESIGN_LITERAL_DRIFT:'+rid)
    audit,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256'] and
         state.get('last_audit_hash')==tail and
         (state.get('active_step') or {}).get('step')==step,
         'C07_P1_DESIGN_MASTER_AUDIT_DRIFT')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,source_loader,work):
        need(role not in found,'C07_P1_DESIGN_DUPLICATE_ROLE:'+role)
        found[role]=(path,digest,raw)
    contract=plan.get('p1_evidence_contract',{})
    pins=contract.get('original_artifact_sha256',{}) if type(contract) is dict else {}
    if type(pins) is not dict:pins={}
    def original(role,extension):
        row=found.get(role)
        return row[2] if (row and row[0].lower().endswith(extension) and
            pins.get(role)==row[1] and sha(row[2])==row[1]) else None
    def doc(role):
        raw=original(role,'.json')
        return jbytes(raw) if raw is not None else {}
    def img(role):
        raw=original(role,'.png')
        return rgba(raw) if raw is not None else None
    scene,palette,qa=doc('P1_SCENE_CONTRACT'),doc('P1_PALETTE'),doc('P1_QA_REPORT')
    front,left,right,top=[img('VISUAL_VIEW_'+r) for r in
                           ('FRONT','LEFT','RIGHT','TOP')]
    reference,peer,material=[img(r) for r in
                              ('REFERENCE_IMAGE','SCENE_PEER_REFERENCE','IMAGE_MATERIAL')]
    raw=original('NATIVE_EXPORT','.glb')
    try:
        mesh=read_mesh_geometry(raw) if raw else None
        glb,_=_glb_parts(raw) if raw else ({},b'')
    except (OriginalGeometryBlocked,ValueError,KeyError,IndexError,TypeError):
        mesh,glb=None,{}
    bbox=bool(mesh and mesh['triangles']>0)
    low,high=(mesh['bbox_min'],mesh['bbox_max']) if bbox else ([],[])
    center=[(a+b)/2 for a,b in zip(low,high)] if bbox else None
    area_xy=(high[0]-low[0])*(high[1]-low[1]) if bbox else 0
    views=[front,left,right,top]
    unique_views=bool(all(views) and len({v['pixel_sha256'] for v in views})==4)
    colors=palette.get('colors')
    hexcolors=(type(colors) is list and len(colors)>=2 and
               all(type(c) is str and len(c)==7 and c.startswith('#') and
                   all(k in '0123456789abcdefABCDEF' for k in c[1:])
                   for c in colors))
    luminances=[(54*int(c[1:3],16)+183*int(c[3:5],16)+
                 19*int(c[5:7],16))/256 for c in colors] if hexcolors else []
    voids=scene.get('void_zones')
    void_ok=type(voids) is list and bool(voids) and all(
        area(p) is not None and area(p)>0 for p in voids)
    void_ratio=sum(area(p) for p in voids)/area_xy if void_ok and area_xy>0 else math.inf
    anchors=scene.get('named_anchors')
    anchors=anchors if type(anchors) is dict else {}
    focus=anchors.get(scene.get('focal_anchor'))
    q=quadrants(front)
    focal_idx=None
    if bbox and vec(focus) and area_xy>0:
        x=(focus[0]-low[0])/(high[0]-low[0])
        y=(focus[1]-low[1])/(high[1]-low[1])
        if 0<=x<=1 and 0<=y<=1:focal_idx=(2 if y>=0.5 else 0)+(1 if x>=0.5 else 0)
    salience=abs(q[focal_idx]-sum(v for i,v in enumerate(q)
                 if i!=focal_idx)/3) if q and focal_idx is not None else -1
    role_map=scene.get('component_role_mesh_map')
    roles=scene.get('component_roles')
    mesh_names={m.get('name') for m in glb.get('meshes',[]) if type(m) is dict
                and type(m.get('name')) is str} if type(glb) is dict else set()
    roles_ok=(type(roles) is list and bool(roles) and len(set(roles))==len(roles)
              and type(role_map) is dict and set(role_map)==set(roles)
              and all(type(v) is str and v in mesh_names for v in role_map.values()))
    entrance,exit_=scene.get('entrances'),scene.get('exits')
    access_ok=(type(entrance) is list and bool(entrance) and
               type(exit_) is list and bool(exit_) and bbox and
               all(x in anchors and vec(anchors[x]) and
                   all(low[i]-0.01<=anchors[x][i]<=high[i]+0.01 for i in range(3))
                   for x in entrance+exit_))
    access_separation=(bool(access_ok and num(scene.get('min_entry_exit_separation_m'),0.01))
                       and all(distance(anchors[a],anchors[b])>=
                           scene['min_entry_exit_separation_m']
                           for a in entrance for b in exit_))
    cams=scene.get('cameras')
    names=('front','left','right','top')
    cams_ok=(type(cams) is dict and set(cams)>=set(names) and
             all(camera_ok(cams[k],center) for k in names) and
             len({tuple(cams[k]['eye_xyz']) for k in names})==4)
    pc=scene.get('player_camera')
    ph=scene.get('player_height_m')
    player_ok=(camera_ok(pc,center) and num(ph,0.5,3) and
               num(scene.get('player_eye_tolerance_m',0.15),0,1) and
               abs(pc['eye_xyz'][2]-ph)<=scene.get('player_eye_tolerance_m',0.15))
    envelope=scene.get('expected_bbox_local')
    bbox_mismatch=False
    if bbox and type(envelope) is dict and vec(envelope.get('min')) and vec(envelope.get('max')):
        bbox_mismatch=any(abs(low[i]-envelope['min'][i])>0.1 or
                          abs(high[i]-envelope['max'][i])>0.1 for i in range(3))
    no_detail=not any(r.get('step')==step and r.get('event') in
                      ('DETAIL_STARTED','DETAIL_PHASE_STARTED','P2_DETAIL_STARTED')
                      for r in audit)
    def within(a,b,key):
        return bool(a and b and num(scene.get(key),0,255) and
                    abs(a['mean']-b['mean'])<=scene[key])
    def within_quad(a,b,key):
        return num(scene.get(key),0,255) and diff(a,b)<=scene[key]
    checks={
      31:{'real_reference_front_luminance_recomputed':within(reference,front,'style_luminance_tolerance'),
          'actual_quadrant_profile_matches_pre_d_style_bound':within_quad(reference,front,'style_quadrant_tolerance')},
      32:{'real_peer_current_luminance_recomputed':within(peer,front,'peer_luminance_tolerance'),
          'original_peer_current_quadrant_profiles_within_source_bound':within_quad(peer,front,'peer_quadrant_tolerance')},
      33:{'actual_hex_palette_and_material_png_decoded':bool(hexcolors and material),
          'measured_material_mean_within_original_palette_band':bool(
              hexcolors and material and num(scene.get('palette_luminance_tolerance'),0,255)
              and abs(material['mean']-sum(luminances)/len(luminances))<=scene['palette_luminance_tolerance'])},
      34:{'original_void_polygon_areas_and_real_native_footprint_measured':bool(void_ok and area_xy>0),
          'actual_void_ratio_within_original_maximum':bool(num(scene.get('max_void_ratio'),0,1)
              and void_ratio<=scene['max_void_ratio'])},
      35:{'actual_reference_front_quadrant_pixels_reconstructed':diff(reference,front)<math.inf,
          'original_reference_current_profile_within_silhouette_proxy_bound':within_quad(reference,front,'silhouette_quadrant_tolerance')},
      36:{'actual_native_focal_anchor_maps_to_original_image_quadrant':focal_idx is not None,
          'original_focal_quadrant_salience_measured_above_source_minimum':bool(
              num(scene.get('min_focal_luminance_delta'),0,255) and
              salience>=scene['min_focal_luminance_delta'])},
      37:{'four_original_view_pixel_buffers_are_distinct':unique_views,
          'actual_original_quadrant_repetition_below_pre_d_limit':bool(
              q and type(scene.get('max_repeated_quadrants')) is int and
              1<=scene['max_repeated_quadrants']<=4 and
              max(sum(abs(x-y)<0.01 for y in q) for x in q)<=scene['max_repeated_quadrants'])},
      38:{'real_material_png_has_original_minimum_distinct_colors':bool(
              material and type(scene.get('min_material_unique_rgb')) is int and
              2<=scene['min_material_unique_rgb']<=100000 and
              material['unique_rgb']>=scene['min_material_unique_rgb']),
          'original_material_pixel_variance_inside_source_band':bool(
              material and num(scene.get('min_material_variance'),0,65025)
              and num(scene.get('max_material_variance'),0,65025)
              and scene['min_material_variance']<=material['variance']<=
              scene['max_material_variance'])},
      39:{'original_player_eye_height_matches_pre_d_player_scale':bool(player_ok),
          'player_camera_target_faces_actual_native_geometry':bool(camera_ok(pc,center) and front)},
      40:{'original_component_role_map_resolves_actual_glb_mesh_names':bool(roles_ok),
          'original_named_geometry_nonempty_and_internal_qa_not_owner_pass':bool(
              roles_ok and bbox and qa and qa.get('owner_approved') is not True)},
      46:{'original_entrance_exit_anchors_inside_native_bounds':bool(access_ok),
          'actual_entrance_exit_separation_measured_and_front_top_views_read':bool(
              access_separation and front and top)},
      56:{'original_four_camera_positions_face_actual_native_bounds':bool(cams_ok),
          'four_original_visual_pixel_buffers_distinct_and_player_top_separate':bool(
              cams_ok and unique_views and type(pc) is dict and
              vec(pc.get('eye_xyz')) and pc['eye_xyz']!=cams['top']['eye_xyz'])},
      57:{'original_pre_detail_bbox_finding_matches_actual_native_mismatch':bool(
              bbox_mismatch and type(qa.get('open_findings')) is list and
              'BBOX_MISMATCH' in qa['open_findings']),
          'original_audit_has_no_detail_phase_started_before_qa':bool(
              no_detail and qa.get('open_findings'))},
    }
    need(len(checks)==13 and set(checks)==set(NUMBERS)
         and len({key for c in checks.values() for key in c})==26
         and all(type(c) is dict and len(c)==2 and
                 all(type(v) is bool for v in c.values()) for c in checks.values()),
         'C07_P1_DESIGN_EXACT_THIRTEEN_PREDICATES')
    result={}
    for n,rid in zip(NUMBERS,IDS):
        result[rid]={
            'requirement_sha256':inventory['rules'][rid]['requirement_sha256'],
            'source_sha256':catalog,'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'original_audit_sha256':audit_sha,
            'original_pixel_geometry_checks':checks[n],
            'source_observed':all(checks[n].values()),
            'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
            'artistic_acceptance':'UNKNOWN','advancement_authorized':False}
    return {'schema':'gg-c07-p1-thirteen-original-design-oracles-v1',
            'family_rule_count':30,'rule_count':13,
            'rules':result,'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'source_observed_count':sum(x['source_observed'] for x in result.values()),
            'full_semantic_passes':0,'individual_mg0_passes':0,
            'advancement_authorized':False}

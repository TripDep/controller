"""C07 P3/P4/P5: thirteen remaining literal-specific original-byte reviews.

This module deliberately returns source-scoped predicates, NOT FULL semantics:
an atlas decision, baking necessity, approved visual equivalence, renderer light
rig, occlusion intent, LOD transition, aesthetic reuse and FiveM profiling
cannot be inferred from a producer's policy or a registered PNG/JSON alone.
Each candidate is tied to the current Controller operation, canonical literal,
SHA-pinned pre-D sources and independently decoded native bytes.
"""
import hashlib
import math
import struct
from collections import Counter

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p345_forty_native_evidence import inspect as inspect_p345, binary_json, PHASE_INDEX
from c07_p5_budget_semantics import _glb_parts
from c07_p5_optimization_semantics import _mesh, _references
from c07_p5_full_review import material_bindings
from c07_p4_texture_semantics import rgba, _embedded
from c07_p6_collision_semantics import _triangles
from c07_p3_geometry_semantics import _read_accessor
from visual_content_metrics import decode_grid, VisualContentBlocked
from c07_p345_light_pixel_replay import pixel_light_response

NUMBERS=(118,119,120,133,134,135,136,139,140,143,145,147,150)
RULES=frozenset('AAA-200-'+('L' if n<=120 else 'N' if n<=140 else 'O')+
                '-%03d'%n for n in NUMBERS)
CRITERIA={
118:('pre_d_original_atlas_and_baseline_contract_sha_bound',
     'actual_native_and_baseline_material_texture_bindings_recomputed',
     'measured_original_atlas_binding_reduction_and_texture_quality_retained'),
119:('pre_d_original_bake_necessity_and_source_normal_map_sha_bound',
     'actual_exported_normal_texture_and_baked_png_pixels_redecoded',
     'actual_baked_map_channels_and_exported_normal_image_match'),
120:('pre_d_original_approved_mesh_and_current_export_sha_bound',
     'actual_approved_and_current_native_triangle_geometry_compared',
     'trusted_original_visual_approval_and_renderer_equivalence_confirmed'),
133:('pre_d_original_lighting_defect_policy_and_capture_sha_bound',
     'actual_original_native_triangles_and_defect_report_recomputed',
     'trusted_lighting_renderer_and_geometry_defect_provenance_confirmed'),
134:('pre_d_original_direct_light_policy_and_view_sha_bound',
     'actual_direct_light_pixels_and_original_pbr_materials_recomputed',
     'trusted_direct_light_renderer_and_physical_material_response_confirmed'),
135:('pre_d_original_shadow_policy_and_view_sha_bound',
     'actual_shadow_and_neutral_pixels_and_materials_recomputed',
     'trusted_shadow_renderer_and_physical_material_response_confirmed'),
136:('pre_d_original_reflective_material_policy_and_view_sha_bound',
     'actual_original_metal_glass_pbr_and_reflection_pixels_recomputed',
     'trusted_reflection_renderer_and_real_material_behavior_confirmed'),
139:('pre_d_original_underside_qa_scope_and_view_sha_bound',
     'actual_underside_pixels_and_unresolved_qa_findings_recomputed',
     'trusted_renderer_provenance_and_complete_defect_coverage_confirmed'),
140:('pre_d_original_separate_presentation_and_technical_qa_sha_bound',
     'actual_distinct_original_visual_capture_and_machine_report_recomputed',
     'trusted_independent_artistic_vs_technical_review_confirmed'),
143:('pre_d_original_hidden_face_policy_and_baseline_sha_bound',
     'actual_before_after_native_triangle_counts_and_bounds_recomputed',
     'original_hidden_face_intent_and_nonessential_geometry_proven'),
145:('pre_d_original_lod_transition_policy_and_views_sha_bound',
     'actual_original_near_far_lod_geometry_and_pixels_recomputed',
     'trusted_renderer_continuity_and_no_visible_lod_popping_confirmed'),
147:('pre_d_original_texture_reuse_and_quality_policy_sha_bound',
     'actual_shared_original_glb_image_bindings_and_pixels_recomputed',
     'independent_scene_quality_not_degraded_by_reuse_confirmed'),
150:('pre_d_original_platform_scene_benchmark_contract_sha_bound',
     'actual_registered_frame_samples_and_source_scene_bytes_recomputed',
     'trusted_real_fivem_runtime_capture_provenance_confirmed'),
}

class OriginalP345RemainingBlocked(ValueError):pass
def need(ok,reason):
    if not ok:raise OriginalP345RemainingBlocked(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def numeric(v):return type(v) in (int,float) and math.isfinite(v)
def positive(v):return numeric(v) and v>0
def rgb_different(a,b):
    return bool(a and b and a['pixel_sha256']!=b['pixel_sha256'] and
                a['width']==b['width'] and a['height']==b['height'])
def boxes_close(a,b,tol):
    return bool(a and b and numeric(tol) and 0<=tol<=10 and all(
        abs(a['bounds'][k][j]-b['bounds'][k][j])<=tol
        for k in range(2) for j in range(3)))
def triangle_counts(raw):
    """Compare native triangles with multiplicity AND front-face winding.

    A reversed triangle has the same three vertices and bounds but may be
    culled in the rendered asset. Cyclic index rotations preserve winding;
    reversed order does not. Atlas/approved-export comparisons must also
    inspect duplicate triangle multiplicity, not just the set of surfaces.
    """
    if raw is None:
        return None
    triangles = _triangles(raw)
    def oriented(triangle):
        vertices=tuple(tuple(float(c) for c in v) for v in triangle)
        return min(vertices[i:]+vertices[:i] for i in range(3))
    return Counter(oriented(triangle) for triangle in triangles)

def actual_primitive_texture_reuse(doc):
    """One image in two shader slots of ONE primitive is not texture reuse.

    Reuse must occur on at least two real triangle primitives with UV0 and
    valid material/texture/image source links, not unused material entries.
    """
    materials=doc.get('materials')
    textures=doc.get('textures')
    images=doc.get('images')
    if not all(type(t) is list for t in (materials,textures,images)):
        return {}
    usage={}
    for mesh in doc.get('meshes',[]):
        if type(mesh) is not dict or type(mesh.get('primitives')) is not list:
            return {}
        for primitive in mesh['primitives']:
            if (type(primitive) is not dict or
                    type(primitive.get('attributes')) is not dict or
                    'TEXCOORD_0' not in primitive['attributes']):
                continue
            material_id=primitive.get('material')
            if type(material_id) is not int or not 0<=material_id<len(materials):
                continue
            material=materials[material_id]
            if type(material) is not dict:
                continue
            pbr=material.get('pbrMetallicRoughness',{})
            if type(pbr) is not dict:
                continue
            binding=pbr.get('baseColorTexture')
            if type(binding) is not dict or type(binding.get('index')) is not int:
                continue
            idx=binding['index']
            if not 0<=idx<len(textures) or type(textures[idx]) is not dict:
                continue
            source=textures[idx].get('source')
            if type(source) is int and 0<=source<len(images):
                usage[source]=usage.get(source,0)+1
    return usage

def baked_normal_channels_valid(raw):
    """Reopen the actual PNG channels, not merely its SHA or color variance.

    Tangent-space normal maps encode a mostly outward-facing unit vector.
    A grayscale photograph renamed normal.png is not valid baked normals.
    """
    if raw is None:
        return False
    try:
        width,height,pixels=decode_grid(raw,step=1)
    except (ValueError,TypeError,VisualContentBlocked):
        return False
    if width<4 or height<4 or not pixels:
        return False
    good=0
    for red,green,blue in pixels:
        x,y,z=(red/127.5-1,green/127.5-1,blue/127.5-1)
        length=math.sqrt(x*x+y*y+z*z)
        if z>=0.3 and 0.8<=length<=1.2:
            good+=1
    return good>=math.ceil(0.95*len(pixels))

def read_original_uv2(doc,binary,index):
    """Bounded native GLTF VEC2 float accessor (VEC3 geometry reader excludes UV)."""
    accessors=doc.get('accessors')
    views=doc.get('bufferViews')
    if (type(index) is not int or type(accessors) is not list
            or type(views) is not list or not 0<=index<len(accessors)):
        return None
    accessor=accessors[index]
    if (type(accessor) is not dict or accessor.get('type')!='VEC2'
            or accessor.get('componentType')!=5126
            or 'sparse' in accessor or type(accessor.get('count')) is not int
            or not 3<=accessor['count']<=10000000):
        return None
    vi=accessor.get('bufferView')
    if type(vi) is not int or not 0<=vi<len(views):
        return None
    view=views[vi]
    if type(view) is not dict or view.get('buffer')!=0:
        return None
    base=view.get('byteOffset',0)
    length=view.get('byteLength')
    offset=accessor.get('byteOffset',0)
    stride=view.get('byteStride',8)
    if (not all(type(x) is int and x>=0 for x in
                (base,length,offset,stride)) or stride<8 or stride%4
            or base+length>len(binary)
            or offset+(accessor['count']-1)*stride+8>length):
        return None
    uv=[struct.unpack_from('<2f',binary,base+offset+i*stride)
        for i in range(accessor['count'])]
    return uv if all(math.isfinite(x) for row in uv for x in row) else None

def sampled_native_surface_colors(raw):
    """Independently sample original embedded base-color pixels at real UVs.

    Triangle geometry is the key, so an atlas can remap UVs without falsely
    failing a faithful bake. Duplicate baseline material bindings must agree
    on their visible surface colors; a deleted texture is not proof of fidelity.
    """
    if raw is None:
        return None
    doc,binary=_glb_parts(raw)
    textures=doc.get('textures')
    images=doc.get('images')
    materials=doc.get('materials')
    views=doc.get('bufferViews')
    if not all(type(v) is list for v in (textures,images,materials,views)):
        return None
    decoded={}
    result={}
    count=0
    for mesh in doc.get('meshes',[]):
        for prim in mesh.get('primitives',[]):
            attrs=prim.get('attributes',{})
            if not all(k in attrs for k in ('POSITION','TEXCOORD_0')):
                return None
            material_id=prim.get('material')
            if type(material_id) is not int or not 0<=material_id<len(materials):
                return None
            pbr=materials[material_id].get('pbrMetallicRoughness',{})
            color=pbr.get('baseColorTexture') if type(pbr) is dict else None
            if type(color) is not dict or color.get('texCoord',0)!=0:
                return None
            index=color.get('index')
            if type(index) is not int or not 0<=index<len(textures):
                return None
            tex=textures[index]
            if type(tex) is not dict or type(tex.get('source')) is not int:
                return None
            source=tex['source']
            if not 0<=source<len(images):
                return None
            if source not in decoded:
                img=images[source]
                if type(img) is not dict or img.get('mimeType')!='image/png':
                    return None
                vi=img.get('bufferView')
                if type(vi) is not int or not 0<=vi<len(views):
                    return None
                view=views[vi]
                offset=view.get('byteOffset',0)
                length=view.get('byteLength')
                if (type(offset) is not int or type(length) is not int
                        or offset<0 or length<=0 or offset+length>len(binary)):
                    return None
                try:
                    decoded[source]=decode_grid(binary[offset:offset+length],step=1)
                except (ValueError,TypeError,VisualContentBlocked):
                    return None
            width,height,pixels=decoded[source]
            xyz=_read_accessor(doc,binary,attrs['POSITION'])
            uv=read_original_uv2(doc,binary,attrs['TEXCOORD_0'])
            if uv is None or len(xyz)!=len(uv):
                return None
            indices=(_read_accessor(doc,binary,prim['indices'],scalar=True)
                     if 'indices' in prim else list(range(len(xyz))))
            if len(indices)%3:
                return None
            for offset in range(0,len(indices),3):
                ids=indices[offset:offset+3]
                triangle=tuple(sorted(tuple(float(v) for v in xyz[i])
                                      for i in ids))
                # Four distinct barycentric samples catch changed atlas tiles
                # that share an average color at the triangle center.
                samples=[]
                for weights in ((1/3,1/3,1/3),(.6,.2,.2),(.2,.6,.2),(.2,.2,.6)):
                    u=sum(uv[i][0]*w for i,w in zip(ids,weights))%1
                    v=sum(uv[i][1]*w for i,w in zip(ids,weights))%1
                    x=min(width-1,int(u*width))
                    y=min(height-1,int(v*height))
                    samples.append(tuple(pixels[y*width+x]))
                result.setdefault(triangle,[]).append(tuple(samples))
                count+=1
                if count>500000:
                    return None
    return result if result else None

def atlas_surface_fidelity(before,after,limit):
    if type(limit) not in (int,float) or not math.isfinite(limit) or not 0<=limit<=16:
        return False
    first=sampled_native_surface_colors(before)
    second=sampled_native_surface_colors(after)
    if not first or not second or set(first)!=set(second):
        return False
    for triangle in first:
        def close(a,b):
            return all(max(abs(c-d) for c,d in zip(px,py))<=limit
                       for px,py in zip(a,b))
        if not all(any(close(a,b) for b in second[triangle])
                   for a in first[triangle]):
            return False
        if not all(any(close(b,a) for a in first[triangle])
                   for b in second[triangle]):
            return False
    return True

def lod_surface_coherence(near_raw,far_raw,tolerance):
    """Measure bidirectional 3D surface distance, not just LOD bbox/triangle ratio.

    A far LOD that drops half a wall can preserve all six bbox extrema while
    remaining visibly incomplete. The original triangle surfaces must cover
    each other to a pre-D geometric tolerance in both directions.
    """
    if (type(tolerance) not in (int,float) or
            not math.isfinite(tolerance) or not 0<tolerance<=0.1 or
            near_raw is None or far_raw is None):
        return False
    near=_triangles(near_raw)
    far=_triangles(far_raw)
    if not near or not far or len(near)>10000 or len(far)>10000:
        return False
    def sub(a,b):
        return tuple(a[i]-b[i] for i in range(3))
    def dot(a,b):
        return sum(a[i]*b[i] for i in range(3))
    def cross(a,b):
        return (a[1]*b[2]-a[2]*b[1],
                a[2]*b[0]-a[0]*b[2],
                a[0]*b[1]-a[1]*b[0])
    def seg_dist(p,a,b):
        d=sub(b,a)
        denom=dot(d,d)
        t=max(0,min(1,dot(sub(p,a),d)/denom)) if denom>1e-18 else 0
        q=tuple(a[i]+t*d[i] for i in range(3))
        v=sub(p,q)
        return dot(v,v)
    def dist(p,tri):
        a,b,c=tri
        ab,ac=sub(b,a),sub(c,a)
        normal=cross(ab,ac)
        denom=dot(normal,normal)
        if denom<=1e-18:
            return float('inf')
        ap=sub(p,a)
        scale=dot(ap,normal)/denom
        projected=tuple(p[i]-scale*normal[i] for i in range(3))
        v=sub(projected,a)
        d00,d01,d11=dot(ab,ab),dot(ab,ac),dot(ac,ac)
        det=d00*d11-d01*d01
        if det>1e-18:
            u=(d11*dot(v,ab)-d01*dot(v,ac))/det
            w=(d00*dot(v,ac)-d01*dot(v,ab))/det
            if u>=-1e-8 and w>=-1e-8 and u+w<=1+1e-8:
                return dot(ap,normal)**2/denom
        return min(seg_dist(p,a,b),seg_dist(p,b,c),seg_dist(p,c,a))
    def sampled(tris):
        unique=list({tuple(sorted(tuple(p) for p in tri)) for tri in tris})
        if len(unique)>256:
            unique=[unique[i*len(unique)//256] for i in range(256)]
        return [tuple(sum(v[k] for v in tri)/3 for k in range(3))
                for tri in unique]
    limit=tolerance*tolerance
    for source,target in ((near,far),(far,near)):
        for point in sampled(source):
            if min(dist(point,tri) for tri in target)>limit:
                return False
    return True

def bindings(raw):
    if raw is None:return None
    try:return material_bindings(raw)
    except (ValueError,KeyError,TypeError,IndexError):return None

def inspect(source_context,rule_id):
    need(type(source_context) is dict and
         set(source_context)=={'inventory','plan','controller','asset',
                               'step','work','source_loader'} and
         rule_id in RULES,'C07_P345_REMAINING_EXACT_CONTEXT')
    inv,plan,controller,asset,step,work,loader=(
        source_context[k] for k in ('inventory','plan','controller',
                                    'asset','step','work','source_loader'))
    n=int(rule_id.rsplit('-',1)[1])
    required_phase=3 if n<=120 else 4 if n<=140 else 5
    need(plan.get('phase') in PHASE_INDEX and
         PHASE_INDEX[plan['phase']]>=required_phase and
         plan.get('phase')==work.get('phase'),
         'C07_P345_REMAINING_CANONICAL_PHASE')
    # The original forty-rule reader enforces every canonical literal,
    # catalog digest, phase, current master and active operation.
    report=inspect_p345(inv,plan,controller,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==work['master_sha256']
         and state.get('last_audit_hash')==tail
         and (state.get('active_step') or {}).get('step')==step
         and report['original_audit_sha256']==audit_sha
         and report['original_audit_tail']==tail,
         'C07_P345_REMAINING_CURRENT_AUDIT_DRIFT')
    pins=plan.get('p345_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P345_REMAINING_PRE_D_PINS')
    records={}
    for role,path,digest,raw in _registered_artifacts(
            rows,state,step,loader,work):
        need(role not in records,'C07_P345_REMAINING_DUPLICATE_ROLE')
        records[role]=(path,digest,raw)
    def original(role,ext):
        row=records.get(role)
        return (row[2] if row and row[0].lower().endswith(ext)
                and pins.get(role)==row[1] and sha(row[2])==row[1]
                else None)
    def policy(role):
        raw=original(role,'.json')
        return binary_json(raw) if raw is not None else {}
    def view(role):
        raw=original(role,'.png')
        return rgba(raw) if raw is not None else None
    raw=original('NATIVE_EXPORT','.glb')
    doc,binary=_glb_parts(raw) if raw is not None else ({},b'')
    native=_mesh(raw) if raw is not None else None
    embedded=_embedded(doc,binary) if raw is not None else None
    mats=doc.get('materials',[])
    images=doc.get('images',[])
    refs=_references(doc) if raw is not None else None
    prims=[p for m in doc.get('meshes',[]) if type(m) is dict
           for p in m.get('primitives',[]) if type(p) is dict]
    pbr=bool(prims and mats and all(type(p.get('attributes')) is dict
         and 'POSITION' in p['attributes'] for p in prims)
         and all(type(m) is dict and
                 type(m.get('pbrMetallicRoughness')) is dict for m in mats))
    n=int(rule_id.rsplit('-',1)[1])
    if n==118:
        baseline_raw=original('P3_ATLAS_BASELINE','.glb')
        baseline=_mesh(baseline_raw) if baseline_raw else None
        atlas_policy=policy('P3_ATLAS_POLICY')
        before,after=bindings(baseline_raw),bindings(raw)
        target=atlas_policy.get('min_material_binding_reduction')
        quality=atlas_policy.get('min_atlas_color_variance')
        atlas_images=bool(embedded and numeric(quality) and quality>0 and
                          all(x['variance']>=quality for x in embedded))
        # A deleted material with a changed mesh is not an atlas benefit.
        # Compare actual triangle coordinates, not merely triangle count/bbox.
        before_surface=triangle_counts(baseline_raw) if baseline_raw else None
        after_surface=triangle_counts(raw) if raw else None
        # An atlas may merge duplicate primitives, but must not introduce
        # a new oriented surface or additional duplicate geometry.
        same_geometry=bool(before_surface and after_surface and
                           set(before_surface)==set(after_surface) and
                           all(before_surface[k]>=after_surface[k]
                               for k in after_surface))
        measured=bool(before is not None and after is not None and
                      before>after>=1 and type(target) is int and target>=1
                      and before-after>=target and atlas_images and
                      boxes_close(native,baseline,0.01) and same_geometry
                      and atlas_surface_fidelity(
                          baseline_raw,raw,
                          atlas_policy.get('max_atlas_sample_rgb_delta')))
        checks=(bool(baseline_raw and original('P3_ATLAS_POLICY','.json')
                     and raw),before is not None and after is not None,measured)
    elif n==119:
        bake_policy=policy('P3_BAKE_POLICY')
        baked_raw=original('P3_BAKED_NORMAL','.png')
        baked=view('P3_BAKED_NORMAL')
        normal_refs=[m.get('normalTexture',{}).get('index') for m in mats
                     if type(m) is dict and type(m.get('normalTexture')) is dict]
        textures=doc.get('textures',[])
        matching=False
        if baked and embedded and normal_refs and type(textures) is list:
            matching=all(type(i) is int and 0<=i<len(textures)
                         and type(textures[i].get('source')) is int
                         and 0<=textures[i]['source']<len(embedded)
                         and embedded[textures[i]['source']]['sha256']==sha(baked_raw)
                         for i in normal_refs)
        checks=(bool(original('P3_BAKE_POLICY','.json') and
                     bake_policy.get('normal_bake_required') is True
                     and baked_raw and raw),
                bool(baked and matching and
                     all('TEXCOORD_0' in p.get('attributes',{}) for p in prims)),
                bool(matching and baked['variance']>1 and
                     baked['unique_rgb']>=4 and
                     baked_normal_channels_valid(baked_raw)))
    elif n==120:
        approved_raw=original('P3_APPROVED_EXPORT','.glb')
        approved=_mesh(approved_raw) if approved_raw else None
        # Identical bbox and triangle count do not prove exported geometry
        # matches the approved original: compare every triangle coordinate.
        approved_faces=triangle_counts(approved_raw) if approved_raw else None
        exported_faces=triangle_counts(raw) if raw else None
        exact=bool(native and approved and approved_faces and exported_faces
                   and approved_faces==exported_faces)
        checks=(bool(approved_raw and raw),exact,False)
    elif n==133:
        defects=policy('P4_GEOMETRY_DEFECT_REPORT')
        count=defects.get('degenerate_triangle_count')
        measured=bool(native and type(count) is int and count>=0 and
                      count==sum(x['degenerate_triangles']
                                 for x in native['metrics']))
        checks=(bool(original('P4_GEOMETRY_DEFECT_REPORT','.json') and
                     view('LIGHT_NEUTRAL_VIEW')),
                measured,False)
    elif n==134:
        direct=view('LIGHT_DIRECT_VIEW')
        neutral=view('LIGHT_NEUTRAL_VIEW')
        checks=(bool(original('P4_LIGHTING_QA','.json') and direct),
                bool(pbr and rgb_different(direct,neutral) and
                     direct['mean']>neutral['mean'] and
                     pixel_light_response(original('LIGHT_NEUTRAL_VIEW','.png'),
                                          original('LIGHT_DIRECT_VIEW','.png'),
                                          direction=1,minimum_delta=5)),False)
    elif n==135:
        shadow=view('LIGHT_SHADOW_VIEW')
        neutral=view('LIGHT_NEUTRAL_VIEW')
        checks=(bool(original('P4_LIGHTING_QA','.json') and shadow),
                bool(pbr and rgb_different(shadow,neutral) and
                     shadow['mean']<neutral['mean'] and
                     pixel_light_response(original('LIGHT_NEUTRAL_VIEW','.png'),
                                          original('LIGHT_SHADOW_VIEW','.png'),
                                          direction=-1,minimum_delta=5)),False)
    elif n==136:
        reflection=view('REFLECTION_VIEW')
        material_plan=policy('P4_MATERIAL_PLAN')
        metal=bool(mats and any(
            type(m) is dict and type(m.get('pbrMetallicRoughness')) is dict
            and numeric(m['pbrMetallicRoughness'].get('metallicFactor'))
            and m['pbrMetallicRoughness']['metallicFactor']>=0.7 for m in mats))
        checks=(bool(original('P4_MATERIAL_PLAN','.json') and
                     material_plan.get('fivem_shader_profile') and reflection),
                bool(metal and reflection and
                     rgb_different(reflection,view('LIGHT_NEUTRAL_VIEW')) and
                     pixel_light_response(original('LIGHT_NEUTRAL_VIEW','.png'),
                                          original('REFLECTION_VIEW','.png'),
                                          direction=0,minimum_delta=5)),False)
    elif n==139:
        underside=view('VISUAL_VIEW_UNDERSIDE')
        qa=policy('P345_QA_REPORT')
        findings=qa.get('unresolved_findings')
        checks=(bool(original('P345_QA_REPORT','.json') and underside),
                bool(underside and type(findings) is list and
                     all(type(x) is str and x.strip() for x in findings)
                     and native),False)
    elif n==140:
        presentation=view('LIGHT_CINEMATIC_VIEW')
        technical=view('LIGHT_NEUTRAL_VIEW')
        qa=policy('P345_QA_REPORT')
        light=policy('P4_LIGHTING_QA')
        checks=(bool(original('P345_QA_REPORT','.json') and
                     original('P4_LIGHTING_QA','.json')),
                bool(presentation and technical and
                     rgb_different(presentation,technical) and
                     pixel_light_response(original('LIGHT_NEUTRAL_VIEW','.png'),
                                          original('LIGHT_CINEMATIC_VIEW','.png'),
                                          direction=0,minimum_delta=5) and
                     type(qa.get('unresolved_findings')) is list and
                     light.get('presentation_mode')=='STUDIO_ONLY'),False)
    elif n==143:
        before_raw=original('P5_HIDDEN_BASELINE','.glb')
        before=_mesh(before_raw) if before_raw else None
        hidden=policy('P5_HIDDEN_GEOMETRY_POLICY')
        target=hidden.get('min_removed_triangles')
        before_faces=triangle_counts(before_raw) if before_raw else None
        after_faces=triangle_counts(raw) if raw else None
        removed=(before_faces-after_faces) if before_faces and after_faces else Counter()
        # Positive source evidence only for independently verified removal
        # of redundant duplicate triangles; arbitrary removed faces do not
        # demonstrate that geometry was hidden or unnecessary.
        duplicate_removal=bool(removed and all(
            before_faces[face]>1 and after_faces[face]>=1
            for face in removed))
        checks=(bool(before_raw and original('P5_HIDDEN_GEOMETRY_POLICY','.json')
                     and raw),
                bool(before and native and type(target) is int and target>0
                     and sum(removed.values())>=target
                     and all(after_faces[face]<=before_faces[face]
                             for face in after_faces)
                     and duplicate_removal
                     and boxes_close(before,native,0.001)),False)
    elif n==145:
        lod_raw=original('LOD_EXPORT','.glb')
        lod=_mesh(lod_raw) if lod_raw else None
        budget=policy('P5_PERF_BUDGET')
        near,far=view('LOD_NEAR_VIEW'),view('LOD_FAR_VIEW')
        ratio=budget.get('lod_max_triangle_ratio')
        checks=(bool(raw and lod_raw and
                     original('P5_PERF_BUDGET','.json')),
                bool(native and lod and numeric(ratio) and 0<ratio<1
                     and lod['triangles']<native['triangles']
                     and lod['triangles']/native['triangles']<=ratio
                     and near and far and rgb_different(near,far)
                     and boxes_close(native,lod,budget.get(
                         'lod_bounds_tolerance_m',0.01))
                     and lod_surface_coherence(raw,lod_raw,
                         budget.get('lod_surface_deviation_m'))),False)
    elif n==147:
        budget=policy('P5_PERF_BUDGET')
        min_shared=budget.get('min_shared_texture_bindings')
        quality=budget.get('min_reused_texture_variance')
        reuse=actual_primitive_texture_reuse(doc)
        checks=(bool(raw and original('P5_PERF_BUDGET','.json')),
                bool(refs is not None and type(min_shared) is int
                     and min_shared>=2 and sum(reuse.values())>=min_shared
                     and any(count>=2 for count in reuse.values())
                     and embedded and numeric(quality) and quality>0
                     and all(im['variance']>=quality for im in embedded)),False)
    else:
        budget=policy('P5_PERF_BUDGET')
        capture=policy('P5_RUNTIME_CAPTURE')
        samples=capture.get('frame_ms_samples')
        target=budget.get('target_frame_ms')
        checks=(bool(raw and original('P5_PERF_BUDGET','.json') and
                     original('P5_RUNTIME_CAPTURE','.json')),
                bool(type(samples) is list and len(samples)>=10 and
                     all(positive(x) and x<10000 for x in samples) and
                     positive(target) and
                     sum(samples)/len(samples)<=target),False)
    criteria=CRITERIA[n]
    need(len(criteria)==3 and len(checks)==3 and
         all(type(x) is bool for x in checks),
         'C07_P345_REMAINING_SOURCE_PREDICATE_SCHEMA')
    return {'rule_id':rule_id,'checks':dict(zip(criteria,checks)),
            'evidence_complete':False,
            'full_rule_semantics':'UNKNOWN','individual_mg0':'UNKNOWN',
            'owner_acceptance':'UNKNOWN','fivem_runtime':'UNKNOWN',
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'advancement_authorized':False}

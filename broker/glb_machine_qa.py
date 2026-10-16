#!/usr/bin/env python3
"""C07 read-only GLB technical evidence, not an artist/visual/FiveM/MG0 PASS.

Standard library; glTF 2.0 GLB static TRIANGLES with embedded buffer; fail closed
on unsupported primitives, sparse accessors, morph targets or dangling refs.
Never declares interpenetrations from bounding-box overlaps alone.
"""
import argparse
import hashlib
import itertools
import json
import math
import struct
from pathlib import Path

from glb_triangle_crossings import inspect as inspect_crossings
from glb_pbr_evidence import inspect as inspect_pbr

MAX_TRIANGLES_FOR_CROSSING = 100000

MAX_BYTES = 250_000_000
MAX_VERTICES = 6_000_000
MAX_TRIANGLES = 12_000_000
FMT = {5120: 'b', 5121: 'B', 5122: 'h', 5123: 'H', 5125: 'I', 5126: 'f'}
SIZE = {k:struct.calcsize('<'+v) for k,v in FMT.items()}
IDENT = (1.,0.,0.,0., 0.,1.,0.,0., 0.,0.,1.,0., 0.,0.,0.,1.)

class GLBError(ValueError): pass

def require(value, reason):
    if not value: raise GLBError(reason)

def multiply(a,b):
    return tuple(sum(a[r*4+k]*b[k*4+c] for k in range(4)) for r in range(4) for c in range(4))

def xform(m,v):
    x,y,z=v
    return (m[0]*x+m[1]*y+m[2]*z+m[3],m[4]*x+m[5]*y+m[6]*z+m[7],m[8]*x+m[9]*y+m[10]*z+m[11])

def matrix(n):
    if 'matrix' in n:
        v=n['matrix'];require(len(v)==16 and all(math.isfinite(x) for x in v),'BAD_NODE_MATRIX')
        return tuple(v[c*4+r] for r in range(4) for c in range(4))
    t=n.get('translation',[0,0,0]);s=n.get('scale',[1,1,1]);q=n.get('rotation',[0,0,0,1])
    require(len(t)==3 and len(s)==3 and len(q)==4 and all(math.isfinite(v) for v in t+s+q),'BAD_NODE_TRS')
    require(all(v!=0 for v in s),'ZERO_NODE_SCALE')
    x,y,z,w=q;norm=x*x+y*y+z*z+w*w
    require(norm>1e-14,'BAD_NODE_QUATERNION')
    norm=2/norm
    xx=x*x*norm;yy=y*y*norm;zz=z*z*norm;xy=x*y*norm;xz=x*z*norm;yz=y*z*norm
    xw=x*w*norm;yw=y*w*norm;zw=z*w*norm
    # glTF T*R*S scales *columns* of R, not rows. For rotated non-uniform
    # scale, the opposite order yields incorrect AABBs and geometric QA.
    return (s[0]*(1-yy-zz),s[1]*(xy-zw),s[2]*(xz+yw),t[0],
            s[0]*(xy+zw),s[1]*(1-xx-zz),s[2]*(yz-xw),t[1],
            s[0]*(xz-yw),s[1]*(yz+xw),s[2]*(1-xx-yy),t[2],0.,0.,0.,1.)

def parse(raw):
    require(len(raw)>=20,'GLB_TOO_SHORT')
    magic,ver,length=struct.unpack_from('<4sII',raw,0)
    require(magic==b'glTF' and ver==2 and length==len(raw),'GLB_BAD_HEADER_LENGTH_VERSION')
    pos=12;chunks=[]
    while pos<len(raw):
        require(pos+8<=len(raw),'GLB_TRUNCATED_CHUNK')
        n,typ=struct.unpack_from('<I4s',raw,pos);pos+=8
        require(n%4==0 and n<=len(raw)-pos,'GLB_BAD_CHUNK_LENGTH')
        chunks.append((typ,raw[pos:pos+n]));pos+=n
    require(chunks and chunks[0][0]==b'JSON','GLB_MISSING_JSON')
    require(len(chunks)<=2 and all(c[0]==b'BIN\x00' for c in chunks[1:]),'GLB_UNSUPPORTED_CHUNKS')
    document=json.loads(chunks[0][1].decode('utf-8').rstrip(' \t\r\n\x00'))
    require(document.get('asset',{}).get('version')=='2.0','GLTF_VERSION_MISMATCH')
    blobs=[c[1] for c in chunks[1:]]
    buffers=document.get('buffers',[])
    require(len(buffers)<=1 and (not buffers or (blobs and 'uri' not in buffers[0])),'EXTERNAL_OR_MULTIPLE_BUFFERS_UNSUPPORTED')
    if buffers:require(buffers[0]['byteLength']<=len(blobs[0]),'BUFFER_INCOMPLETE')
    return document,blobs[0] if blobs else b''

def read_accessor(g,bin_blob,aid,typ,comp=None):
    accessors=g.get('accessors',[]);views=g.get('bufferViews',[])
    require(type(aid)==int and 0<=aid<len(accessors),'ACCESSOR_OUT_OF_RANGE')
    a=accessors[aid]
    require(a.get('type')==typ and a.get('componentType') in FMT and
            (comp is None or a['componentType'] in comp),'ACCESSOR_BAD_TYPE')
    require('sparse' not in a and 'bufferView' in a,'SPARSE_OR_UNBACKED_ACCESSOR_UNSUPPORTED')
    count=a['count']; require(type(count)==int and 0<=count<=MAX_VERTICES*3,'ACCESSOR_INVALID_COUNT')
    vid=a['bufferView'];require(type(vid)==int and 0<=vid<len(views),'BUFFERVIEW_OUT_OF_RANGE')
    v=views[vid];require(v.get('buffer')==0,'EXTERNAL_BUFFER_UNSUPPORTED')
    elems=3 if typ=='VEC3' else 1
    size=SIZE[a['componentType']]*elems
    stride=v.get('byteStride',size)
    require(type(stride)==int and stride>=size and stride%SIZE[a['componentType']]==0,'ACCESSOR_BAD_STRIDE')
    view_start=v.get('byteOffset',0);view_length=v['byteLength'];start=view_start+a.get('byteOffset',0)
    require(all(type(x)==int and x>=0 for x in (view_start,view_length,start)),'ACCESSOR_BAD_OFFSET')
    require(view_start+view_length<=len(bin_blob) and
            (count==0 or start+(count-1)*stride+size<=view_start+view_length),'ACCESSOR_OUT_OF_BOUNDS')
    unpack=struct.Struct('<'+FMT[a['componentType']]*elems).unpack_from
    return [unpack(bin_blob,start+i*stride) for i in range(count)]

def aabb(coords):
    if not coords:return None
    return [[min(v[k] for v in coords) for k in range(3)], [max(v[k] for v in coords) for k in range(3)]]

def overlaps(a,b):
    return all(max(a[0][k],b[0][k])<=min(a[1][k],b[1][k])+1e-9 for k in range(3))

def audit_bytes(raw):
    g,blob=parse(raw)
    meshes=g.get('meshes',[]);nodes=g.get('nodes',[]);scenes=g.get('scenes',[])
    require(meshes and scenes,'SCENE_OR_MESH_MISSING')
    scene_id=g.get('scene',0)
    require(type(scene_id)==int and 0<=scene_id<len(scenes),'DEFAULT_SCENE_INVALID')
    all_mesh=[];seen=set();visiting=set();unsupported=[];errors=[]
    def descend(nid,parent):
        require(type(nid)==int and 0<=nid<len(nodes),'NODE_REFERENCE_INVALID')
        require(nid not in visiting,'NODE_CYCLE')
        visiting.add(nid)
        n=nodes[nid]
        if 'skin' in n or 'weights' in n:unsupported.append('SKINNED_OR_WEIGHTED_NODE:'+str(nid))
        transform=multiply(parent,matrix(n));seen.add(nid)
        if 'mesh' in n:
            idx=n['mesh'];require(type(idx)==int and 0<=idx<len(meshes),'MESH_REFERENCE_INVALID')
            all_mesh.append((nid,idx,transform))
        for child in n.get('children',[]):descend(child,transform)
        visiting.remove(nid)
    for n in scenes[scene_id].get('nodes',[]):descend(n,IDENT)
    require(all_mesh,'NO_RENDERABLE_NODES')
    num_verts=0;num_triangles=0;num_degenerate=0;num_bad_indices=0
    num_mesh_primitives=0;num_nonfinite=0;num_nontriangles=0;bounding=[];mats=g.get('materials',[])
    crossing_groups=[];crossing_storage=0;crossing_storage_exceeded=False
    for nid,mid,transform in all_mesh:
        mesh=meshes[mid]
        for pid,primitive in enumerate(mesh.get('primitives',[])):
            num_mesh_primitives+=1
            if primitive.get('targets'):unsupported.append('MORPH_TARGETS:'+str(nid)+':'+str(pid))
            if primitive.get('mode',4)!=4:
                num_nontriangles+=1;unsupported.append('NON_TRIANGLES:'+str(nid)+':'+str(pid));continue
            if 'POSITION' not in primitive.get('attributes',{}):
                errors.append('MISSING_POSITIONS:'+str(nid)+':'+str(pid));continue
            positions=read_accessor(g,blob,primitive['attributes']['POSITION'],'VEC3',(5126,))
            num_verts+=len(positions)
            require(num_verts<=MAX_VERTICES,'VERTEX_BUDGET_EXCEEDED')
            if not all(math.isfinite(x) for p in positions for x in p):
                num_nonfinite+=sum(1 for p in positions if any(not math.isfinite(x) for x in p))
                continue
            transformed=[xform(transform,p) for p in positions]
            if not all(math.isfinite(x) for p in transformed for x in p):
                errors.append('NONFINITE_WORLD_TRANSFORM:'+str(nid));continue
            bb=aabb(transformed)
            if bb:bounding.append({'node':nid,'mesh':mid,'primitive':pid,'bounds':bb})
            if 'material' in primitive:
                mat=primitive['material'];
                if type(mat)!=int or mat<0 or mat>=len(mats):errors.append('INVALID_MATERIAL_REFERENCE:'+str(nid)+':'+str(pid))
            if 'indices' in primitive:
                indices=[item[0] for item in read_accessor(g,blob,primitive['indices'],'SCALAR',(5121,5123,5125))]
            else:indices=list(range(len(positions)))
            if len(indices)%3:errors.append('TRIANGLE_INDEX_COUNT_NOT_MULTIPLE_OF_3:'+str(nid)+':'+str(pid));continue
            num_triangles+=len(indices)//3
            require(num_triangles<=MAX_TRIANGLES,'FACE_BUDGET_EXCEEDED')
            bad=sum(1 for i in indices if i<0 or i>=len(positions))
            num_bad_indices+=bad
            if bad:continue
            group_triangles=[]
            if crossing_storage + len(indices)//3 > MAX_TRIANGLES_FOR_CROSSING:
                crossing_storage_exceeded=True
            for i in range(0,len(indices),3):
                a,b,c=[transformed[indices[i+k]] for k in range(3)]
                if not crossing_storage_exceeded:
                    group_triangles.append((a,b,c))
                u=[b[k]-a[k] for k in range(3)];v=[c[k]-a[k] for k in range(3)]
                cross=[u[1]*v[2]-u[2]*v[1],u[2]*v[0]-u[0]*v[2],u[0]*v[1]-u[1]*v[0]]
                # A triangle exactly collapsed (within double-float tolerance)
                if sum(x*x for x in cross)<=1e-24:num_degenerate+=1
            if not crossing_storage_exceeded:
                crossing_groups.append({'key':(nid,pid),'triangles':group_triangles})
                crossing_storage += len(group_triangles)
            else:
                crossing_groups.clear()
    candidate_pairs=[]
    for a,b in itertools.combinations(bounding,2):
        if overlaps(a['bounds'],b['bounds']):candidate_pairs.append([a['node'],a['primitive'],b['node'],b['primitive']])
    if crossing_storage_exceeded:
        cross_report={'schema':'gg-c07-bounded-strict-triangle-crossings-v1',
                      'strict_surface_crossing_pairs_found':0,
                      'strict_crossing_examples':[],
                      'candidate_triangle_pairs_tested':0,
                      'all_requested_pairs_fully_scanned':False,
                      'unresolved_pairs':[{'reason':'GLB_TRIANGLE_STORAGE_BUDGET_EXCEEDED'}],
                      'contact_and_coplanar_cases':'NOT_COVERED',
                      'defect_classification':'UNKNOWN_REQUIRES_ASSET_RULE_CONTEXT',
                      'individual_mg0':'UNKNOWN','advancement_authorized':False}
    else:
        cross_report=inspect_crossings(crossing_groups,candidate_pairs)
    pbr_report=inspect_pbr(g,blob,all_mesh)
    errors.extend(pbr_report['pbr_structural_errors'])
    if num_bad_indices:errors.append('INDEX_OUT_OF_RANGE:'+str(num_bad_indices))
    if num_nonfinite:errors.append('NONFINITE_POSITIONS:'+str(num_nonfinite))
    if num_degenerate:errors.append('DEGENERATE_TRIANGLES:'+str(num_degenerate))
    if num_triangles==0:errors.append('NO_TRIANGLES')
    for i,image in enumerate(g.get('images',[])):
        if 'uri' in image:unsupported.append('EXTERNAL_OR_DATA_URI_IMAGE:'+str(i))
        elif 'bufferView' in image:
            ref=image['bufferView']
            if type(ref)!=int or ref<0 or ref>=len(g.get('bufferViews',[])):
                errors.append('INVALID_IMAGE_BUFFER_VIEW:'+str(i))
    return {'schema':'gg-c07-glb-readonly-machine-audit-v1',
      'source_sha256':hashlib.sha256(raw).hexdigest(),
      'checks':{'glb_header':'VERIFIED','scene_references':'VERIFIED','embedded_accessor_bounds':'VERIFIED',
                'static_world_transform':'VERIFIED'},
      'scene_mesh_nodes':len(all_mesh),'mesh_primitives':num_mesh_primitives,
      'vertices_examined':num_verts,'triangles_examined':num_triangles,
      'degenerate_triangles':num_degenerate,'invalid_indices':num_bad_indices,
      'nonfinite_positions':num_nonfinite,
      'geometry_groups_with_bounds':len(bounding),
      'aabb_overlap_candidates_count':len(candidate_pairs),
      'aabb_overlap_candidates_first_15':candidate_pairs[:15],
      'triangle_surface_crossing_evidence':cross_report,
      'material_source_evidence':pbr_report,
      'errors':sorted(set(errors)),'unsupported_requires_independent_check':sorted(set(unsupported)),
      'machine_evidence_status':'FAIL' if errors else 'UNKNOWN_UNSUPPORTED_INPUT' if unsupported else 'NO_FATAL_STRUCTURAL_DEFECT_DETECTED',
      'overlaps_confirmed':False,
      'visual_qa':'UNKNOWN','materials_pbr_qa':'UNKNOWN','fivem_runtime':'UNKNOWN','mg0':'UNKNOWN',
      'asset_acceptance':'NOT_AUTHORIZED','overall_rule_semantics':'UNKNOWN',
      'note':'Strict triangle piercings are geometric observations, not automatically forbidden defects. Zero findings, budget truncation, coplanar geometry, touch, and untested groups cannot support a collision-free PASS.'}

def examine(path,expected_sha256):
    path=Path(path)
    require(path.is_file() and path.suffix.lower()=='.glb','SOURCE_GLB_FILE_REQUIRED')
    require(path.stat().st_size<=MAX_BYTES,'SOURCE_GLB_TOO_LARGE')
    raw=path.read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    require(expected_sha256==digest,'SOURCE_GLB_SHA256_MISMATCH')
    return audit_bytes(raw)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('glb',help='local actual GLB - read only')
    p.add_argument('--sha256',required=True,help='source artifact exact SHA256')
    p.add_argument('--report',help='JSON path separate from model; without this stdout only')
    a=p.parse_args()
    try:
        result=examine(a.glb,a.sha256)
        status=2 if result['machine_evidence_status']=='FAIL' else 0
    except (GLBError,ValueError,KeyError,TypeError,struct.error,UnicodeError) as exc:
        result={'schema':'gg-c07-glb-readonly-machine-audit-v1','machine_evidence_status':'FAIL',
                'errors':['INVALID_OR_UNSUPPORTED_GLB:'+str(exc)],
                'overall_rule_semantics':'UNKNOWN','asset_acceptance':'NOT_AUTHORIZED'}
        status=2
    payload=json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False)
    print(payload)
    if a.report: Path(a.report).write_text(payload+'\n',encoding='utf-8')
    raise SystemExit(status)
if __name__=='__main__':main()
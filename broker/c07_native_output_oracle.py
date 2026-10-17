"""C07 R139: real GLB vertex/triangle outcome oracle for exact R-176/R-180.

Verifies original, pre-D enrolled geometric EXPECTATIONS against original
Controller-registered model bytes. Unlike checking an exit status or log, this
re-parses the output and baseline binary. Does not assert artistry, player
walkability, owner approval or per-rule MG0.
"""
import hashlib
import json
import math
import struct

from c07_r124_positive_process import inspect as base8, TEXT as R_TEXT
from c07_positive_native_process import _original_attempt, _registered_artifacts
SCHEMA='gg-c07-r139-glb-native-expected-output-two-rules-v1'
CONTRACT='gg-c07-pre-d-output-geometry-contract-v1'
REQUIRED=frozenset(('schema','bbox_min','bbox_max','bbox_tolerance_m',
                     'min_meshes','min_triangles','max_triangles',
                     'min_triangle_delta_from_baseline'))

class OriginalGeometryBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise OriginalGeometryBlocked(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def read_mesh_geometry(raw):
    """Recompute the original GLB float vertices; never trust accessor min/max."""
    need(type(raw) is bytes and 52<=len(raw)<=250_000_000,
         'R139_GLB_SOURCE_BYTES_SIZE')
    need(raw[:4]==b'glTF','R139_GLB_MAGIC')
    ver,total=struct.unpack_from('<II',raw,4)
    need(ver==2 and total==len(raw),'R139_GLB_VERSION_LENGTH')
    jsz,jtype=struct.unpack_from('<I4s',raw,12)
    need(jtype==b'JSON' and 2<=jsz<=8_000_000 and jsz%4==0 and
         28+jsz<=len(raw),'R139_GLB_JSON_CHUNK')
    doc=json.loads(raw[20:20+jsz])
    bin_size,bin_type=struct.unpack_from('<I4s',raw,20+jsz)
    need(bin_type==bytes((66,73,78,0))
         and bin_size%4==0 and 28+jsz+bin_size==len(raw),
         'R139_GLB_BINARY_CHUNK')
    data=memoryview(raw)[28+jsz:]
    buffers=doc.get('buffers',[])
    views=doc.get('bufferViews',[])
    accessors=doc.get('accessors',[])
    meshes=doc.get('meshes',[])
    need(type(buffers) is list and len(buffers)==1 and
         type(buffers[0].get('byteLength')) is int and
         0<buffers[0]['byteLength']<=len(data) and
         type(views) is list and type(accessors) is list
         and type(meshes) is list and len(meshes)>0,
         'R139_GLB_TABLES')
    bound=[math.inf]*3;top=[-math.inf]*3;tris=0;primitives=0
    for mesh in meshes:
        need(type(mesh) is dict and type(mesh.get('primitives')) is list,
             'R139_GLB_MESH_SCHEMA')
        for prim in mesh['primitives']:
            need(type(prim) is dict and prim.get('mode',4)==4,
                 'R139_GLB_TRIANGLE_ONLY')
            v=prim.get('attributes',{}).get('POSITION')
            need(type(v) is int and 0<=v<len(accessors),
                 'R139_GLB_POSITION_MISSING')
            acc=accessors[v]
            need(type(acc) is dict and acc.get('type')=='VEC3' and
                 acc.get('componentType')==5126 and
                 type(acc.get('count')) is int and 3<=acc['count']<=10_000_000
                 and 'sparse' not in acc,'R139_GLB_POSITION_ENCODING')
            vi=acc.get('bufferView')
            need(type(vi) is int and 0<=vi<len(views),
                 'R139_GLB_POSITION_VIEW')
            view=views[vi]
            off=view.get('byteOffset',0);loc=acc.get('byteOffset',0)
            count=acc['count'];stride=view.get('byteStride',12)
            end=view.get('byteLength')
            need(view.get('buffer')==0 and
                 all(type(t) is int for t in (off,loc,stride,end)) and
                 min(off,loc,stride,end)>=0 and
                 stride>=12 and stride%4==0 and
                 off+end<=buffers[0]['byteLength'] and
                 loc+(count-1)*stride+12<=end,
                 'R139_GLB_POSITION_OUT_OF_BOUNDS')
            data_offset=off+loc
            for i in range(count):
                coords=struct.unpack_from('<3f',data,data_offset+i*stride)
                need(all(math.isfinite(x) for x in coords),
                     'R139_NONFINITE_REAL_POSITION')
                for axis,value in enumerate(coords):
                    bound[axis]=min(bound[axis],value)
                    top[axis]=max(top[axis],value)
            if 'indices' in prim:
                index=prim['indices']
                need(type(index) is int and 0<=index<len(accessors),
                     'R139_INVALID_INDEX_ACCESSOR')
                idx=accessors[index]
                typ={5121:('<B',1),5123:('<H',2),5125:('<I',4)}.get(
                    idx.get('componentType'))
                need(idx.get('type')=='SCALAR' and typ is not None and
                     type(idx.get('count')) is int and idx['count']>=3 and
                     idx['count']%3==0 and 'sparse' not in idx,
                     'R139_INDEX_ENCODING')
                iw=idx.get('bufferView')
                need(type(iw) is int and 0<=iw<len(views),
                     'R139_INDEX_VIEW')
                vrow=views[iw]
                stride_i=vrow.get('byteStride',typ[1])
                start=vrow.get('byteOffset',0)+idx.get('byteOffset',0)
                need(vrow.get('buffer')==0 and
                     all(type(x) is int for x in (stride_i,start)) and
                     stride_i>=typ[1] and start>=0 and
                     start+(idx['count']-1)*stride_i+typ[1]<=
                         vrow.get('byteOffset',0)+vrow.get('byteLength',0)
                     and start+(idx['count']-1)*stride_i+typ[1]<=len(data),
                     'R139_INDEX_OUT_OF_BOUNDS')
                for i in range(idx['count']):
                    vertex=struct.unpack_from(typ[0],data,start+i*stride_i)[0]
                    need(vertex<count,'R139_INDEX_OVERFLOW')
                tris+=idx['count']//3
            else:
                need(count%3==0,'R139_UNINDEXED_TRIANGLE_COUNT')
                tris+=count//3
            primitives+=1
    need(primitives>0 and tris>0 and all(math.isfinite(x) for x in bound+top),
         'R139_MESH_WITH_NO_REAL_TRIANGLES')
    return {'mesh_definitions':len(meshes),'primitive_count':primitives,
            'triangles':tris,'bbox_min':bound,'bbox_max':top}

def _contract(value):
    if type(value) is not dict or set(value)!=REQUIRED or value['schema']!=CONTRACT:
        return None
    lo,hi=value['bbox_min'],value['bbox_max']
    if (type(lo) is not list or type(hi) is not list or
        len(lo)!=3 or len(hi)!=3 or not all(
        type(x) in (int,float) and math.isfinite(x) for x in lo+hi)
        or not (all(lo[k]<=hi[k] for k in range(3)) and any(lo[k]<hi[k] for k in range(3)))):
        return None
    if (type(value['bbox_tolerance_m']) not in (int,float) or
        not 0<=value['bbox_tolerance_m']<=0.25 or
        not all(type(value[k]) is int for k in (
          'min_meshes','min_triangles','max_triangles',
          'min_triangle_delta_from_baseline')) or
        not 1<=value['min_meshes']<=100000 or
        not 1<=value['min_triangles']<=value['max_triangles']<=30_000_000 or
        not 1<=value['min_triangle_delta_from_baseline']<=1000000):
        return None
    return value

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    report=base8(inventory,plan,controller,asset,step,work,
                 source_loader=source_loader)
    need(report['source_rules_evaluated']==8 and
         set(('AAA-200-R-176','AAA-200-R-180'))<=set(report['rules']) and
         report['full_current_attempt_rule_passes']==0 and
         report['individual_mg0_passes']==0 and
         report['advancement_authorized'] is False,
         'R139_SOURCE_BOUND_R124_BASE_MISSING')
    records,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(tail==report['real_controller_audit_tail'] and
         audit_sha==report['real_controller_audit_sha256'],
         'R139_AUDIT_SOURCE_CHANGED')
    artifacts=_registered_artifacts(records,state,step,source_loader,work)
    role={r:(path,digest,raw) for r,path,digest,raw in artifacts}
    spec=_contract(plan.get('output_expectation'))
    actual=None;baseline=None
    if 'NATIVE_EXPORT' in role:
        try:actual=read_mesh_geometry(role['NATIVE_EXPORT'][2])
        except (OriginalGeometryBlocked,KeyError,ValueError,TypeError,
                IndexError,struct.error,UnicodeDecodeError,
                json.JSONDecodeError):pass
    if 'BASELINE_SNAPSHOT' in role and role['BASELINE_SNAPSHOT'][0].lower().endswith('.glb'):
        try:baseline=read_mesh_geometry(role['BASELINE_SNAPSHOT'][2])
        except (OriginalGeometryBlocked,KeyError,ValueError,TypeError,
                IndexError,struct.error,UnicodeDecodeError,
                json.JSONDecodeError):pass
    bbox_match=bool(spec and actual and all(
        abs(actual[field][k]-spec[field][k])<=spec['bbox_tolerance_m']
        for field in ('bbox_min','bbox_max') for k in range(3)))
    count_match=bool(spec and actual and
        spec['min_meshes']<=actual['mesh_definitions'] and
        spec['min_triangles']<=actual['triangles']<=spec['max_triangles'])
    changed=bool(actual and baseline and
        role['NATIVE_EXPORT'][1]!=role['BASELINE_SNAPSHOT'][1] and
        actual['triangles']-baseline['triangles']>=
         (spec['min_triangle_delta_from_baseline'] if spec else math.inf))
    v176={
      'pre_D_expected_geometry_fixed_in_enrolled_plan':spec is not None,
      'registered_native_export_reopened_as_actual_GLTF2':actual is not None,
      'expected_bbox_matches_original_vertex_floats':bbox_match,
      'expected_mesh_and_triangle_counts_match':count_match,
    }
    v180={
      'new_nondegenerate_model_output_from_actual_bytes':actual is not None,
      'original_baseline_GLTF2_bytes_independently_reopened':baseline is not None,
      'real_change_to_geometry_not_just_report':changed,
      'pre_D_minimum_material_output_delta_honored':bool(spec and changed),
    }
    result={}
    for n,checks in ((176,v176),(180,v180)):
        rid=f'AAA-200-R-{n:03}'
        row=inventory['rules'][rid]
        need(row['requirement']==R_TEXT[n] and
             row['requirement_sha256']==sha(R_TEXT[n].encode()),
             'R139_CHANGED_CANONICAL_SOURCE:'+rid)
        result[rid]={
          'rule_id':rid,'requirement_sha256':row['requirement_sha256'],
          'source_sha256':row['source_sha256'],
          'native_r124_checks':report['rules'][rid]['machine_checks'],
          'independently_measured_geometry':actual,
          'pre_D_expected_geometry':spec,
          'baseline_geometry':baseline,
          'source_specific_output_conditions':checks,
          'machine_semantics':'OBSERVED_SCOPE_PASS' if all(checks.values()) else 'UNKNOWN',
          'individual_mg0':'UNKNOWN','full_work_rule_pass':False,
          'owner_acceptance':'UNKNOWN','advancement_authorized':False,
        }
    return {'schema':SCHEMA,'asset':asset,'step':step,
        'original_audit_sha256':audit_sha,'original_audit_tail':tail,
        'attempt_id':work['attempt_id'],
        'operation_sha256':work['operation_sha256'],
        'master_sha256':work['master_sha256'],
        'source_rules_examined':2,'rule_ids':sorted(result),
        'new_output_semantics_observed':sum(
            v['machine_semantics']=='OBSERVED_SCOPE_PASS' for v in result.values()),
        'full_work_rule_passes':0,'individual_mg0_passes':0,
        'advancement_authorized':False,'rules':result}

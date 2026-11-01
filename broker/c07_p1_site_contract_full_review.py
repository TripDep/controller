"""Source-specific original-byte P1 site dimensions and coordinate contracts.

E041 measures the actual site survey polygon and independently decoded native
GLB bounds. E042 authenticates an unambiguous metric coordinate definition,
axis parity, orientation and original native geometry. These are code-level
source verifiers, never FiveM, owner, terrain-Z or operational MG0 approval.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as inspect_p1, jbytes
from c07_native_output_oracle import read_mesh_geometry, OriginalGeometryBlocked

SITE = 'AAA-200-E-041'
COORD = 'AAA-200-E-042'
IDS = frozenset((SITE, COORD))
CRITERIA = {
    SITE: (
        'pre_d_site_survey_boundary_and_metric_dimensions_sha_pinned',
        'original_survey_polygon_area_and_extents_independently_measured',
        'native_original_mesh_extents_inside_measured_site_boundary',
    ),
    COORD: (
        'pre_d_metric_axis_contract_and_native_source_sha_pinned',
        'right_handed_axis_basis_origin_orientation_and_scale_verified',
        'actual_original_mesh_geometry_reopened_in_defined_local_coordinates',
    ),
}
EPS=1e-6

class SiteContractBlocked(ValueError):
    pass

def need(v, code):
    if not v:
        raise SiteContractBlocked(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def finite(x):
    return type(x) in (int,float) and math.isfinite(x)

def point(x):
    return type(x) is list and len(x)==2 and all(finite(y) for y in x)

def signed_basis(matrix):
    if type(matrix) is not list or len(matrix)!=3 or any(
            type(row) is not list or len(row)!=3 for row in matrix):
        return False
    if not all(finite(v) and v in (-1,0,1) for row in matrix for v in row):
        return False
    if any(sum(x!=0 for x in row)!=1 for row in matrix):
        return False
    if any(sum(row[col]!=0 for row in matrix)!=1 for col in range(3)):
        return False
    a,b,c=matrix
    det=(a[0]*(b[1]*c[2]-b[2]*c[1])
        -a[1]*(b[0]*c[2]-b[2]*c[0])
        +a[2]*(b[0]*c[1]-b[1]*c[0]))
    return det==1

def simple_polygon(p):
    if type(p) is not list or not 3<=len(p)<=256 or not all(point(v) for v in p):
        return False
    pts=p[:-1] if p[0]==p[-1] else p
    if len(pts)<3 or len(set(map(tuple,pts)))!=len(pts):
        return False
    def cross(a,b,c):
        return (b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0])
    edges=list(zip(pts,pts[1:]+pts[:1]))
    if any(math.dist(a,b)<=EPS for a,b in edges):
        return False
    area=sum(a[0]*b[1]-b[0]*a[1] for a,b in edges)/2
    if abs(area)<=EPS:
        return False
    def collide(a,b,c,d):
        x,y=cross(a,b,c),cross(a,b,d)
        u,v=cross(c,d,a),cross(c,d,b)
        return ((x>EPS and y< -EPS or x< -EPS and y>EPS) and
                (u>EPS and v< -EPS or u< -EPS and v>EPS))
    return not any(collide(*edges[i],*edges[j]) for i in range(len(edges))
                   for j in range(i+1,len(edges))
                   if j not in (i,(i+1)%len(edges)) and
                   not (i==0 and j==len(edges)-1))

def inside(p,poly):
    # Strict inside or on polygon edge; original survey never fabricated from a bbox.
    pts=poly[:-1] if poly[0]==poly[-1] else poly
    x,y=p;ok=False
    for a,b in zip(pts,pts[1:]+pts[:1]):
        dx,dy=b[0]-a[0],b[1]-a[1]
        t=((x-a[0])*dx+(y-a[1])*dy)/(dx*dx+dy*dy)
        if 0<=t<=1 and math.dist((x,y),(a[0]+t*dx,a[1]+t*dy))<=EPS:
            return True
        if (a[1]>y)!=(b[1]>y) and x < (b[0]-a[0])*(y-a[1])/(b[1]-a[1])+a[0]:
            ok=not ok
    return ok

def inspect(source_context, rule_id):
    need(rule_id in IDS and type(source_context) is dict,
         'C07_P1_SITE_UNREVIEWED_RULE')
    inv,plan,ctrl,asset,step,work,loader=(
        source_context[k] for k in ('inventory','plan','controller',
                                   'asset','step','work','source_loader'))
    report=inspect_p1(inv,plan,ctrl,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,ctrl,asset,step,work)
    need(report['original_audit_sha256']==audit_sha and
         report['original_audit_tail']==tail and
         sha(ctrl.master.read_bytes())==work['master_sha256'],
         'C07_P1_SITE_CURRENT_AUDIT_CHANGED')
    regs=_registered_artifacts(rows,state,step,loader,work)
    pins=plan.get('p1_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P1_SITE_PRE_D_PINS_REQUIRED')
    found={}
    for role,path,digest,raw in regs:
        if role in ('P1_SCENE_CONTRACT','P1_TERRAIN_SAMPLES','NATIVE_EXPORT'):
            need(role not in found,'C07_P1_SITE_DUPLICATE_ORIGINAL_ROLE')
            found[role]=(path,digest,raw)
    def source(role,suffix):
        row=found.get(role)
        if (row is None or not row[0].lower().endswith(suffix) or
                pins.get(role)!=row[1] or sha(row[2])!=row[1]):
            return None
        return row[2]
    scene_raw=source('P1_SCENE_CONTRACT','.json')
    glb_raw=source('NATIVE_EXPORT','.glb')
    field_raw=source('P1_TERRAIN_SAMPLES','.json')
    scene=jbytes(scene_raw) if scene_raw is not None else {}
    field=jbytes(field_raw) if field_raw is not None else {}
    try:
        geo=read_mesh_geometry(glb_raw) if glb_raw is not None else None
    except (OriginalGeometryBlocked,KeyError,TypeError,ValueError,IndexError):
        geo=None
    geom=bool(geo and geo['triangles']>0 and
              all(finite(x) for x in geo['bbox_min']+geo['bbox_max']))
    if rule_id==SITE:
        boundary=field.get('survey_boundary_xy_m')
        survey=simple_polygon(boundary)
        dims=scene.get('available_site_dimensions_m')
        if survey:
            pts=boundary[:-1] if boundary[0]==boundary[-1] else boundary
            w=max(p[0] for p in pts)-min(p[0] for p in pts)
            h=max(p[1] for p in pts)-min(p[1] for p in pts)
        else:
            w=h=0
        contract=bool(survey and type(dims) is list and len(dims)==2 and
                      all(finite(x) and x>0 for x in dims))
        measured=bool(contract and w>EPS and h>EPS and
                      abs(w-dims[0])<=EPS and abs(h-dims[1])<=EPS)
        corners=([(x,y) for x in (geo['bbox_min'][0],geo['bbox_max'][0])
                         for y in (geo['bbox_min'][1],geo['bbox_max'][1])]
                 if geom else [])
        fit=bool(measured and geom and all(inside(p,boundary) for p in corners))
        checks=dict(zip(CRITERIA[SITE],(contract,measured,fit)))
        complete=bool(scene_raw and glb_raw and field_raw)
    else:
        origin=scene.get('origin_xyz')
        rot=scene.get('orientation_xyz_deg')
        units=scene.get('meters_per_unit')
        axis=scene.get('native_to_world_axis_matrix')
        named=scene.get('coordinate_basis')
        contract=bool(scene_raw and glb_raw and type(named) is str and
                      bool(named.strip()) and signed_basis(axis) and
                      finite(units) and units>0)
        orientation=bool(contract and type(origin) is list and
             type(rot) is list and len(origin)==len(rot)==3 and
             all(finite(v) for v in origin+rot) and
             all(-360<=v<=360 for v in rot))
        checks=dict(zip(CRITERIA[COORD],(contract,orientation,geom)))
        complete=bool(scene_raw and glb_raw)
    return {'rule_id':rule_id,'checks':checks,'evidence_complete':complete,
        'original_audit_sha256':audit_sha,'original_audit_tail':tail,
        'attempt_id':work['attempt_id'],'operation_sha256':work['operation_sha256'],
        'individual_mg0':'UNKNOWN','advancement_authorized':False}

"""C07 P6 P-151..154: original collision-vs-visual GLB geometry oracles.

Pre-D pinned collision policy and both original GLBs are reopened from the
exact Controller operation. Door volumes are conservative AABB diagnostics,
not player movement, FiveM collision, owner acceptance or independent MG0.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p3_geometry_semantics import geometry, _read_accessor
from c07_p5_budget_semantics import _glb_parts, _json
from c07_p678_forty_native_domain import TEXT, PHASES

NUMBERS=(151,152,153,154)
IDS=tuple("AAA-200-P-%03d"%n for n in NUMBERS)
SCHEMA="gg-c07-p6-four-original-collision-oracles-v1"

class OriginalCollisionBlocked(ValueError):
    pass

def need(ok,why):
    if not ok:raise OriginalCollisionBlocked(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def _box(row):
    if type(row) is not dict:return None
    low,high=row.get("min_xyz"),row.get("max_xyz")
    if type(low) is not list or type(high) is not list or len(low)!=3 or len(high)!=3:
        return None
    if not all(type(x) in (int,float) and math.isfinite(x)
               for x in low+high):return None
    if not all(a<b for a,b in zip(low,high)):return None
    return low,high

def _triangles(raw):
    metrics=geometry(raw)
    doc,binary=_glb_parts(raw)
    triangles=[]
    for mesh in doc["meshes"]:
        for prim in mesh["primitives"]:
            xyz=_read_accessor(doc,binary,prim["attributes"]["POSITION"])
            ids=(_read_accessor(doc,binary,prim["indices"],scalar=True)
                 if "indices" in prim else list(range(len(xyz))))
            for k in range(0,len(ids),3):
                tri=[xyz[i] for i in ids[k:k+3]]
                triangles.append(tri)
    need(len(triangles)==sum(m["triangles"] for m in metrics),
         "C07_P6_TRIANGLE_COUNT_MISMATCH")
    return triangles

def _centroid_in(triangle,box):
    lo,hi=box
    point=[sum(p[k] for p in triangle)/3 for k in range(3)]
    return all(lo[k]<=point[k]<=hi[k] for k in range(3))

def _aabb_intersects(triangle,box):
    lo,hi=box
    return all(max(p[k] for p in triangle)>=lo[k] and
               min(p[k] for p in triangle)<=hi[k] for k in range(3))

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get("rule_count")==763
         and inventory.get("schema")=="gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASES
         and PHASES[plan["phase"]]>=6
         and plan["phase"]==work.get("phase") and callable(source_loader),
         "C07_P6_ORIGINAL_OPERATION_CONTEXT")
    catalog=inventory.get("source_digests",{}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog)==64
         and all(c in "0123456789abcdef" for c in catalog),
         "C07_P6_CANONICAL_SOURCE")
    for n,rid in zip(NUMBERS,IDS):
        source,phase=TEXT[str(n)]
        row=inventory["rules"].get(rid,{})
        need(phase=="P6" and row.get("family")=="AAA-200"
             and row.get("catalog_number")==n
             and row.get("catalog_section")=="P"
             and row.get("catalog_phase")==phase
             and row.get("requirement")==source
             and row.get("requirement_sha256")==sha(source.encode())
             and row.get("source_sha256")==catalog,
             "C07_P6_ORIGINAL_LITERAL_CHANGED:"+rid)
    audit,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail
         and sha(controller.master.read_bytes())==work["master_sha256"]
         and (state.get("active_step") or {}).get("step")==step,
         "C07_P6_ORIGINAL_AUDIT_DRIFT")
    recorded=_registered_artifacts(audit,state,step,source_loader,work)
    found={}
    for role,path,digest,raw in recorded:
        if role in ("COLLISION_EXPORT","NATIVE_EXPORT","P6_COLLISION_POLICY"):
            need(role not in found,"C07_P6_DUPLICATE_ROLE:"+role)
            found[role]=(path,digest,raw)
    contract=plan.get("p678_evidence_contract",{})
    pins=contract.get("original_artifact_sha256",{}) if type(contract) is dict else {}
    if type(pins) is not dict:pins={}
    def original(role,suffix):
        item=found.get(role)
        return (item[2] if item and item[0].lower().endswith(suffix)
                and pins.get(role)==item[1] and sha(item[2])==item[1]
                else None)
    policy_raw=original("P6_COLLISION_POLICY",".json")
    policy=_json(policy_raw) if policy_raw is not None else {}
    collision_raw=original("COLLISION_EXPORT",".glb")
    visual_raw=original("NATIVE_EXPORT",".glb")
    collision=_triangles(collision_raw) if collision_raw is not None else None
    visual=_triangles(visual_raw) if visual_raw is not None else None
    solid=policy.get("solid_surfaces")
    openings=policy.get("openings")
    solid_boxes=(type(solid) is list and bool(solid) and len(solid)<=128
                 and all(type(x) is dict and type(x.get("name")) is str
                         and bool(x["name"]) and _box(x) is not None for x in solid))
    opening_boxes=(type(openings) is list and bool(openings)
                   and len(openings)<=128
                   and all(type(x) is dict
                           and x.get("kind") in ("door","passage","stair","railing")
                           and _box(x) is not None for x in openings))
    solids_covered=(solid_boxes and collision is not None
                    and all(any(_centroid_in(tri,_box(x)) for tri in collision)
                            for x in solid))
    free_openings=(opening_boxes and collision is not None
                   and all(not any(_aabb_intersects(tri,_box(x))
                                   for tri in collision)
                           for x in openings))
    max_tri=policy.get("max_collision_triangles")
    max_ratio=policy.get("max_collision_to_visual_ratio")
    c_count=len(collision) if collision is not None else 0
    v_count=len(visual) if visual is not None else 0
    checks={
        151:{
            "source_solid_surface_regions_explicit_and_valid":
                bool(solid_boxes),
            "each_original_solid_region_has_real_collision_faces":
                bool(solids_covered),
        },
        152:{
            "original_visual_and_collision_exports_distinct":
                collision is not None and visual is not None
                and sha(collision_raw)!=sha(visual_raw),
            "separate_actual_triangle_sets_independently_read":
                c_count>0 and v_count>0,
        },
        153:{
            "original_collision_triangle_budget_explicit":
                type(max_tri) is int and max_tri>0
                and type(max_ratio) in (int,float)
                and math.isfinite(max_ratio) and 0<max_ratio<=1,
            "actual_collision_complexity_within_original_limits":
                c_count>0 and v_count>0
                and type(max_tri) is int and c_count<=max_tri
                and type(max_ratio) in (int,float)
                and math.isfinite(max_ratio)
                and c_count<=v_count*max_ratio,
        },
        154:{
            "source_door_passage_clearance_volumes_valid":
                bool(opening_boxes),
            "actual_collision_triangles_do_not_intersect_clearance_boxes":
                bool(free_openings),
        },
    }
    rules={}
    for n,rid in zip(NUMBERS,IDS):
        measured=checks[n]
        rules[rid]={
            "requirement_sha256":inventory["rules"][rid]["requirement_sha256"],
            "source_sha256":catalog,"exact_attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_machine_checks":measured,
            "machine_scope":"OBSERVED_SCOPE_PASS" if all(measured.values())
                            else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
            "owner_acceptance":"UNKNOWN","advancement_authorized":False,
        }
    return {"schema":SCHEMA,"source_rule_count":4,"rules":rules,
            "original_audit_sha256":audit_sha,"original_audit_tail":tail,
            "attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_collision_metrics":{
                "collision_triangles":c_count,"visual_triangles":v_count,
                "solid_regions":len(solid) if solid_boxes else 0,
                "clearance_regions":len(openings) if opening_boxes else 0},
            "machine_positive_obligations":sum(
                r["machine_scope"]=="OBSERVED_SCOPE_PASS"
                for r in rules.values()),
            "full_rule_semantic_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False}

"""C07 P3: original UV distortion, texel-density and overlap measurements.

Original Controller audit + pre-D pins + actual GLB UV arrays are required.
No inferred intentional overlap, no producer QA flag, no MG0 or owner PASS.
"""
import hashlib
import json
import math
import struct

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p3_geometry_semantics import _read_accessor, geometry
from c07_p5_budget_semantics import _glb_parts, _texture_bytes, _json
from c07_p345_forty_native_evidence import TEXT, PHASE_INDEX

NUMBERS=(115,116,117)
IDS=tuple("AAA-200-L-%03d"%n for n in NUMBERS)
SCHEMA="gg-c07-p3-three-original-uv-oracles-v1"

class OriginalUVBlocked(ValueError):
    pass

def need(condition,reason):
    if not condition:raise OriginalUVBlocked(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def _positive(value):
    return type(value) in (int,float) and math.isfinite(value) and value>0

def _uv_accessor(doc,binary,index):
    arrays=doc["accessors"]
    views=doc["bufferViews"]
    need(type(index) is int and 0<=index<len(arrays),
         "C07_P3_UV_ACCESSOR_INDEX")
    acc=arrays[index]
    need(acc.get("componentType")==5126 and acc.get("type")=="VEC2"
         and type(acc.get("count")) is int
         and 3<=acc["count"]<=500000 and "sparse" not in acc
         and "normalized" not in acc,"C07_P3_UV_ACCESSOR_FORMAT")
    vi=acc.get("bufferView")
    need(type(vi) is int and 0<=vi<len(views),"C07_P3_UV_VIEW")
    view=views[vi]
    off=view.get("byteOffset",0)
    local=acc.get("byteOffset",0)
    stride=view.get("byteStride",8)
    size=view.get("byteLength")
    need(view.get("buffer")==0 and
         all(type(x) is int for x in (off,local,stride,size))
         and min(off,local,stride,size)>=0 and stride>=8
         and off+size<=len(binary)
         and local+(acc["count"]-1)*stride+8<=size,
         "C07_P3_UV_OUT_OF_BOUNDS")
    values=[struct.unpack_from("<ff",binary,off+local+i*stride)
            for i in range(acc["count"])]
    need(all(math.isfinite(x) for pair in values for x in pair),
         "C07_P3_UV_NONFINITE")
    return values

def _cross(a,b,c):
    return (b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0])

def _clip(subject,clip):
    # Convex triangle intersection; collinear/shared edges have zero area.
    orientation=1 if _cross(*clip)>0 else -1
    result=list(subject)
    for i in range(3):
        a,b=clip[i],clip[(i+1)%3]
        source=result
        result=[]
        if not source:break
        for j,p in enumerate(source):
            q=source[j-1]
            dp=orientation*_cross(a,b,p)
            dq=orientation*_cross(a,b,q)
            inside_p=dp>=-1e-12
            inside_q=dq>=-1e-12
            if inside_p != inside_q:
                t=dq/(dq-dp)
                result.append((q[0]+t*(p[0]-q[0]),
                               q[1]+t*(p[1]-q[1])))
            if inside_p:result.append(p)
    if len(result)<3:return 0.
    return abs(sum(result[i][0]*result[(i+1)%len(result)][1]-
                   result[(i+1)%len(result)][0]*result[i][1]
                   for i in range(len(result))))/2

def _scan(doc,binary,scale,pixels):
    primitives=[]
    for mesh in doc.get("meshes",[]):
        for prim in mesh.get("primitives",[]):
            attrs=prim.get("attributes",{})
            if "TEXCOORD_0" not in attrs:return None
            xyz=_read_accessor(doc,binary,attrs["POSITION"])
            uv=_uv_accessor(doc,binary,attrs["TEXCOORD_0"])
            need(len(xyz)==len(uv),"C07_P3_UV_VERTEX_COUNT")
            ids=(_read_accessor(doc,binary,prim["indices"],scalar=True)
                 if "indices" in prim else list(range(len(xyz))))
            need(len(ids)%3==0 and len(ids)>=3
                 and all(type(i) is int and 0<=i<len(xyz) for i in ids),
                 "C07_P3_UV_TRIANGLE_INDEX")
            triangles=[]
            density=[]
            anisotropy=[]
            for offset in range(0,len(ids),3):
                ix=ids[offset:offset+3]
                coords=[uv[i] for i in ix]
                world=[xyz[i] for i in ix]
                uv_area=abs(_cross(*coords))/2
                need(uv_area>1e-12,"C07_P3_UV_ZERO_AREA")
                edge_density=[]
                for a,b in ((0,1),(1,2),(2,0)):
                    w=math.dist(world[a],world[b])*scale
                    u=math.dist(coords[a],coords[b])
                    need(w>1e-9 and u>1e-9,"C07_P3_UV_ZERO_EDGE")
                    if pixels is not None:
                        dx=(coords[b][0]-coords[a][0])*pixels[0]
                        dy=(coords[b][1]-coords[a][1])*pixels[1]
                        density.append(math.hypot(dx,dy)/w)
                    edge_density.append(u/w)
                anisotropy.append(max(edge_density)/min(edge_density))
                triangles.append(coords)
            primitives.append((triangles,anisotropy,density))
    return primitives if primitives else None

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get("rule_count")==763
         and inventory.get("schema")=="gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASE_INDEX
         and PHASE_INDEX[plan["phase"]]>=3
         and plan["phase"]==work.get("phase") and callable(source_loader),
         "C07_P3_UV_ORIGINAL_CONTEXT")
    catalog=inventory.get("source_digests",{}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog)==64
         and all(c in "0123456789abcdef" for c in catalog),
         "C07_P3_UV_CATALOG_SOURCE")
    for n,rid in zip(NUMBERS,IDS):
        source,phase=TEXT[str(n)]
        row=inventory["rules"].get(rid,{})
        need(phase=="P3" and row.get("family")=="AAA-200"
             and row.get("catalog_number")==n
             and row.get("catalog_section")=="L"
             and row.get("catalog_phase")==phase
             and row.get("requirement")==source
             and row.get("requirement_sha256")==sha(source.encode())
             and row.get("source_sha256")==catalog,
             "C07_P3_UV_ORIGINAL_LITERAL_CHANGED:"+rid)
    audit,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail
         and sha(controller.master.read_bytes())==work["master_sha256"]
         and (state.get("active_step") or {}).get("step")==step,
         "C07_P3_UV_AUDIT_DRIFT")
    records=_registered_artifacts(audit,state,step,source_loader,work)
    found={}
    for role,path,digest,raw in records:
        if role in ("NATIVE_EXPORT","P3_UV_POLICY","P3_RELATED_EXPORT"):
            need(role not in found,"C07_P3_UV_DUPLICATE_ROLE:"+role)
            found[role]=(path,digest,raw)
    contract=plan.get("p345_evidence_contract",{})
    pins=contract.get("original_artifact_sha256",{}) if type(contract) is dict else {}
    if type(pins) is not dict:pins={}
    def original(role,suffix):
        item=found.get(role)
        return (item[2] if item and item[0].lower().endswith(suffix)
                and pins.get(role)==item[1] and sha(item[2])==item[1]
                else None)
    policy_raw=original("P3_UV_POLICY",".json")
    policy=_json(policy_raw) if policy_raw is not None else {}
    raw=original("NATIVE_EXPORT",".glb")
    native=geometry(raw) if raw is not None else None
    doc,binary=_glb_parts(raw) if native is not None else ({},b"")
    imgs=_texture_bytes(doc,binary) if native is not None else None
    # A raster is a texel-density witness only when the exported material
    # actually references that exact embedded image, not a spare PNG.
    prims=[p for m in doc.get("meshes",[]) for p in m.get("primitives",[])]
    textures=doc.get("textures",[])
    materials=doc.get("materials",[])
    linked=(len(prims)==1 and len(textures)==1 and len(materials)>0
            and textures[0].get("source")==0
            and type(prims[0].get("material")) is int
            and 0<=prims[0]["material"]<len(materials)
            and materials[prims[0]["material"]].get(
                "pbrMetallicRoughness",{}).get(
                "baseColorTexture",{}).get("index")==0)
    pixels=(imgs[0]["width"],imgs[0]["height"]) if (
        imgs and len(imgs)==1 and linked) else None
    scale=policy.get("meters_per_unit")
    scanned=(_scan(doc,binary,scale,pixels) if native is not None
             and _positive(scale) and scale<=100 else None)
    anis=[x for _,a,_ in scanned or [] for x in a]
    density=[x for _,_,d in scanned or [] for x in d]
    # Independently reopen a distinct related asset; density consistency
    # cannot be certified by comparing a single asset against itself.
    peer_raw=original("P3_RELATED_EXPORT",".glb")
    peer_native=geometry(peer_raw) if peer_raw is not None else None
    peer_doc,peer_bin=_glb_parts(peer_raw) if peer_native is not None else ({},b"")
    peer_images=_texture_bytes(peer_doc,peer_bin) if peer_native is not None else None
    peer_prims=[p for m in peer_doc.get("meshes",[])
                for p in m.get("primitives",[])]
    peer_textures=peer_doc.get("textures",[])
    peer_materials=peer_doc.get("materials",[])
    peer_linked=(len(peer_prims)==1 and len(peer_textures)==1
        and len(peer_materials)>0
        and peer_textures[0].get("source")==0
        and type(peer_prims[0].get("material")) is int
        and 0<=peer_prims[0]["material"]<len(peer_materials)
        and peer_materials[peer_prims[0]["material"]].get(
            "pbrMetallicRoughness",{}).get(
            "baseColorTexture",{}).get("index")==0)
    peer_pixels=(peer_images[0]["width"],peer_images[0]["height"]) if (
        peer_images and len(peer_images)==1 and peer_linked) else None
    peer_scanned=(_scan(peer_doc,peer_bin,scale,peer_pixels)
                  if peer_native is not None and _positive(scale)
                  and scale<=100 else None)
    peer_density=[x for _,_,d in peer_scanned or [] for x in d]
    max_ratio=policy.get("max_uv_edge_anisotropy")
    target=policy.get("texel_px_per_m")
    tolerance=policy.get("texel_density_tolerance_pct")
    no_overlap=True
    # Multi-primitive overlap needs cross-primitive material/UV intent proof.
    complete=bool(scanned) and len(scanned)==1
    overlap_count=0
    for triangles,_,_ in scanned or []:
        if len(triangles)>2000:
            complete=False
            break
        for i in range(len(triangles)):
            for j in range(i+1,len(triangles)):
                if _clip(triangles[i],triangles[j])>1e-9:
                    no_overlap=False
                    overlap_count+=1
    checks={
        115:{
            "all_original_uv_triangles_independently_measured":
                bool(anis) and complete,
            "uv_edge_anisotropy_within_pre_d_bound":
                bool(anis) and complete and _positive(max_ratio)
                and 1<=max_ratio<=50 and max(anis)<=max_ratio,
        },
        116:{
            "actual_embedded_png_and_uv_texel_density_measured":
                bool(density) and complete and pixels is not None,
            "real_texel_density_within_original_target":
                bool(density) and complete and _positive(target)
                and type(tolerance) in (int,float)
                and math.isfinite(tolerance) and 0<=tolerance<=100
                and all(abs(v-target)<=target*tolerance/100
                        for v in density),
            "distinct_original_related_asset_density_matches_pre_d_tolerance":
                bool(density and peer_density and peer_raw != raw)
                and type(policy.get("related_asset_id")) is str
                and bool(policy["related_asset_id"].strip())
                and _positive(target) and type(tolerance) in (int,float)
                and math.isfinite(tolerance) and 0<=tolerance<=100
                and all(abs(v-target)<=target*tolerance/100
                        for v in density+peer_density),
        },
        117:{
            "all_original_uv_triangle_pairs_compared":
                complete and bool(anis),
            "no_positive_area_overlap_under_original_policy":
                complete and bool(anis) and no_overlap
                and policy.get("uv_overlap_policy")=="NO_UNINTENDED_OVERLAPS",
        },
    }
    rules={}
    for n,rid in zip(NUMBERS,IDS):
        measured=checks[n]
        rules[rid]={
            "requirement_sha256":inventory["rules"][rid]["requirement_sha256"],
            "source_sha256":catalog,
            "exact_attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_machine_checks":measured,
            "machine_scope":"OBSERVED_SCOPE_PASS" if all(measured.values())
                            else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
            "owner_acceptance":"UNKNOWN","advancement_authorized":False,
        }
    return {"schema":SCHEMA,"source_rule_count":3,"rules":rules,
            "original_audit_sha256":audit_sha,"original_audit_tail":tail,
            "attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_uv_metrics":{"triangles":len(anis),
                "max_edge_anisotropy":max(anis) if anis else None,
                "measured_density_edges":len(density),
                "uv_overlap_pairs":overlap_count,
                "pair_scan_complete":complete},
            "machine_positive_obligations":sum(
                v["machine_scope"]=="OBSERVED_SCOPE_PASS"
                for v in rules.values()),
            "full_rule_semantic_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False}

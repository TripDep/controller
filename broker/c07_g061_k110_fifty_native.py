"""C07 G061-K110 original-byte native diagnostics, not full-rule/MG0 PASS.

Consume the canonical original Controller operation, original artifact bytes,
native world-geometry QA, independently recomputed winding and PNG integrity.
Quality, botanical science, engineering intent and in-game claims remain UNKNOWN.
"""
import re
from pathlib import Path
from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from glb_machine_qa import audit_bytes,parse,GLBError,MAX_BYTES
from glb_winding_readback import scan_bytes,WindingBlocked
from glb_pbr_evidence import validate_png_chunks,MaterialEvidenceError
from c07_gk50_canonical import CLAUSES,IDS,CATALOG_SHA
from c07_gk50_predicates import SPEC,UNVERIFIED
from c07_gk50_size_scan import readback as original_world_size_readback

SCHEMA="gg-c07-g061-k110-fifty-source-native-v1"
GROUP_PATTERNS={
 "architecture":r"building|facade|wall|roof|pillar|column|beam|door|window|stair",
 "structural":r"beam|pillar|column|support",
 "roof":r"roof|eave|tetto",
 "wall":r"wall|facade|parete",
 "door_window":r"door|window|porta|finestra",
 "stair_rail":r"stair|step|rail|gradin",
 "rock":r"rock|boulder|stone|taihu|rocc",
 "vegetation":r"tree|bamboo|bush|shrub|leaf|grass|plant|foliage",
 "trunk":r"trunk|tronco",
 "branch":r"branch|ramo",
 "foliage":r"leaf|frond|foglia|foliage",
 "lod":r"(?:^|[_ .-])lod(?:0|1|2|3|4|5|low|med|high)(?:$|[_ .-])",
 "terrain":r"ground|terrain|landscape|terreno|landform",
 "water":r"water|pond|lake|acqua|river",
 "path":r"path|walkway|sentiero",
 "bridge":r"bridge|ponte",
 "stairs":r"stair|step|gradin",
 "bank":r"bank|shore|sponda",
 "bevel":r"bevel|chamfer|smuss",
}
class GKBlocked(ValueError):pass
def need(cond, reason):
    if not cond:raise GKBlocked(reason)

def exact_catalog(inv):
    need(type(inv) is dict and inv.get("schema")=="gg-effective-family-inventory-v1"
         and inv.get("rule_count")==763
         and inv.get("source_digests",{}).get("aaa_catalog")==CATALOG_SHA,
         "GK50_ORIGINAL_INVENTORY_OR_CATALOG_DRIFT")
    need(len(CLAUSES)==len(IDS)==len(SPEC)==50 and
         set(CLAUSES)==set(SPEC),"GK50_MISSING_CANONICAL_RULE")
    for n,(section,wording,phase,kind) in CLAUSES.items():
        rid=IDS[n-61];row=inv.get("rules",{}).get(rid,{})
        need(row.get("family")=="AAA-200" and row.get("source_sha256")==CATALOG_SHA
             and row.get("catalog_number")==n and row.get("catalog_section")==section
             and row.get("catalog_phase")==phase=="P2"
             and row.get("asset_type")==kind
             and row.get("requirement")==wording
             and row.get("requirement_sha256")==sha(wording.encode("utf-8")),
             "GK50_ORIGINAL_CANONICAL_RULE_CHANGED:"+rid)

def machine_features(records,artifacts,plan,step,work):
    """Read actual GLB bytes, not a user or producer supplied PASS dictionary."""
    roles={};paths=set()
    for role,path,digest,raw in artifacts:
        need(type(role) is str and type(path) is str and path not in paths and
             type(raw) is bytes and len(raw)>0 and sha(raw)==digest,
             "GK50_DUPLICATE_OR_UNVERIFIED_ORIGINAL_ARTIFACT")
        paths.add(path);roles.setdefault(role,[]).append((path,digest,raw))
    originals=[x for x in roles.get("NATIVE_EXPORT",())
               if Path(x[0]).suffix.lower()==".glb"]
    need(len(originals)<=1,"GK50_MULTIPLE_REGISTERED_GLB")
    report=None;document=None;winding=None
    if originals:
        raw=originals[0][2]
        need(len(raw)<=MAX_BYTES,"GK50_REGISTERED_GLB_TOO_LARGE")
        try:
            report=audit_bytes(raw)
            document,_=parse(raw)
            need(report["source_sha256"]==originals[0][1],
                 "GK50_ORIGINAL_GLB_SHA_DRIFT")
            try:winding=scan_bytes(raw,originals[0][1])
            except (WindingBlocked,GLBError,ValueError,TypeError,KeyError):pass
        except (GLBError,ValueError,TypeError,KeyError,IndexError) as exc:
            raise GKBlocked("GK50_REGISTERED_ORIGINAL_GLB_INVALID:"+str(exc)) from exc
    meshes=(document or {}).get("meshes",[])
    nodes=(document or {}).get("nodes",[])
    names=[str(x.get("name","")) for x in meshes+nodes if type(x) is dict]
    def named(group):return any(re.search(GROUP_PATTERNS[group],name,re.I)
                                for name in names)
    def num(group):return sum(bool(re.search(GROUP_PATTERNS[group],name,re.I))
                              for name in names)
    def role(name):return len(roles.get(name,()))==1
    def image(view):
        a=roles.get("VISUAL_VIEW_"+view,())
        if len(a)!=1 or Path(a[0][0]).suffix.lower()!=".png":return False
        try:validate_png_chunks(a[0][2]);return True
        except (MaterialEvidenceError,ValueError,TypeError):return False
    exact_events=[e for e in records if
                  e.get("step")==step and
                  e.get("attempt_id")==work.get("attempt_id") and
                  e.get("operation_sha256")==work.get("operation_sha256")]
    event=lambda name:any(x.get("event")==name for x in exact_events)
    scan=(report or {}).get("triangle_surface_crossing_evidence",{})
    materials=(document or {}).get("materials",[])
    alpha=any(type(m) is dict and m.get("alphaMode") in ("MASK","BLEND")
              for m in materials)
    texalpha=any(type(m) is dict and m.get("alphaMode") in ("MASK","BLEND")
                 and "baseColorTexture" in m.get("pbrMetallicRoughness",{})
                 for m in materials)
    source_geometry=bool(report and report["triangles_examined"]>0)
    F={
      "source_geometry":source_geometry,
      "geometry_triangles":source_geometry,
      "bounded_world_bounds":bool(report and report["geometry_groups_with_bounds"]>0
                                  and report["checks"]["static_world_transform"]=="VERIFIED"),
      "reference_image":role("REFERENCE_IMAGE"),
      "front_view":image("FRONT"),"top_view":image("TOP"),
      "source_editable":role("SOURCE_EDITABLE"),
      "winding_readback":winding is not None,
      "winding_orientation_clean":bool(winding and
                    winding["same_direction_shared_edges"]==0
                    and winding["nonmanifold_edges"]==0),
      "normals_present":bool(document and any(
                    "NORMAL" in p.get("attributes",{})
                    for mesh in meshes for p in mesh.get("primitives",[]))),
      "degenerate_absent":bool(report and report["degenerate_triangles"]==0),
      "overlap_candidates_scanned":bool(report and
                                      report["geometry_groups_with_bounds"]>0),
      "crossing_scan_complete":scan.get("all_requested_pairs_fully_scanned") is True,
      "no_strict_crossings_observed":bool(
                    scan.get("all_requested_pairs_fully_scanned") is True and
                    scan.get("strict_surface_crossing_pairs_found")==0),
      "transform_matrix_valid":bool(report and
                    report["checks"]["static_world_transform"]=="VERIFIED"),
      "mesh_instances_shared":bool(document and
                    len([n["mesh"] for n in nodes if "mesh" in n])
                    >len(set(n["mesh"] for n in nodes if "mesh" in n))),
      "bevel_name_hint":named("bevel"),
      "architecture_named":named("architecture"),
      "architecture_multi_mesh":num("architecture")>=2,
      "structural_named":named("structural"),
      "roof_named":named("roof"),"wall_named":named("wall"),
      "door_window_named":named("door_window"),
      "stair_rail_named":named("stair_rail"),
      "rock_named":named("rock"),"rock_multi_instances":num("rock")>=2,
      "terrain_named":named("terrain"),
      "vegetation_named":named("vegetation"),
      "trunk_named":named("trunk"),"branch_named":named("branch"),
      "foliage_named":named("foliage"),"lod_named":named("lod"),
      "alpha_materials_observed":alpha,
      "alpha_texture_referenced":texalpha,
      "vegetation_multi_instances":num("vegetation")>=2,
      "runtime_evidence_recorded":event("FIVEM_RUNTIME_EVIDENCE"),
      "terrain_source_original":role("TERRAIN_HEIGHT_REFERENCE"),
      "original_target_dimensions":bool(
                    isinstance(plan.get("pre_d_control"),dict) and
                    plan["pre_d_control"].get("expected_measurements")),
      "water_named":named("water"),"path_named":named("path"),
      "bridge_named":named("bridge"),"stairs_named":named("stairs"),
      "bank_named":named("bank"),
    }
    # Numeric size comparisons must use geometry, not object labels.
    # The existing original GLB machine parser confirms actual dimensions,
    # but a pair of differently named objects alone does not prove variations.
    sizes=(original_world_size_readback(originals[0][2],report) if originals
           else {'rock':False,'vegetation':False})
    F["rock_bbox_variants"]=sizes['rock']
    F["vegetation_bbox_variants"]=sizes['vegetation']
    # No fake assertion that reference matches, a plant is botanical, terrain
    # aligns to survey heights, or the water/wind works in FiveM.
    unproven={key for scope in SPEC.values() for key in scope
             if key not in F}
    need(unproven==UNVERIFIED,
         "GK50_UNRECOGNIZED_SOURCE_RULE_PREDICATE:"+str(sorted(unproven)))
    F.update({key:False for key in unproven})
    need(all(type(v) is bool for v in F.values()),"GK50_INVALID_NATIVE_BOOL")
    return F,report

def inspect(inv,plan,controller,asset,step,work,*,source_loader):
    need(callable(source_loader),"GK50_ORIGINAL_BYTES_READER_REQUIRED")
    exact_catalog(inv)
    records,tail,state,audit_sha=_original_attempt(inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==inv["canonical_master_sha256"]
         ==work["master_sha256"] and state.get("last_audit_hash")==tail
         and (state.get("active_step") or {}).get("step")==step,
         "GK50_CURRENT_MASTER_OR_AUDIT_STATE_CHANGED")
    artifacts=_registered_artifacts(records,state,step,source_loader,work)
    features,report=machine_features(records,artifacts,plan,step,work)
    out={};checked=0;observed=0
    for n,(section,literal,phase,kind) in CLAUSES.items():
        rid=IDS[n-61];names=SPEC[n]
        need(len(names)>=3 and len(set(names))==len(names) and
             all(name in features for name in names),
             "GK50_MISSING_NATIVE_RULE_IMPLEMENTATION:"+rid)
        checks={name:features[name] for name in names}
        checked+=len(checks);observed+=sum(checks.values())
        due=work.get("asset_type")==kind and work.get("phase") in (
            "P2","P3","P4","P5","P6","P7","P8")
        out[rid]={
            "rule_id":rid,"requirement_sha256":inv["rules"][rid]["requirement_sha256"],
            "source_sha256":CATALOG_SHA,"canonical_requirement":literal,
            "applicability":"DUE" if due else
              ("FUTURE_PHASE" if work.get("phase") in ("P0","P1") else
               "N_A_ASSET_TYPE"),
            "native_byte_checks":checks,
            "observed":sorted(k for k,v in checks.items() if v),
            "not_proven":sorted(k for k,v in checks.items() if not v),
            "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
            "owner_approval":"UNKNOWN","advancement_authorized":False,
        }
    need(checked>=150 and len(out)==50,"GK50_50_RULE_SCOPE_INCOMPLETE")
    return {
       "schema":SCHEMA,"asset":asset,"step":step,
       "attempt_id":work["attempt_id"],"operation_sha256":work["operation_sha256"],
       "original_audit_sha256":audit_sha,"original_audit_tail":tail,
       "native_glb_sha256":report["source_sha256"] if report else None,
       "source_rules_examined":50,"native_conditions_evaluated":checked,
       "native_conditions_observed":observed,
       "full_rule_passes":0,"individual_mg0_passes":0,
       "advancement_authorized":False,"rules":out}

"""C07 P6 P-155..160: original collision, walkable, terrain and vehicle probes.

Actual GTA/FiveM player movement and runtime collision are NOT attestable
from a producer-supplied log. P-160 is deliberately never machine-positive.
Original audit/operation, pre-D SHA and native GLB bytes are mandatory.
"""
import hashlib
import math
from c07_positive_native_process import _original_attempt,_registered_artifacts
from c07_p6_collision_semantics import _triangles,_box,_aabb_intersects,_centroid_in
from c07_p5_budget_semantics import _json
from c07_p678_forty_native_domain import TEXT,PHASES

NUMBERS=tuple(range(155,161))
IDS=tuple("AAA-200-P-%03d"%n for n in NUMBERS)
SCHEMA="gg-c07-p6-six-original-walkability-probes-v1"
class OriginalWalkabilityBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise OriginalWalkabilityBlocked(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def finite(v):return type(v) in (int,float) and math.isfinite(v)
def valid_zones(rows,*,kind=None):
    return (type(rows) is list and bool(rows) and len(rows)<=128
            and all(type(r) is dict and _box(r) is not None
                    and type(r.get("name")) is str and bool(r["name"])
                    and (kind is None or r.get("kind")==kind)
                    for r in rows)
            and len({r["name"] for r in rows})==len(rows))
def triangles_in_region(triangles,zone):
    return any(_centroid_in(t,_box(zone)) for t in triangles)

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(type(inventory) is dict and inventory.get("rule_count")==763
         and inventory.get("schema")=="gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASES and PHASES[plan["phase"]]>=6
         and work.get("phase")==plan["phase"] and callable(source_loader),
         "C07_P6_WALKABILITY_CONTEXT")
    catalog=inventory.get("source_digests",{}).get("aaa_catalog")
    need(type(catalog) is str and len(catalog)==64
         and all(c in "0123456789abcdef" for c in catalog),
         "C07_P6_WALKABILITY_SOURCE")
    for n,rid in zip(NUMBERS,IDS):
        literal,phase=TEXT[str(n)]
        row=inventory["rules"].get(rid,{})
        need(phase=="P6" and row.get("family")=="AAA-200"
             and row.get("catalog_number")==n
             and row.get("catalog_section")=="P"
             and row.get("catalog_phase")==phase
             and row.get("requirement")==literal
             and row.get("requirement_sha256")==sha(literal.encode())
             and row.get("source_sha256")==catalog,
             "C07_P6_WALKABILITY_LITERAL_CHANGED:"+rid)
    audit,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail
         and sha(controller.master.read_bytes())==work["master_sha256"]
         and (state.get("active_step") or {}).get("step")==step,
         "C07_P6_WALKABILITY_AUDIT_DRIFT")
    found={}
    for role,path,digest,raw in _registered_artifacts(
            audit,state,step,source_loader,work):
        need(role not in found,"C07_P6_WALKABILITY_DUPLICATE_ROLE:"+role)
        found[role]=(path,digest,raw)
    contract=plan.get("p678_evidence_contract",{})
    pins=contract.get("original_artifact_sha256",{}) if type(contract) is dict else {}
    if type(pins) is not dict:pins={}
    def original(role,ext):
        row=found.get(role)
        return (row[2] if row and row[0].lower().endswith(ext)
                and pins.get(role)==row[1] and sha(row[2])==row[1] else None)
    raw_policy=original("P6_COLLISION_POLICY",".json")
    policy=_json(raw_policy) if raw_policy is not None else {}
    native=original("NATIVE_EXPORT",".glb")
    collision=original("COLLISION_EXPORT",".glb")
    terrain=original("TERRAIN_EXPORT",".glb")
    native_tris=_triangles(native) if native is not None else None
    coll_tris=_triangles(collision) if collision is not None else None
    terrain_tris=_triangles(terrain) if terrain is not None else None
    solid=policy.get("solid_surfaces")
    walk=policy.get("walkable_regions")
    vehicle=policy.get("vehicle_corridors")
    solid_ok=valid_zones(solid)
    walk_ok=valid_zones(walk)
    vehicle_ok=valid_zones(vehicle,kind="vehicle")
    solid_proxy=(solid_ok and coll_tris is not None
                 and all(triangles_in_region(coll_tris,z) for z in solid))
    # A collision triangle entirely outside the visual AABB is an
    # independently measurable invisible proxy; this is not game visibility.
    def global_bounds(triangles):
        return ([min(p[i] for t in triangles for p in t) for i in range(3)],
                [max(p[i] for t in triangles for p in t) for i in range(3)])
    visual_box=global_bounds(native_tris) if native_tris else None
    collision_inside_visual=(visual_box is not None and coll_tris is not None
        and all(all(visual_box[0][i]-0.001<=p[i]<=visual_box[1][i]+0.001
                    for i in range(3)) for t in coll_tris for p in t))
    walk_surfaces=(walk_ok and coll_tris is not None
        and all(triangles_in_region(coll_tris,z) for z in walk))
    player_width=policy.get("min_player_width_m")
    walk_clearance=bool(walk_ok and finite(player_width)
        and 0.4<=player_width<=2.0
        and all(min(z["max_xyz"][i]-z["min_xyz"][i]
                    for i in (0,1))>=player_width for z in walk))
    # Compare original collision and original terrain Z at coincident XY
    # triangle centroids. This is a source geometry proxy, NOT a game test.
    max_gap=policy.get("terrain_contact_max_gap_m")
    # Hash measured terrain centroids into 5 cm XY cells. This preserves
    # exact 5 cm XY tolerance with adjacent-cell probes and avoids O(N*M)
    # scans of large collision/terrain exports.
    contact_ok=False
    contact_regions_verified=False
    matched=[]
    if (coll_tris is not None and terrain_tris is not None
            and finite(max_gap) and 0<=max_gap<=0.5):
        def center(tri):
            return tuple(sum(p[i] for p in tri)/3 for i in range(3))
        def cell(v):
            return (math.floor(v[0]/0.05),math.floor(v[1]/0.05))
        terrain_grid={}
        for tri in terrain_tris:
            p=center(tri)
            terrain_grid.setdefault(cell(p),[]).append(p)
        matched=[]
        for tri in coll_tris:
            p=center(tri)
            x,y=cell(p)
            if any(abs(p[0]-q[0])<=0.05 and
                   abs(p[1]-q[1])<=0.05 and
                   abs(p[2]-q[2])<=max_gap
                   for dx in (-1,0,1) for dy in (-1,0,1)
                   for q in terrain_grid.get((x+dx,y+dy),())):
                matched.append(p)
        contact_ok=bool(matched)
        regions=policy.get("terrain_contact_regions")
        contact_regions_verified=bool(valid_zones(regions) and
            all(any(all(lo<=p[i]<=hi for i,(lo,hi) in enumerate(
                    zip(zone["min_xyz"],zone["max_xyz"])))
                    for p in matched) for zone in regions))
    vehicle_clear=(vehicle_ok and coll_tris is not None
        and all(not any(_aabb_intersects(t,_box(z)) for t in coll_tris)
                for z in vehicle))
    vehicle_height=policy.get("min_vehicle_height_m")
    vehicle_vertical_clearance=bool(vehicle_ok and finite(vehicle_height)
        and 1.5<=vehicle_height<=5.0
        and all(z["max_xyz"][2]-z["min_xyz"][2]>=vehicle_height
                for z in vehicle))
    widths=(vehicle_ok and finite(policy.get("min_vehicle_width_m"))
        and 1.5<=policy["min_vehicle_width_m"]<=15
        and all(z["max_xyz"][0]-z["min_xyz"][0]>=
                policy["min_vehicle_width_m"] for z in vehicle))
    # These two observations do not imply a real FiveM session, no matter
    # what producer-controlled logs or QA events claim.
    runtime=original("FIVEM_COLLISION_RUNTIME_LOG",".log")
    runtime_attested=False
    checks={
      155:{"original_solid_surface_collision_proxy_recomputed":bool(solid_proxy),
           "original_collision_faces_nonempty":bool(coll_tris)},
      156:{"original_collision_and_visual_meshes_reopened":
               bool(coll_tris and native_tris),
           "original_collision_vertices_inside_visual_bounds":
               bool(collision_inside_visual)},
      157:{"original_walkable_region_boxes_valid":bool(walk_ok),
           "each_walkable_region_has_original_collision_surface":
               bool(walk_surfaces),
           "every_walkable_region_has_source_pinned_player_width_clearance":
               walk_clearance},
      158:{"original_collision_and_terrain_triangles_reopened":
               bool(coll_tris and terrain_tris),
           "original_terrain_collision_contact_centroids_measured":
               bool(contact_ok),
           "every_pre_d_contact_region_has_independently_matched_source_geometry":
               contact_regions_verified},
      159:{"original_vehicle_corridor_widths_measured":bool(widths),
           "actual_collision_faces_clear_of_vehicle_corridors":
               bool(vehicle_clear),
           "every_vehicle_corridor_has_source_pinned_vertical_clearance":
               vehicle_vertical_clearance},
      160:{"original_fivem_runtime_log_registered":
               runtime is not None,
           "independent_fivem_runtime_walkability_attested":
               runtime_attested},
    }
    # Six original-geometry semantic obligations beyond source presence.
    # Static triangle coverage cannot attest a player's FiveM collision test.
    def center(triangle):
        return tuple(sum(p[i] for p in triangle)/3 for i in range(3))
    def actual_solid_contact():
        # A matching triangle centroid does not establish that the collision
        # surface covers the original solid mesh: tiny triangles with the same
        # centroid could let a player fall through. Compare each original
        # visual triangle vertex to the actual collision triangle surfaces.
        if not (solid_proxy and native_tris and coll_tris):
            return False
        tolerance=policy.get("max_visual_collision_gap_m",0.05)
        if not finite(tolerance) or not 0<=tolerance<=0.2:
            return False
        from c07_p6_invisible_collision_full_review import (
            surface_distance, unit_normal, dot)
        for zone in solid:
            box=_box(zone)
            visual=[t for t in native_tris if _centroid_in(t,box)]
            collision=[t for t in coll_tris if _centroid_in(t,box)]
            if not visual or not collision:
                return False
            # Refuse to claim a complete static proof on an unbounded
            # Cartesian scan; keep UNKNOWN rather than sampling a few faces.
            if len(visual)*len(collision)>2_000_000:
                return False
            collision_normals=[unit_normal(t) for t in collision]
            if any(n is None for n in collision_normals):
                return False
            for tri in visual:
                normal=unit_normal(tri)
                if normal is None:
                    return False
                for vertex in tri:
                    if not any(
                        abs(dot(normal,cn))>=0.9 and
                        surface_distance(vertex,ct)<=tolerance
                        for ct,cn in zip(collision,collision_normals)):
                        return False
        return True
    deep={
      155:("original_solid_visual_triangles_supported_by_collision_geometry",
           bool(actual_solid_contact())),
      156:("original_collision_proxy_inside_real_visual_mesh_envelope",
           bool(collision_inside_visual and coll_tris and native_tris)),
      157:("original_walkable_corridors_fit_pre_d_player_width",
           bool(walk_surfaces and walk_clearance)),
      158:("every_original_collision_triangle_matches_original_terrain_contact",
           bool(contact_regions_verified and coll_tris and
                len(matched)==len(coll_tris))),
      159:("original_vehicle_corridors_have_measured_horizontal_vertical_clearance",
           bool(widths and vehicle_clear and vehicle_vertical_clearance)),
      160:("independent_actual_fivem_player_collision_and_walkability_proof",False),
    }
    need(set(deep)==set(NUMBERS) and
         len({name for name,_ in deep.values()})==6 and
         all(type(v) is bool for _,v in deep.values()),
         "C07_P6_SIX_DISTINCT_ORIGINAL_SEMANTIC_PREDICATES")
    result={}
    for n,rid in zip(NUMBERS,IDS):
        c=checks[n]
        need(len(c)==(3 if n in (157,158,159) else 2)
             and all(type(v) is bool for v in c.values()),
             "C07_P6_WALKABILITY_EXACT_RULE_CHECKS:"+rid)
        result[rid]={
            "requirement_sha256":inventory["rules"][rid]["requirement_sha256"],
            "source_sha256":catalog,"exact_attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "original_machine_checks":c,
            "original_cross_source_semantic":{deep[n][0]:deep[n][1]},
            "machine_scope":"OBSERVED_SCOPE_PASS" if all(c.values())
                            else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
            "owner_acceptance":"UNKNOWN","advancement_authorized":False}
    return {"schema":SCHEMA,"source_rule_count":6,"rules":result,
            "original_audit_sha256":audit_sha,"original_audit_tail":tail,
            "attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "metrics":{"collision_triangles":len(coll_tris or []),
                       "terrain_triangles":len(terrain_tris or []),
                       "walkable_regions":len(walk) if walk_ok else 0,
                       "vehicle_corridors":len(vehicle) if vehicle_ok else 0,
                       "fivem_runtime_independently_attested":False},
            "machine_positive_obligations":sum(
                v["machine_scope"]=="OBSERVED_SCOPE_PASS" for v in result.values()),
            "original_cross_source_positive_obligations":sum(
                value for _,value in deep.values()),
            "full_rule_semantic_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False}

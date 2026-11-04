"""C07: independent byte-backed M-121..Q-170 original work observations.

Material, visual, optimization, collision and FiveM rules are evaluated by
distinct native predicates bound to the canonical catalog and authenticated
current attempt. GLB/PBR fields are computed from registered original bytes;
visual shots and native-file names are read from original registered artifacts.
No descriptive labels, completed CI jobs or producer claims can certify art,
runtime, user approval, an individual MG0 or a complete canonical rule.
"""
import re
from pathlib import Path

from c07_positive_native_process import _original_attempt, _registered_artifacts, sha
from glb_machine_qa import audit_bytes, parse, MAX_BYTES, GLBError

SCHEMA = "gg-c07-m121-q170-fifty-original-native-v1"
CATALOG_SHA = "f9e7e0d11398c26095f5b3a83a2cf1e8a14ea459bc47dc09c4dfad891664fcf9"
CLAUSES = {
    121: "Identificare correttamente il materiale fisico rappresentato.",
    122: "Studiare roughness, riflettanza e comportamento delle superfici reali.",
    123: "Utilizzare mappe normal, roughness e altre proprietà quando supportate.",
    124: "Evitare colori uniformi che rendono i materiali artificiali.",
    125: "Introdurre variazioni credibili di superficie.",
    126: "Preparare legno, pietra, metallo, vetro e intonaco con caratteristiche differenti.",
    127: "Evitare texture troppo pulite o usurate senza motivo.",
    128: "Verificare risoluzione, compressione e costo delle texture.",
    129: "Adattare i materiali allo shader supportato dal motore di destinazione.",
    130: "Controllare che il materiale resti coerente sotto diverse condizioni di illuminazione.",
    131: "Utilizzare illuminazione neutra per verificare il modello.",
    132: "Separare l’illuminazione di controllo da quella cinematografica.",
    133: "Controllare come la luce evidenzia i difetti geometrici.",
    134: "Verificare il comportamento dei materiali in luce diretta.",
    135: "Verificare il comportamento in ombra.",
    136: "Controllare superfici metalliche, vetri e materiali riflettenti.",
    137: "Osservare il modello dalla visuale del giocatore.",
    138: "Produrre viste frontali, laterali, posteriori e dall’alto per il QA.",
    139: "Non utilizzare render suggestivi per nascondere difetti.",
    140: "Distinguere la qualità della presentazione dalla qualità tecnica dell’asset.",
    141: "Stabilire un budget prestazionale coerente con la scena e la piattaforma.",
    142: "Controllare il numero di triangoli delle mesh.",
    143: "Eliminare geometria invisibile quando non necessaria.",
    144: "Preparare LOD coerenti con distanza e importanza dell’asset.",
    145: "Verificare le transizioni tra i livelli di dettaglio.",
    146: "Ridurre il costo dei materiali quando possibile.",
    147: "Riutilizzare texture e materiali senza impoverire la scena.",
    148: "Controllare il consumo di memoria delle texture.",
    149: "Valutare il costo della vegetazione e delle superfici trasparenti.",
    150: "Misurare le prestazioni nel contesto reale, senza inventare benchmark.",
    151: "Identificare le superfici che necessitano di collisione.",
    152: "Separare collisioni e geometria visiva.",
    153: "Evitare collisioni inutilmente complesse.",
    154: "Controllare porte, passaggi, scale e corrimano.",
    155: "Verificare che il giocatore non attraversi superfici solide.",
    156: "Verificare che non esistano collisioni invisibili indesiderate.",
    157: "Controllare le zone accessibili a piedi.",
    158: "Testare punti di contatto tra edifici e terreno.",
    159: "Considerare eventuali passaggi dei veicoli.",
    160: "Verificare collisioni e percorribilità dentro il motore di gioco.",
    161: "Conoscere la struttura delle risorse di GTA V/FiveM.",
    162: "Comprendere la funzione di .ydr per i drawable.",
    163: "Comprendere il ruolo dei dizionari texture .ytd.",
    164: "Comprendere la funzione degli archetipi .ytyp.",
    165: "Comprendere il posizionamento degli oggetti tramite .ymap.",
    166: "Comprendere le collisioni .ybn.",
    167: "Utilizzare Sollumz per preparare gli asset compatibili.",
    168: "Verificare shader RAGE, attributi dei vertici e materiali supportati.",
    169: "Controllare posizionamento, streaming, LOD e visualizzazione in CodeWalker.",
    170: "Provare gli asset in FiveM prima di dichiararli pronti per il gioco.",
}
IDS = tuple("AAA-200-" + "MNOPQ"[(n-121)//10] + "-%03d" % n for n in CLAUSES)
SECTIONS = "MNOPQ"
PNG = b"\x89PNG\r\n\x1a\n"
NATIVE_SUFFIXES = frozenset((".ydr", ".ytd", ".ytyp", ".ymap", ".ybn"))
ENGINE_SUFFIXES = (".ydr", ".ytd", ".ytyp", ".ymap", ".ybn")
VIEWS = ("FRONT", "REAR", "TOP", "RIGHT", "LEFT", "UNDERSIDE", "PLAYER", "SHADOW", "DIRECT")

class Native50Blocked(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise Native50Blocked(why)

def literal_sources(inv):
    need(type(inv) is dict and inv.get("schema") == "gg-effective-family-inventory-v1"
         and inv.get("rule_count") == 763 and
         inv.get("source_digests", {}).get("aaa_catalog") == CATALOG_SHA,
         "M121_Q170_CANONICAL_SOURCE_OR_INVENTORY_CHANGED")
    for n, sentence in CLAUSES.items():
        section = SECTIONS[(n - 121) // 10]
        rid = "AAA-200-" + section + "-%03d" % n
        row = inv.get("rules", {}).get(rid, {})
        need(row.get("family") == "AAA-200" and
             row.get("catalog_section") == section and
             row.get("catalog_number") == n and
             row.get("catalog_phase") == ("P4" if n <= 140 else "P5" if n <= 150 else "P6" if n <= 160 else "P7") and
             row.get("requirement") == sentence and
             row.get("requirement_sha256") == sha(sentence.encode("utf-8")) and
             row.get("source_sha256") == CATALOG_SHA,
             "M121_Q170_ORIGINAL_RULE_CHANGED:" + rid)

def original_features(records, artifact_rows, plan, state, step, work):
    """Read original model bytes once. Missing/unsupported evidence is not PASS."""
    roles = {}
    native = {}
    seen_paths = set()
    for role, path, digest, data in artifact_rows:
        need(type(role) is str and type(path) is str and
             path not in seen_paths and type(data) is bytes and
             len(data) > 0 and sha(data) == digest,
             "M121_Q170_DUPLICATE_OR_UNTRUSTED_ARTIFACT")
        seen_paths.add(path)
        roles.setdefault(role, []).append((path, digest, data))
        suffix = Path(path).suffix.lower()
        if suffix in NATIVE_SUFFIXES:
            native.setdefault(suffix, []).append((path, digest, data))
    glb = [a for a in roles.get("NATIVE_EXPORT", [])
           if Path(a[0]).suffix.lower() == ".glb"]
    need(len(glb) <= 1, "M121_Q170_AMBIGUOUS_REGISTERED_GLB")
    report, g = None, None
    if glb:
        raw = glb[0][2]
        need(len(raw) <= MAX_BYTES, "M121_Q170_GLB_EXCEEDS_NATIVE_SAFETY_LIMIT")
        try:
            report = audit_bytes(raw)
            g, _ = parse(raw)
        except (GLBError, ValueError, KeyError, TypeError, IndexError) as exc:
            # A corrupt independently registered GLB is not merely unknown.
            raise Native50Blocked("M121_Q170_INVALID_REGISTERED_NATIVE_GLB:" +
                                  str(exc)) from exc
        need(report["source_sha256"] == glb[0][1],
             "M121_Q170_REGISTERED_GLB_HASH_MISMATCH")
    pbr = (report or {}).get("material_source_evidence", {})
    mesh_names = [str(m.get("name", "")) for m in (g or {}).get("meshes", [])
                  if type(m) is dict]
    node_names = [str(x.get("name", "")) for x in (g or {}).get("nodes", [])
                  if type(x) is dict]
    materials = [m for m in (g or {}).get("materials", [])
                 if type(m) is dict]
    used = set(pbr.get("used_material_indices", []))
    selected_mats = [m for i,m in enumerate((g or {}).get("materials", []))
                     if i in used and type(m) is dict]
    factors = [m.get("pbrMetallicRoughness", {}) for m in selected_mats]
    dims = [v for v in pbr.get("referenced_image_dimensions", {}).values()
            if type(v) is list and len(v) == 2 and
            all(type(x) is int and x > 0 for x in v)]
    distinct_pbr_factors = set(
        (tuple(p.get("baseColorFactor", (1,1,1,1))),
         p.get("metallicFactor", 1), p.get("roughnessFactor", 1))
        for p in factors if type(p) is dict
    )
    # Capture only recognized originally registered PNG bytes, not render labels.
    shots = {}
    for view in VIEWS:
        candidates = roles.get("VISUAL_VIEW_" + view, [])
        shots[view] = (len(candidates) == 1 and
                       Path(candidates[0][0]).suffix.lower() == ".png" and
                       candidates[0][2].startswith(PNG))
    current = [r for r in records if r.get("step") == step
               and r.get("attempt_id") == work.get("attempt_id")
               and r.get("operation_sha256") == work.get("operation_sha256")]
    def event(name):
        return any(x.get("event") == name for x in current)
    def native_role(suffix):
        return bool(native.get(suffix))
    has_model = report is not None
    no_errors = has_model and not report["errors"]
    # Machine checks may be useful without claiming visual/runtime quality.
    features = {
      "registered_glb_original": has_model,
      "glb_header_structurally_valid": has_model,
      "glb_geometry_nonempty": has_model and report["triangles_examined"] > 0,
      "glb_no_fatal_geometry_errors": bool(no_errors),
      "glb_no_unsupported_features": has_model and not report["unsupported_requires_independent_check"],
      "pbr_structurally_valid": bool(no_errors and not pbr.get("pbr_structural_errors")),
      "used_materials_exist": bool(selected_mats),
      "distinct_materials_present": len(selected_mats) > 1,
      "named_materials_present": bool(selected_mats) and all(bool(m.get("name")) for m in selected_mats),
      "distinct_pbr_numeric_factors": len(distinct_pbr_factors) >= 2,
      "material_roughness_numbers": bool(factors) and all(
          type(p.get("roughnessFactor", 1)) in (int,float) for p in factors),
      "material_metalness_numbers": bool(factors) and all(
          type(p.get("metallicFactor", 1)) in (int,float) for p in factors),
      "normal_texture_referenced": any("normalTexture" in m for m in selected_mats),
      "roughness_texture_referenced": any("metallicRoughnessTexture" in p for p in factors),
      "albedo_texture_referenced": any("baseColorTexture" in p for p in factors),
      "uv_sets_checked": pbr.get("uv_sets_finite_checked",0) > 0,
      "texture_image_dimensions_reopened": bool(dims),
      "referenced_texture_count_positive": pbr.get("referenced_textures_count",0) > 0,
      "texture_dimensions_power_of_two": bool(dims) and all(
          (w & (w-1)) == 0 and (h & (h-1)) == 0 for w,h in dims),
      "material_alpha_structural_observation": bool(selected_mats) and
          all(m.get("alphaMode","OPAQUE") in ("OPAQUE","MASK","BLEND") for m in selected_mats),
      "surface_normals_present": has_model and any(
          "NORMAL" in p.get("attributes",{})
          for m in g.get("meshes", []) for p in m.get("primitives", [])),
      "texture_diagnostic_warnings_examined": bool(has_model),
      "neutral_view_source_png": shots["FRONT"],
      "rear_view_source_png": shots["REAR"],
      "right_view_source_png": shots["RIGHT"],
      "left_view_source_png": shots["LEFT"],
      "top_view_source_png": shots["TOP"],
      "underside_view_source_png": shots["UNDERSIDE"],
      "player_view_source_png": shots["PLAYER"],
      "direct_light_view_source_png": shots["DIRECT"],
      "shadow_view_source_png": shots["SHADOW"],
      "original_visual_qa_event_present": event("SUPERVISOR_NATIVE_QA"),
      "original_cinematic_view_separate": bool(roles.get("CINEMATIC_VIEW")),
      "original_neutral_qa_declared": event("NEUTRAL_LIGHTING_QA"),
      "original_player_camera_qa_declared": event("PLAYER_CAMERA_QA"),
      "original_material_direct_qa_declared": event("DIRECT_LIGHT_MATERIAL_QA"),
      "original_material_shadow_qa_declared": event("SHADOW_MATERIAL_QA"),
      "original_renderer_source_authenticated": False,
      "original_geometry_defect_visual_reviewed": False,
      "original_artistic_quality_independently_approved": False,
      "triangle_count_from_original_indices": has_model and report["triangles_examined"] > 0,
      "original_mesh_primitive_count": has_model and report["mesh_primitives"] > 0,
      "no_degenerate_triangles_found": bool(no_errors and report["degenerate_triangles"] == 0),
      "material_instance_count_measured": bool(selected_mats),
      "texture_dimensions_measured": bool(dims),
      "transparent_material_count_observed": has_model and
          any(m.get("alphaMode") == "BLEND" for m in selected_mats),
      "vegetation_named_meshes_present": any(
          re.search("tree|grass|bush|leaf|vegetation|foliage", x, re.I)
          for x in mesh_names+node_names),
      "named_lod_hierarchy_present": any(
          re.search(r"(?:^|[_ .-])lod(?:0|1|2|3|4|5|low|med|high)(?:$|[_ .-])", x, re.I)
          for x in mesh_names+node_names),
      "source_scene_crossing_candidates_scanned": has_model and
          type(report.get("triangle_surface_crossing_evidence")) is dict,
      "collision_named_meshes_present": any(
          re.search("collision|colmesh|bound|ybn", x, re.I)
          for x in mesh_names+node_names),
      "editable_source_original_verified": bool(roles.get("SOURCE_EDITABLE")),
      "original_native_reimport_bytes": bool(roles.get("NATIVE_REIMPORT")),
      "original_runtime_evidence_event_present": event("FIVEM_RUNTIME_EVIDENCE"),
      "registered_native_ydr": native_role(".ydr"),
      "registered_native_ytd": native_role(".ytd"),
      "registered_native_ytyp": native_role(".ytyp"),
      "registered_native_ymap": native_role(".ymap"),
      "registered_native_ybn": native_role(".ybn"),
      "original_fivem_manifest_bytes_present": bool(roles.get("FIVEM_MANIFEST")),
      "original_codewalker_qa_record": event("CODEWALKER_NATIVE_QA"),
      "original_sollumz_native_export_record": event("SOLLUMZ_EXPORT_READBACK"),
      "original_runtime_collision_walk_record": event("FIVEM_COLLISION_WALK_QA"),
      "original_runtime_streaming_record": event("FIVEM_STREAMING_QA"),
      "original_declared_perf_budget": bool(plan.get("pre_d_control",{}).get("performance_budget")),
      "original_runtime_frame_measurement_verified": False,
      "original_runtime_collision_proven": False,
      "native_drawable_header_validated": False,
      "native_texture_dictionary_validated": False,
      "native_ytyp_archetypes_validated": False,
      "native_ymap_placements_validated": False,
      "native_ybn_collision_structures_validated": False,
      "correct_lod_transition_independently_replayed": False,
      "geometry_visibility_independently_proven": False,
      "lighting_quality_independently_proven": False,
      "collision_stability_independently_proven": False,
      "optimization_benefit_independently_measured": False,
      "material_authenticity_independently_proven": False,
      "true_fivem_runtime_playback_verified": False,
    }
    need(all(type(v) is bool for v in features.values()),
         "M121_Q170_MISSING_BOOLEAN_NATIVE_EVIDENCE")
    return features, report, shots

# Each source clause gets separate *meaningful original-byte observations*.
# A condition is a source observation, NOT completion of that requirement.
# Deliberately unverified physical/artistic/runtime criteria remain False.
RULE_PREDICATES = {
121: ("used_materials_exist","named_materials_present","material_authenticity_independently_proven"),
122: ("pbr_structurally_valid","material_roughness_numbers","material_metalness_numbers","material_authenticity_independently_proven"),
123: ("normal_texture_referenced","roughness_texture_referenced","uv_sets_checked","pbr_structurally_valid"),
124: ("albedo_texture_referenced","distinct_pbr_numeric_factors","original_artistic_quality_independently_approved"),
125: ("distinct_materials_present","distinct_pbr_numeric_factors","material_authenticity_independently_proven"),
126: ("named_materials_present","distinct_materials_present","material_roughness_numbers","material_authenticity_independently_proven"),
127: ("albedo_texture_referenced","texture_diagnostic_warnings_examined","original_artistic_quality_independently_approved"),
128: ("texture_image_dimensions_reopened","texture_dimensions_power_of_two","optimization_benefit_independently_measured"),
129: ("pbr_structurally_valid","registered_native_ydr","native_drawable_header_validated"),
130: ("direct_light_view_source_png","shadow_view_source_png","lighting_quality_independently_proven"),
131: ("neutral_view_source_png","original_neutral_qa_declared","original_renderer_source_authenticated"),
132: ("neutral_view_source_png","original_cinematic_view_separate","original_renderer_source_authenticated"),
133: ("neutral_view_source_png","glb_no_fatal_geometry_errors","original_geometry_defect_visual_reviewed"),
134: ("direct_light_view_source_png","original_material_direct_qa_declared","lighting_quality_independently_proven"),
135: ("shadow_view_source_png","original_material_shadow_qa_declared","lighting_quality_independently_proven"),
136: ("material_alpha_structural_observation","material_metalness_numbers","direct_light_view_source_png","lighting_quality_independently_proven"),
137: ("player_view_source_png","original_player_camera_qa_declared","true_fivem_runtime_playback_verified"),
138: ("neutral_view_source_png","right_view_source_png","rear_view_source_png","top_view_source_png"),
139: ("neutral_view_source_png","underside_view_source_png","original_geometry_defect_visual_reviewed"),
140: ("glb_no_fatal_geometry_errors","original_visual_qa_event_present","original_artistic_quality_independently_approved"),
141: ("triangle_count_from_original_indices","original_declared_perf_budget","original_runtime_frame_measurement_verified"),
142: ("triangle_count_from_original_indices","original_mesh_primitive_count","glb_no_fatal_geometry_errors"),
143: ("source_scene_crossing_candidates_scanned","glb_no_fatal_geometry_errors","geometry_visibility_independently_proven"),
144: ("named_lod_hierarchy_present","original_mesh_primitive_count","correct_lod_transition_independently_replayed"),
145: ("named_lod_hierarchy_present","original_native_reimport_bytes","correct_lod_transition_independently_replayed"),
146: ("material_instance_count_measured","referenced_texture_count_positive","optimization_benefit_independently_measured"),
147: ("referenced_texture_count_positive","material_instance_count_measured","original_artistic_quality_independently_approved"),
148: ("texture_dimensions_measured","referenced_texture_count_positive","optimization_benefit_independently_measured"),
149: ("vegetation_named_meshes_present","transparent_material_count_observed","triangle_count_from_original_indices","optimization_benefit_independently_measured"),
150: ("original_declared_perf_budget","original_runtime_evidence_event_present","original_runtime_frame_measurement_verified"),
151: ("collision_named_meshes_present","glb_geometry_nonempty","original_runtime_collision_proven"),
152: ("collision_named_meshes_present","original_mesh_primitive_count","original_runtime_collision_proven"),
153: ("collision_named_meshes_present","triangle_count_from_original_indices","optimization_benefit_independently_measured"),
154: ("player_view_source_png","registered_native_ybn","collision_stability_independently_proven"),
155: ("registered_native_ybn","original_runtime_collision_walk_record","original_runtime_collision_proven"),
156: ("registered_native_ybn","original_runtime_collision_walk_record","collision_stability_independently_proven"),
157: ("player_view_source_png","original_runtime_collision_walk_record","true_fivem_runtime_playback_verified"),
158: ("glb_geometry_nonempty","registered_native_ybn","original_runtime_collision_proven"),
159: ("original_fivem_manifest_bytes_present","original_runtime_collision_walk_record","true_fivem_runtime_playback_verified"),
160: ("registered_native_ybn","original_runtime_evidence_event_present","true_fivem_runtime_playback_verified"),
161: ("original_fivem_manifest_bytes_present","registered_native_ydr","registered_native_ymap","true_fivem_runtime_playback_verified"),
162: ("registered_native_ydr","editable_source_original_verified","native_drawable_header_validated"),
163: ("registered_native_ytd","referenced_texture_count_positive","native_texture_dictionary_validated"),
164: ("registered_native_ytyp","registered_native_ydr","native_ytyp_archetypes_validated"),
165: ("registered_native_ymap","registered_native_ytyp","native_ymap_placements_validated"),
166: ("registered_native_ybn","collision_named_meshes_present","native_ybn_collision_structures_validated"),
167: ("original_sollumz_native_export_record","registered_native_ydr","native_drawable_header_validated"),
168: ("material_alpha_structural_observation","pbr_structurally_valid","native_drawable_header_validated"),
169: ("original_codewalker_qa_record","registered_native_ymap","original_runtime_streaming_record","true_fivem_runtime_playback_verified"),
170: ("original_runtime_evidence_event_present","original_runtime_collision_walk_record","original_runtime_streaming_record","true_fivem_runtime_playback_verified"),
}
def inspect(inv, plan, controller, asset, step, work, *, source_loader):
    need(callable(source_loader), "M121_Q170_ORIGINAL_READBACK_REQUIRED")
    literal_sources(inv)
    records, audit_tail, state, audit_hash = _original_attempt(
        inv, plan, controller, asset, step, work)
    need(sha(controller.master.read_bytes()) ==
         inv["canonical_master_sha256"] == work["master_sha256"] and
         state.get("last_audit_hash") == audit_tail and
         (state.get("active_step") or {}).get("step") == step,
         "M121_Q170_ORIGINAL_MASTER_AUDIT_STATE_DRIFT")
    artifact_rows = _registered_artifacts(records,state,step,source_loader,work)
    features, report, shots = original_features(
        records,artifact_rows,plan,state,step,work)
    need(set(RULE_PREDICATES) == set(CLAUSES) and len(RULE_PREDICATES) == 50,
         "M121_Q170_SOURCE_RULE_COVERAGE_INCOMPLETE")
    result = {}
    condition_count = 0
    observed_count = 0
    for n, requirement in CLAUSES.items():
        rid = IDS[n-121]
        keys = RULE_PREDICATES[n]
        need(len(keys) >= 3 and len(set(keys)) == len(keys) and
             all(k in features for k in keys),
             "M121_Q170_MISSING_SPECIFIC_EVIDENCE:" + rid)
        observations = {k: features[k] for k in keys}
        condition_count += len(keys)
        observed_count += sum(observations.values())
        row = inv["rules"][rid]
        result[rid] = {
            "rule_id": rid, "canonical_requirement": requirement,
            "canonical_source_sha256": row["source_sha256"],
            "requirement_sha256": row["requirement_sha256"],
            "original_native_predicates": observations,
            "observed": sorted(k for k,v in observations.items() if v),
            "missing": sorted(k for k,v in observations.items() if not v),
            "bounded_native_observation": (
                "SOURCE_SUBCONDITIONS_OBSERVED" if all(observations.values())
                else "UNKNOWN_INCOMPLETE"),
            "full_rule_semantics": "UNKNOWN",
            "individual_mg0": "UNKNOWN",
            "owner_approval": "UNKNOWN",
            "advancement_authorized": False,
        }
    return {
        "schema": SCHEMA, "asset": asset, "step": step,
        "attempt_id": work["attempt_id"],
        "operation_sha256": work["operation_sha256"],
        "original_audit_sha256": audit_hash,
        "original_audit_tail": audit_tail,
        "native_glb_sha256": report["source_sha256"] if report else None,
        "source_rules_examined": 50,
        "native_predicates_evaluated": condition_count,
        "native_predicates_observed": observed_count,
        "individual_mg0_passes": 0, "full_rule_passes": 0,
        "advancement_authorized": False, "rules": result,
    }

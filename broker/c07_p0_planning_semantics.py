"""C07 P0: nine original B-011/B-013..020 planning semantic oracles.

Each source rule has its own executable content predicate over registered
original JSON and/or independently reopened plan dependencies. No generic YES,
fingerprint, QA event or green CI can substitute for a rule's requirements.
These observations do not prove design suitability, owner authority, MG0,
production readiness, or a complete rule PASS.
"""
import hashlib
import json
import math
import re
from pathlib import Path

from c07_positive_native_process import _original_attempt, _registered_artifacts
from r173_rule_semantics import RULES as CANONICAL_TEXT

NUMBERS = (11, 13, 14, 15, 16, 17, 18, 19, 20)
IDS = tuple("AAA-200-B-%03d" % n for n in NUMBERS)
ROLE_BY_NUMBER = {
    11: "P0_PROJECT_BRIEF",
    13: "P0_FORMAT_COORDS",
    14: "P0_REUSE_INVENTORY",
    15: "P0_LOCK_MATRIX",
    16: "P0_DEPENDENCY_GRAPH",
    17: "P0_DELIVERABLES",
    18: "P0_RISK_REGISTER",
    19: "P0_ESTIMATE",
    20: "P0_ACCEPTANCE",
}
SCHEMA = "gg-c07-p0-nine-original-planning-oracles-v1"
MEASUREMENT_ROLE = "P0_MEASUREMENTS"
HEX = re.compile(r"[a-f0-9]{64}\Z")

class OriginalPlanningBlocked(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise OriginalPlanningBlocked(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def text(v):
    return type(v) is str and bool(v.strip()) and len(v) <= 1000

def items(v):
    return type(v) is list and bool(v) and len(v) <= 1000

def finite(v):
    return type(v) in (int, float) and math.isfinite(v)

def original_json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 1_000_000,
         "C07_P0_ORIGINAL_DOCUMENT_BYTES")
    def pairs(rows):
        d = {}
        for k, v in rows:
            need(k not in d, "C07_P0_DUPLICATE_JSON_KEY")
            d[k] = v
        return d
    def invalid_constant(value):
        raise OriginalPlanningBlocked("C07_P0_NONFINITE_JSON")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=invalid_constant)
    need(type(value) is dict, "C07_P0_ORIGINAL_DOCUMENT_OBJECT")
    return value

def _no_cycle(nodes, edges):
    """Bounded iterative DAG check: no recursion-limit bypass or stack crash."""
    if type(nodes) is not list or len(set(nodes)) != len(nodes):
        return False
    indegree = {n: 0 for n in nodes}
    forward = {n: [] for n in nodes}
    for edge in edges:
        if (type(edge) is not list or len(edge) != 2 or
                type(edge[0]) is not str or type(edge[1]) is not str or
                edge[0] not in forward or edge[1] not in forward):
            return False
        forward[edge[0]].append(edge[1])
        indegree[edge[1]] += 1
    ready = [n for n in nodes if indegree[n] == 0]
    visited = 0
    while ready:
        node = ready.pop()
        visited += 1
        for target in forward[node]:
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    return visited == len(nodes)

def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    need(type(inventory) is dict and inventory.get("rule_count") == 763 and
         type(plan) is dict and type(work) is dict and
         plan.get("phase") in ("P0", "P1", "P2", "P3", "P4", "P5",
                               "P6", "P7", "P8") and
         work.get("phase") == plan["phase"] and callable(source_loader),
         "C07_P0_TRUSTED_WORK_CONTEXT")
    catalog = inventory.get("source_digests", {}).get("aaa_catalog")
    need(type(catalog) is str and HEX.fullmatch(catalog),
         "C07_P0_CANONICAL_CATALOG_SOURCE")
    for n, rid in zip(NUMBERS, IDS):
        row = inventory["rules"].get(rid, {})
        expected = CANONICAL_TEXT[rid][1]
        need(row.get("family") == "AAA-200" and
             row.get("catalog_number") == n and
             row.get("catalog_section") == "B" and
             row.get("catalog_phase") == "P0" and
             row.get("requirement") == expected and
             row.get("requirement_sha256") == sha(expected.encode()) and
             row.get("source_sha256") == catalog,
             "C07_P0_ORIGINAL_LITERAL_CHANGED:" + rid)
    records, tail, state, audit_sha = _original_attempt(
        inventory, plan, controller, asset, step, work)
    need(state.get("last_audit_hash") == tail and
         sha(controller.master.read_bytes()) == work["master_sha256"] and
         (state.get("active_step") or {}).get("step") == step,
         "C07_P0_ORIGINAL_CONTROLLER_DRIFT")
    original = _registered_artifacts(records, state, step, source_loader, work)
    docs = {}
    for role, path, digest, raw in original:
        if role in set(ROLE_BY_NUMBER.values()) | {MEASUREMENT_ROLE}:
            need(role not in docs and Path(path).suffix.lower() == ".json",
                 "C07_P0_DUPLICATE_OR_NONJSON_ROLE:" + role)
            docs[role] = original_json(raw)
    # Reopen ORIGINAL dependencies, not a producer's claim of their hashes.
    dep_paths = plan.get("dependency_files", {})
    dep_hashes = work.get("work_dependencies", {})
    need(type(dep_paths) is dict and type(dep_hashes) is dict and
         set(dep_paths) == set(dep_hashes),
         "C07_P0_ORIGINAL_DEPENDENCY_SET")
    verified_deps = {}
    for key, path in dep_paths.items():
        need(type(key) is str and HEX.fullmatch(key) and
             type(path) is str and bool(path),
             "C07_P0_DEPENDENCY_PATH_OR_ID")
        relative = Path(path)
        root = controller.root.resolve()
        full = root / relative
        need(not relative.is_absolute() and ".." not in relative.parts and
             str(relative) == path and
             full.resolve().is_relative_to(root) and full.is_file() and
             not any(part.is_symlink() for part in
                     (full, *list(full.parents)[:len(relative.parts)])),
             "C07_P0_DEPENDENCY_PATH_NOT_ORIGINAL:" + key)
        raw = full.read_bytes()
        need(type(raw) is bytes and sha(raw) == dep_hashes[key],
             "C07_P0_DEPENDENCY_BYTES_CHANGED:" + key)
        verified_deps[key] = dep_hashes[key]

    def doc(n):
        return docs.get(ROLE_BY_NUMBER[n], {})

    brief = doc(11)
    coords = doc(13)
    reuse = doc(14)
    locks = doc(15)
    graph = doc(16)
    delivery = doc(17)
    risks = doc(18)
    estimate = doc(19)
    measurements = docs.get(MEASUREMENT_ROLE, {}).get("measurements", {})
    acceptance = doc(20)
    candidates = reuse.get("candidates")
    approved = locks.get("approved")
    mutable = locks.get("mutable")
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    outputs = delivery.get("deliverables")
    risk_rows = risks.get("risks")
    tasks = estimate.get("tasks")
    criteria = acceptance.get("criteria")

    checked = {
        11: {
            "original_asset_purpose_matches_work": brief.get("asset") == asset
                and text(brief.get("purpose")),
            "intended_game_use_and_output_named": text(brief.get("intended_use"))
                and items(brief.get("deliverables"))
                and all(text(x) for x in brief.get("deliverables", [])),
        },
        13: {
            "target_engine_and_native_format_explicit":
                coords.get("engine") == "GTA_V_FIVEM" and
                coords.get("export_format") in ("GLB", "YDR", "YMAP", "YTYP"),
            "actual_scale_units_world_origin_finite":
                finite(coords.get("meters_per_unit")) and
                0 < coords["meters_per_unit"] <= 100 and
                type(coords.get("world_origin_xyz")) is list and
                len(coords["world_origin_xyz"]) == 3 and
                all(finite(x) for x in coords["world_origin_xyz"]),
        },
        14: {
            "original_reuse_inventory_lists_real_candidates":
                items(candidates) and all(
                    type(x) is dict and text(x.get("name")) and
                    x.get("decision") in ("REUSE", "REBUILD", "LOCKED")
                    for x in candidates or []),
            "all_candidate_sources_independently_reopened":
                items(candidates) and all(
                    type(x) is dict and
                    x.get("dependency_id") in verified_deps and
                    x.get("sha256") == verified_deps.get(x.get("dependency_id"))
                    for x in candidates or []),
        },
        15: {
            "approved_and_mutable_names_are_disjoint":
                items(approved) and items(mutable) and
                all(text(x) for x in approved + mutable) and
                len(set(approved)) == len(approved) and
                len(set(mutable)) == len(mutable) and
                not set(approved) & set(mutable),
            "approved_original_source_sha_pinned":
                items(approved) and
                type(locks.get("approved_dependencies")) is dict and
                set(locks["approved_dependencies"]) == set(approved) and
                all(v in verified_deps for v in
                    locks["approved_dependencies"].values()),
        },
        16: {
            "original_dependency_nodes_are_verified":
                items(nodes) and all(type(n) is str and n in verified_deps
                                     for n in nodes) and
                len(set(nodes)) == len(nodes),
            "original_dependency_edges_refer_to_nodes_and_are_acyclic":
                items(nodes) and type(edges) is list and
                _no_cycle(nodes, edges),
        },
        17: {
            "original_deliverables_distinct_from_studies":
                items(outputs) and all(
                    type(o) is dict and text(o.get("path")) and
                    o.get("kind") in ("SOURCE", "NATIVE_EXPORT", "DELIVERY")
                    for o in outputs or []) and
                len({o["path"] for o in outputs or []}) == len(outputs or []),
            "delivery_plan_names_original_source_and_export":
                items(outputs) and
                {"SOURCE", "NATIVE_EXPORT"} <= {
                    o.get("kind") for o in outputs or []
                    if type(o) is dict},
        },
        18: {
            "real_original_risks_have_triggers_and_mitigations":
                items(risk_rows) and all(
                    type(x) is dict and text(x.get("id")) and
                    text(x.get("trigger")) and text(x.get("mitigation"))
                    for x in risk_rows or []),
            "risk_severity_is_explicit_and_unique":
                items(risk_rows) and
                len({x.get("id") for x in risk_rows or []
                     if type(x) is dict}) == len(risk_rows or []) and
                all(type(x) is dict and
                    x.get("severity") in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
                    for x in risk_rows or []),
        },
        19: {
            "time_estimate_uses_measured_task_hours":
                items(tasks) and type(measurements) is dict and
                MEASUREMENT_ROLE in docs and all(
                    type(x) is dict and text(x.get("task")) and
                    text(x.get("measurement_key")) and
                    finite(measurements.get(x.get("measurement_key"))) and
                    measurements[x["measurement_key"]] > 0 and
                    finite(x.get("hours_per_unit")) and
                    x["hours_per_unit"] > 0 and
                    finite(x.get("estimated_hours")) and
                    0 < x["estimated_hours"] <= 10000 and
                    abs(x["estimated_hours"] -
                        measurements[x["measurement_key"]] *
                        x["hours_per_unit"]) < 1e-6 and
                    text(x.get("evidence_basis"))
                    for x in tasks or []),
            "estimate_total_independently_recomputed":
                items(tasks) and type(measurements) is dict and
                MEASUREMENT_ROLE in docs and
                all(type(x) is dict and
                    x.get("measurement_key") in measurements and
                    finite(x.get("hours_per_unit")) and
                    finite(measurements[x["measurement_key"]])
                    for x in tasks or []) and
                finite(estimate.get("total_hours")) and
                abs(sum(measurements[x["measurement_key"]] *
                        x["hours_per_unit"] for x in tasks or [])
                    - estimate["total_hours"]) < 1e-6,
        },
        20: {
            "objective_measurable_criteria_present":
                items(criteria) and all(
                    type(x) is dict and text(x.get("id")) and
                    text(x.get("metric")) and
                    x.get("operator") in ("<", "<=", "=", ">=", ">") and
                    finite(x.get("threshold"))
                    for x in criteria or []),
            "every_criterion_names_independent_measurement_source":
                items(criteria) and
                len({x.get("id") for x in criteria or []
                     if type(x) is dict}) == len(criteria or []) and
                all(type(x) is dict and
                    text(x.get("measurement_source")) and
                    type(x.get("measurement_source_sha256")) is str and
                    x["measurement_source_sha256"] in verified_deps.values()
                    for x in criteria or []),
        },
    }
    need(len(checked) == 9 and
         all(type(v) is dict and len(v) == 2 for v in checked.values()),
         "C07_P0_NINE_DISTINCT_ORACLES_REQUIRED")
    result = {}
    for n, checks in checked.items():
        rid = "AAA-200-B-%03d" % n
        need(all(type(v) is bool for v in checks.values()),
             "C07_P0_ORACLE_RESULT_NOT_BOOLEAN:" + rid)
        result[rid] = {
            "requirement_sha256": inventory["rules"][rid]["requirement_sha256"],
            "source_sha256": inventory["rules"][rid]["source_sha256"],
            "original_role": ROLE_BY_NUMBER[n],
            "source_bytes_reopened": ROLE_BY_NUMBER[n] in docs,
            "original_machine_checks": checks,
            "machine_scope": ("OBSERVED_SCOPE_PASS" if all(checks.values())
                              else "UNKNOWN"),
            "full_rule_semantics": "UNKNOWN", "individual_mg0": "UNKNOWN",
            "owner_approval": "UNKNOWN", "advancement_authorized": False,
        }
    return {
        "schema": SCHEMA, "source_rule_count": 9,
        "original_registered_planning_documents": sorted(docs),
        "original_dependency_bytes_verified": len(verified_deps),
        "rules": result,
        "machine_positive_obligations": sum(
            v["machine_scope"] == "OBSERVED_SCOPE_PASS" for v in result.values()),
        "original_audit_sha256": audit_sha, "original_audit_tail": tail,
        "attempt_id": work["attempt_id"],
        "operation_sha256": work["operation_sha256"],
        "full_rule_semantic_passes": 0, "individual_mg0_passes": 0,
        "advancement_authorized": False,
    }

"""C07 P8 T-195..200: six original-source closure/QA process oracles.

Original registered bytes and pre-D contracts are compared against Controller
audit. A QA row, a method-change document, or an owner-labelled JSON cannot
independently prove a game test, root-cause correction, MG0 or acceptance.
Therefore these remain scoped observations; T-200 cannot auto-pass.
"""
import hashlib
import re
from pathlib import PurePosixPath

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p5_budget_semantics import _json
from c07_p3_geometry_semantics import geometry
from c07_p678_forty_native_domain import TEXT, PHASES

NUMBERS = tuple(range(195, 201))
IDS = tuple("AAA-200-T-%03d" % n for n in NUMBERS)
SCHEMA = "gg-c07-p8-six-original-closure-oracles-v1"
HEX = re.compile(r"[a-f0-9]{64}\Z")

class OriginalClosureBlocked(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise OriginalClosureBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def named(x):
    return type(x) is str and bool(x.strip()) and len(x) <= 300

def names(x):
    return (type(x) is list and bool(x) and len(x) <= 128
            and all(named(v) for v in x) and len(set(x)) == len(x))

def safe_path(name):
    if not named(name) or "\\" in name or name.startswith("/"):
        return False
    path = PurePosixPath(name)
    return ".." not in path.parts and str(path) == name

def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    need(type(inventory) is dict and inventory.get("rule_count") == 763
         and inventory.get("schema") == "gg-effective-family-inventory-v1"
         and type(plan) is dict and type(work) is dict
         and plan.get("phase") in PHASES and PHASES[plan["phase"]] >= 8
         and work.get("phase") == plan["phase"]
         and callable(source_loader), "C07_P8_CLOSURE_CONTEXT")
    catalog = inventory.get("source_digests", {}).get("aaa_catalog")
    need(type(catalog) is str and HEX.fullmatch(catalog),
         "C07_P8_CLOSURE_CATALOG")
    for n, rid in zip(NUMBERS, IDS):
        literal, phase = TEXT[str(n)]
        row = inventory["rules"].get(rid, {})
        need(phase == "P8" and row.get("family") == "AAA-200"
             and row.get("catalog_number") == n
             and row.get("catalog_section") == "T"
             and row.get("catalog_phase") == phase
             and row.get("requirement") == literal
             and row.get("requirement_sha256") == sha(literal.encode())
             and row.get("source_sha256") == catalog,
             "C07_P8_CLOSURE_LITERAL_CHANGED:" + rid)
    audit, tail, state, audit_sha = _original_attempt(
        inventory, plan, controller, asset, step, work)
    need(state.get("last_audit_hash") == tail
         and sha(controller.master.read_bytes()) == work["master_sha256"]
         and (state.get("active_step") or {}).get("step") == step,
         "C07_P8_CLOSURE_AUDIT_DRIFT")
    artifacts = _registered_artifacts(
        audit, state, step, source_loader, work)
    found = {}
    for role, path, digest, raw in artifacts:
        need(role not in found, "C07_P8_DUPLICATE_ORIGINAL_ROLE:" + role)
        found[role] = (path, digest, raw)
    contract = plan.get("p678_evidence_contract", {})
    pins = contract.get("original_artifact_sha256", {}) if type(contract) is dict else {}
    if type(pins) is not dict:
        pins = {}
    def original(role, ext=None):
        row = found.get(role)
        if row is None or (ext is not None and
                           not row[0].lower().endswith(ext)):
            return None
        return row[2] if pins.get(role) == row[1] and sha(row[2]) == row[1] else None
    def json_role(role):
        raw = original(role, ".json")
        return _json(raw) if raw is not None else {}

    guide = json_role("P8_MAINTENANCE_GUIDE")
    tests = json_role("P8_TEST_MATRIX")
    history = json_role("P8_DEFECT_HISTORY")
    method = json_role("P8_METHOD_CHANGE")
    source = original("SOURCE_EDITABLE", ".blend")
    export = original("NATIVE_EXPORT", ".glb")
    before = original("BASELINE_SNAPSHOT", ".glb")
    method_before = original("P8_METHOD_BEFORE", ".py")
    method_after = original("P8_METHOD_AFTER", ".py")

    guide_bindings = bool(
        guide.get("asset") == asset and source and export
        and guide.get("source_sha256") == sha(source)
        and guide.get("export_sha256") == sha(export))
    install_paths = guide.get("install_paths")
    guide_steps = guide.get("maintenance_steps")
    guide_content = bool(
        type(install_paths) is list and bool(install_paths)
        and len(install_paths) <= 100 and
        all(safe_path(x) for x in install_paths)
        and names(guide_steps))
    rows = tests.get("tests")
    rows_ok = (type(rows) is list and 2 <= len(rows) <= 100
               and all(type(row) is dict and named(row.get("id"))
                       and row.get("status") in ("RUN", "NOT_RUN")
                       for row in rows))
    if rows_ok:
        rows_ok = len({row["id"] for row in rows}) == len(rows)
    observed = [row for row in rows if row.get("status") == "RUN"] if rows_ok else []
    omitted = [row for row in rows if row.get("status") == "NOT_RUN"] if rows_ok else []
    disclosure = bool(rows_ok and observed and omitted and
                      all(row.get("evidence_role") is None
                          and row.get("evidence_sha256") is None
                          for row in omitted))
    observed_bound = bool(
        disclosure and all(
            named(row.get("evidence_role"))
            and row["evidence_role"] not in (
                "P8_TEST_MATRIX", "P8_MAINTENANCE_GUIDE")
            and original(row["evidence_role"]) is not None
            and row.get("evidence_sha256") ==
                sha(original(row["evidence_role"]))
            for row in observed))
    # Replay the *declared* SOURCE_BYTES test from the independently reopened
    # original editable and GLB bytes. Other RUN labels have no reviewed
    # executor here: they cannot be silently accepted as performed tests.
    try:
        source_bytes_decoded = bool(source and export and
            source.startswith(b"BLENDER") and len(source) >= 12 and
            geometry(export))
    except (ValueError, KeyError, TypeError, IndexError):
        source_bytes_decoded = False
    declared_runs_replayed = bool(
        observed_bound and guide_bindings and source_bytes_decoded and
        all(row["id"] == "SOURCE_BYTES"
            and row["evidence_role"] == "NATIVE_EXPORT"
            and row["evidence_sha256"] == sha(export)
            for row in observed))
    candidate_only = (guide.get("status") == "CANDIDATE"
                      and guide.get("owner_approved") is False
                      and state.get("delivery_status") != "DELIVERABLE")
    issues = history.get("issues")
    issues_ok = (type(issues) is list and 2 <= len(issues) <= 100
                 and all(type(row) is dict and named(row.get("id"))
                         and named(row.get("root_cause"))
                         and named(row.get("corrective_action"))
                         and type(row.get("before_sha256")) is str
                         and type(row.get("after_sha256")) is str
                         and HEX.fullmatch(row["before_sha256"])
                         and HEX.fullmatch(row["after_sha256"])
                         for row in issues))
    if issues_ok:
        issues_ok = len({row["id"] for row in issues}) == len(issues)
    recurring = bool(issues_ok and
                     len({row["root_cause"] for row in issues}) < len(issues))
    before_after = bool(
        recurring and before and export and sha(before) != sha(export)
        and all(row["before_sha256"] == sha(before)
                and row["after_sha256"] == sha(export)
                for row in issues))
    changed_scripts = bool(
        method_before and method_after and sha(method_before) != sha(method_after)
        and method.get("before_sha256") == sha(method_before)
        and method.get("after_sha256") == sha(method_after))
    method_targets_cause = bool(
        changed_scripts and recurring and
        method.get("root_cause") in {row["root_cause"] for row in issues}
        and named(method.get("verification_method")))
    # A JSON record cannot attest an actual FiveM run, independent MG0,
    # owner identity, complete artistic QA or final contractual acceptance.
    checks = {
        195: {
            "original_guide_binds_actual_source_and_export_bytes": guide_bindings,
            "original_install_paths_and_maintenance_steps_explicit": guide_content,
        },
        196: {
            "original_test_matrix_explicitly_separates_run_and_not_run": disclosure,
            "every_reported_run_references_registered_original_evidence":
                observed_bound,
            "declared_source_byte_test_replayed_from_originals":
                declared_runs_replayed,
        },
        197: {
            "original_candidate_not_self_labelled_approved": candidate_only,
            "source_bound_candidate_and_export_exist": guide_bindings,
        },
        198: {
            "original_history_identifies_repeated_named_root_causes": recurring,
            "before_after_original_binary_sha_differences_measured": before_after,
        },
        199: {
            "original_before_after_method_script_bytes_differ": changed_scripts,
            "recorded_method_change_targets_named_recurrent_cause":
                method_targets_cause,
        },
        200: {
            "source_and_export_bytes_reopened_in_current_attempt":
                bool(source and export),
            "independent_full_acceptance_mg0_and_fivem_proven": False,
        },
    }
    rules = {}
    for n, rid in zip(NUMBERS, IDS):
        measured = {k: bool(v) for k,v in checks[n].items()}
        rules[rid] = {
            "requirement_sha256": inventory["rules"][rid]["requirement_sha256"],
            "source_sha256": catalog,
            "exact_attempt_id": work["attempt_id"],
            "operation_sha256": work["operation_sha256"],
            "original_machine_checks": measured,
            "machine_scope": "OBSERVED_SCOPE_PASS" if all(measured.values())
                             else "UNKNOWN_OR_DEFECT",
            "full_rule_semantics": "UNKNOWN", "individual_mg0": "UNKNOWN",
            "owner_acceptance": "UNKNOWN", "advancement_authorized": False,
        }
    return {
        "schema": SCHEMA, "source_rule_count": len(IDS), "rules": rules,
        "original_audit_sha256": audit_sha, "original_audit_tail": tail,
        "attempt_id": work["attempt_id"], "operation_sha256": work["operation_sha256"],
        "metrics": {
            "guide_bound": guide_bindings,
            "run_rows": len(observed), "not_run_rows": len(omitted),
            "recurrent_issues": len(issues) if recurring else 0,
            "before_after_bytes_changed": before_after,
            "method_script_bytes_changed": changed_scripts,
            "final_acceptance_unattested": True,
        },
        "machine_positive_obligations": sum(
            v["machine_scope"] == "OBSERVED_SCOPE_PASS" for v in rules.values()),
        "full_rule_semantic_passes": 0, "individual_mg0_passes": 0,
        "advancement_authorized": False,
    }

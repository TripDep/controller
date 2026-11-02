"""C07 P0: ten literal original-source process rules, R-171..R-180.

Unlike the earlier word-only trigger list, each condition below is computed
from authenticated Controller audit, original artifact bytes or the existing
independently replayed R-172/R-178 native verifiers. A machine observation is
never owner acceptance, MG0 certification, FiveM PASS or work authorization.
"""
import hashlib
import re
from pathlib import Path

from c07_positive_native_process import (
    _original_attempt, _registered_artifacts, inspect as native_process, sha,
)

SCHEMA = "gg-c07-r171-r180-original-process-semantics-v1"
CATALOG_SHA = "f9e7e0d11398c26095f5b3a83a2cf1e8a14ea459bc47dc09c4dfad891664fcf9"
CLAUSES = {
    171: "Organizzare i sorgenti con nomi e strutture coerenti.",
    172: "Distinguere sorgenti modificabili, esportazioni e consegne.",
    173: "Utilizzare il controllo versione per proteggere il lavoro.",
    174: "Conservare copie verificabili degli asset approvati.",
    175: "Automatizzare verifiche ripetitive quando il beneficio è concreto.",
    176: "Verificare che gli script producano il risultato atteso, non soltanto che terminino senza errori.",
    177: "Evitare che una procedura automatica sovrascriva asset approvati.",
    178: "Registrare dipendenze e stato reale delle attività.",
    179: "Riprendere da un checkpoint valido dopo un’interruzione, senza duplicare lavoro.",
    180: "Misurare il progresso tramite produzione effettiva, non tramite quantità di registrazioni o documenti.",
}
IDS = tuple("AAA-200-R-%03d" % n for n in CLAUSES)

class Process10Blocked(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Process10Blocked(reason)

def exact_canon(inventory):
    need(type(inventory) is dict and
         inventory.get("schema") == "gg-effective-family-inventory-v1" and
         inventory.get("rule_count") == 763 and
         inventory.get("source_digests", {}).get("aaa_catalog") == CATALOG_SHA,
         "R171_180_CANONICAL_763_AND_SOURCE_REQUIRED")
    for n, clause in CLAUSES.items():
        rid = "AAA-200-R-%03d" % n
        row = inventory["rules"].get(rid, {})
        need(row.get("family") == "AAA-200" and
             row.get("catalog_number") == n and
             row.get("catalog_section") == "R" and
             row.get("catalog_phase") == "P0" and
             row.get("requirement") == clause and
             row.get("source_sha256") == CATALOG_SHA and
             row.get("requirement_sha256") == sha(clause.encode("utf-8")),
             "R171_180_LITERAL_SOURCE_CHANGED:" + rid)

def _artifact_map(artifacts):
    # All artifact bytes have already been verified by _registered_artifacts.
    by_role = {}
    paths = set()
    for role, path, digest, raw in artifacts:
        need(type(role) is str and role and type(path) is str and path not in paths,
             "R171_180_DUPLICATE_OR_MISSING_ARTIFACT_ROLE")
        paths.add(path)
        by_role.setdefault(role, []).append((Path(path), digest, raw))
    return by_role

def _one(by_role, role):
    values = by_role.get(role, ())
    return values[0] if len(values) == 1 else None

def _event(rows, name, work, step):
    return [r for r in rows if r.get("event") == name and
            r.get("step") == step and
            r.get("attempt_id") == work["attempt_id"] and
            r.get("operation_sha256") == work["operation_sha256"]]

def evidence_checks(inventory, plan, records, state, artifacts, work, step,
                    native):
    """Ten independent per-clause observations; no producer-selected PASS map."""
    by_role = _artifact_map(artifacts)
    editable = _one(by_role, "SOURCE_EDITABLE")
    exported = _one(by_role, "NATIVE_EXPORT")
    package = _one(by_role, "DELIVERY_PACKAGE")
    baseline = _one(by_role, "BASELINE_SNAPSHOT")
    # Path identity is checked separately from filename extensions.
    source_paths = [x[0] for x in by_role.get("SOURCE_EDITABLE", ())]
    source_names = [p.name for p in source_paths]
    path_names_ok = bool(source_paths) and all(
        p.is_absolute() and p.name not in (".", "..") and
        not re.search(r"[\\\n\r\t]", p.name) and p.suffix.lower()
        in (".blend", ".fbx", ".obj")
        for p in source_paths
    )
    organized = (path_names_ok and len(source_names) == len(set(source_names))
                 and all(p.parent != p for p in source_paths))
    output_differs = bool(exported and baseline and exported[1] != baseline[1])
    source_export_separate = bool(
        editable and exported and package and
        len({str(editable[0]), str(exported[0]), str(package[0])}) == 3)
    # Existing independently replayed literal source verifiers must agree.
    native_rules = native["rules"]
    base_172 = native_rules["AAA-200-R-172"]
    base_178 = native_rules["AAA-200-R-178"]
    need(native["rule_count"] == 2 and
         native["individual_mg0_passes"] == 0 and
         native["advancement_authorized"] is False and
         all(x["semantic_result"] in ("SEMANTIC_OBSERVED", "UNKNOWN")
             for x in native_rules.values()),
         "R171_180_UNTRUSTED_EXISTING_NATIVE_READBACK")

    # An audit mention of a Git commit, an APPROVED flag or an "automation"
    # event is not an independent version/owner/benefit proof. Even if these
    # are present, proof remains UNKNOWN until the underlying bytes or trusted
    # independent origin can be examined.
    version = _event(records, "SOURCE_VERSION_INDEPENDENTLY_VERIFIED", work, step)
    approvals = _event(records, "OWNER_APPROVED_ASSET_COPY_VERIFIED", work, step)
    automated = _event(records, "AUTOMATED_ORIGINAL_OUTPUT_CHECK", work, step)
    checkpoint = _event(records, "CHECKPOINT_RESTORED_AND_VERIFIED", work, step)
    native_qa = _event(records, "NATIVE_OUTPUT_INDEPENDENT_QA", work, step)
    old_approved = _event(records, "APPROVED_ORIGINAL_BYTES_RECHECKED", work, step)

    prior_outputs = {
        x.get("evidence_operation", {}).get("sha256")
        for x in records if x.get("event") == "ARTIFACT_RECORDED"
        and x.get("step") != step
        and isinstance(x.get("evidence_operation"), dict)
        and x["evidence_operation"].get("role") == "NATIVE_EXPORT"
    }
    old_steps = [x for x in records
                 if x.get("event") == "STEP_CLOSE" and
                 x.get("step") != step]
    deps = plan.get("dependency_files", {})
    deps_exact = bool(deps) and isinstance(deps, dict) and (
        set(deps) == set(work.get("work_dependencies", {}))
    )
    source_bytes_exist = bool(editable and type(editable[2]) is bytes)
    qa_bytes_exist = bool(_one(by_role, "NATIVE_REIMPORT"))
    has_new_real_export = bool(exported and exported[1] not in prior_outputs
                               and exported[0].suffix.lower() in
                               (".glb", ".gltf", ".ydr", ".yft", ".ymap"))

    checks = {
      171: {
        "registered_original_editable_bytes": source_bytes_exist,
        "editable_file_names_unique_and_structurally_valid": organized,
        "roles_not_inferred_from_document_names": bool(
            source_export_separate),
        "original_source_paths_are_distinct": len(source_paths) == len(set(source_paths)) and bool(source_paths),
      },
      172: {
        "source_export_delivery_are_distinct_original_files": source_export_separate,
        "existing_source_native_verifier_observed": base_172["semantic_result"] == "SEMANTIC_OBSERVED",
        "original_registered_roles_have_true_bytes": bool(editable and exported and package),
        "delivery_manifest_and_export_exactly_replayed": all(base_172["criteria"].values()),
      },
      173: {
        "protected_editable_original_bytes_present": source_bytes_exist,
        "original_version_audit_chain_contains_exact_attempt": bool(version),
        # Audit reports alone do not verify an actual independent Git tree.
        "independent_version_storage_readback": False,
        "baseline_before_current_change_available": bool(baseline),
      },
      174: {
        "verifiable_baseline_original_bytes_present": bool(baseline),
        "owner_approval_event_bound_to_exact_attempt": bool(approvals),
        "independent_owner_identity_verified": False,
        "approved_copy_bytes_proven_unchanged": bool(
            baseline and old_approved),
      },
      175: {
        "repeated_checks_performed_on_exact_attempt": len(automated) >= 2,
        "distinct_recorded_check_runs": len({
            r.get("record_hash") for r in automated}) >= 2,
        "original_output_not_only_exit_status": bool(exported and native_qa),
        "measured_net_benefit_independently_proven": False,
      },
      176: {
        "original_export_output_bytes_sha_verified": bool(exported),
        "current_script_result_checked_against_binary_reimport": qa_bytes_exist,
        "original_native_qa_event_recorded": bool(native_qa),
        "expected_result_oracle_independently_verified": False,
      },
      177: {
        "existing_approved_copy_reopened": bool(baseline),
        "copy_sha_does_not_equal_changed_current_output": output_differs,
        "original_approved_bytes_rechecked": bool(old_approved),
        "independent_pre_and_post_approved_copy_hashes_equal": False,
      },
      178: {
        "exact_original_operation_dependency_sources": deps_exact,
        "native_recorded_dependencies_and_state_semantics": base_178["semantic_result"] == "SEMANTIC_OBSERVED",
        "current_original_audit_state_step": state.get("active_step", {}).get("step") == step,
        "native_source_conditions_all_observed": all(base_178["criteria"].values()),
      },
      179: {
        "actual_prior_checkpoint_exists": bool(old_steps),
        "recovery_event_matches_exact_current_attempt": bool(checkpoint),
        "original_previous_and_current_operations_different": bool(
            old_steps and
            work.get("previous_attempt_id") and
            work["previous_attempt_id"] != work["attempt_id"]),
        "checkpoint_bytes_and_no_duplicate_work_independently_replayed": False,
      },
      180: {
        "current_original_model_export_exists": bool(exported),
        "registered_output_is_new_original_model_bytes": has_new_real_export,
        "real_output_differs_from_registered_original_baseline": output_differs,
        "progress_not_derived_from_document_event_count": bool(
            exported and baseline and output_differs),
      },
    }
    need(set(checks) == set(CLAUSES) and
         all(type(cs) is dict and len(cs) == 4 and
             all(type(v) is bool for v in cs.values())
             for cs in checks.values()),
         "R171_180_TEN_COMPLETE_NATIVE_PREDICATE_SETS_REQUIRED")
    return checks

def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    need(callable(source_loader), "R171_180_ORIGINAL_BYTES_READER_REQUIRED")
    exact_canon(inventory)
    records, audit_tail, state, audit_sha = _original_attempt(
        inventory, plan, controller, asset, step, work)
    need(sha(controller.master.read_bytes()) ==
         inventory["canonical_master_sha256"] == work["master_sha256"] and
         state.get("last_audit_hash") == audit_tail and
         state.get("active_step", {}).get("step") == step,
         "R171_180_ORIGINAL_CONTROLLER_AUDIT_OR_MASTER_CHANGED")
    artifacts = _registered_artifacts(records, state, step, source_loader, work)
    native = native_process(inventory, plan, controller, asset, step, work,
                            source_loader=source_loader)
    checks = evidence_checks(inventory, plan, records, state, artifacts,
                             work, step, native)
    result = {}
    for n, clause in CLAUSES.items():
        rid = "AAA-200-R-%03d" % n
        row = inventory["rules"][rid]
        cs = checks[n]
        result[rid] = {
            "rule_id": rid, "canonical_requirement": clause,
            "source_sha256": row["source_sha256"],
            "requirement_sha256": row["requirement_sha256"],
            "original_machine_criteria": cs,
            "observed_criteria": sorted(k for k,v in cs.items() if v),
            "missing_criteria": sorted(k for k,v in cs.items() if not v),
            "literal_semantics": "SCOPE_OBSERVED" if all(cs.values()) else "UNKNOWN",
            "independent_mg0": "UNKNOWN",
            "full_rule_pass": False, "advancement_authorized": False,
        }
    return {
        "schema": SCHEMA, "source_rules_examined": 10, "rule_count": 10,
        "native_conditions_evaluated": 40,
        "native_conditions_observed": sum(sum(cs.values()) for cs in checks.values()),
        "original_audit_sha256": audit_sha, "original_audit_tail": audit_tail,
        "attempt_id": work["attempt_id"], "operation_sha256": work["operation_sha256"],
        "master_sha256": work["master_sha256"],
        "individual_mg0_passes": 0, "full_rule_passes": 0,
        "advancement_authorized": False, "rules": result,
    }

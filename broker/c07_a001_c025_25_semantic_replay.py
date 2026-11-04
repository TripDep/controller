"""C07 eighth 25 — exact P0 A001–C025 original-source semantic replay.

Re-executes existing original-byte readers for A001–A010, B011–B020,
C021–C025, binds their audited outputs and all 25 independent MG0 negative
judgments to ONE immutable Controller attempt. The B/F engine reuses R140
for C21–C30; duplicate evidence is never counted as independent proof.
Machine subconditions, fixture tests and a missing MG0 PASS cannot become
a FULL semantic, licensing, quality or owner certification.
"""
import hashlib
import re
from c07_a10_c10_original_evidence import (
    SCHEMA as AC_SCHEMA, TEXT as AC_TEXT, inspect as inspect_ac)
from c07_b011_f060_fifty_native import (
    SCHEMA as BF_SCHEMA, inspect as inspect_bf)
from c07_bf50_canonical import CLAUSES, CATALOG_SHA
from c07_bf50_predicates import SPEC
from c07_mg0_individual import inspect_batch as inspect_mg0

SCHEMA = "gg-c07-a001-c025-original-semantic25-v1"
IDS = tuple("AAA-200-%s-%03d" % (
    "A" if n <= 10 else "B" if n <= 20 else "C", n)
    for n in range(1, 26))
PHASES = ("P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class A001C025Blocked(ValueError):
    pass


def need(value, reason):
    if not value:
        raise A001C025Blocked(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(inv):
    need(type(inv) is dict and
         inv.get("schema") == "gg-effective-family-inventory-v1" and
         inv.get("rule_count") == 763 and
         inv.get("source_digests", {}).get("aaa_catalog") == CATALOG_SHA and
         len(IDS) == len(set(IDS)) == 25,
         "C07_A001_C025_EXACT_25_ORIGINAL_CATALOG_REQUIRED")
    for n, rid in enumerate(IDS, 1):
        sec = "A" if n <= 10 else "B" if n <= 20 else "C"
        source = AC_TEXT[n] if n <= 10 or n >= 21 else CLAUSES[n][1]
        if n >= 11:
            need(CLAUSES[n] == (sec, source, "P0", "all") and
                 len(SPEC[n]) == len(set(SPEC[n])) == 4,
                 "C07_A001_C025_EXACT_ORIGINAL_BF_SOURCE_CHANGED:" + rid)
        row = inv.get("rules", {}).get(rid, {})
        need(row.get("family") == "AAA-200" and
             row.get("catalog_number") == n and
             row.get("catalog_section") == sec and
             row.get("catalog_phase") == "P0" and
             row.get("asset_type") == "all" and
             row.get("source_sha256") == CATALOG_SHA and
             row.get("requirement") == source and
             row.get("requirement_sha256") == sha(source.encode("utf-8")),
             "C07_A001_C025_ORIGINAL_REQUIREMENT_CHANGED:" + rid)


def inspect(context):
    need(type(context) is dict and set(context) == {
         "inventory", "plan", "controller", "asset", "step", "work",
         "source_loader"} and callable(context["source_loader"]),
         "C07_A001_C025_ORIGINAL_SOURCE_CONTEXT_REQUIRED")
    inv, plan, ctrl = context["inventory"], context["plan"], context["controller"]
    asset, step, work = context["asset"], context["step"], context["work"]
    canonical(inv)
    need(type(plan) is dict and type(work) is dict and
         plan.get("phase") == work.get("phase") and
         work.get("phase") in PHASES and
         plan.get("master_sha256") == work.get("master_sha256") ==
            inv.get("canonical_master_sha256") and
         type(work.get("attempt_id")) is str and
         HEX64.fullmatch(work["attempt_id"]) and
         type(work.get("operation_sha256")) is str and
         HEX64.fullmatch(work["operation_sha256"]),
         "C07_A001_C025_ACTIVE_OPERATION_PHASE_REQUIRED")
    master = ctrl.master.read_bytes()
    need(type(master) is bytes and sha(master) == work["master_sha256"],
         "C07_A001_C025_MASTER_READBACK_CHANGED")
    args = (inv, plan, ctrl, asset, step, work)
    kw = {"source_loader": context["source_loader"]}
    ac = inspect_ac(*args, **kw)
    bf = inspect_bf(*args, **kw)
    audit = ctrl.audit_path(asset).read_bytes()
    need(type(audit) is bytes, "C07_A001_C025_ORIGINAL_AUDIT_MISSING")
    mg0 = inspect_mg0(master, audit, asset, work["master_sha256"],
                      list(IDS), work["attempt_id"])
    need(ac.get("schema") == AC_SCHEMA and bf.get("schema") == BF_SCHEMA and
         ac.get("source_rules_examined") == 20 and
         bf.get("source_rules_examined") == 50 and
         ac.get("native_conditions_evaluated") == 60 and
         bf.get("native_conditions_evaluated") == 200 and
         ac.get("full_rule_passes") == bf.get("full_rule_passes") == 0 and
         ac.get("individual_mg0_passes") ==
            bf.get("individual_mg0_passes") == 0 and
         ac.get("advancement_authorized") is False and
         bf.get("advancement_authorized") is False and
         ac.get("original_audit_sha256") ==
            bf.get("original_audit_sha256") ==
            mg0.get("audit_sha256") == sha(audit) and
         ac.get("original_audit_tail") ==
            bf.get("original_audit_tail") == mg0.get("audit_tail_sha256") and
         ac.get("attempt_id") ==
            bf.get("attempt_id") == mg0.get("attempt_id") ==
            work["attempt_id"] and
         ac.get("operation_sha256") ==
            bf.get("operation_sha256") == work["operation_sha256"] and
         mg0.get("rule_count") == 25 and
         set(mg0.get("rules", {})) == set(IDS) and
         mg0.get("counts", {}).get("PASS") == 0 and
         mg0.get("individual_mg0_passes") == 0 and
         mg0.get("advancement_authorized") is False,
         "C07_A001_C025_ORIGINAL_SOURCE_AND_MG0_REPLAY_DIVERGED")

    results = {}
    machine_checks = machine_observed = negative_failures = 0
    for n, rid in enumerate(IDS, 1):
        original = inv["rules"][rid]
        ac_row = ac.get("rules", {}).get(rid) if n <= 10 or n >= 21 else None
        bf_row = bf.get("rules", {}).get(rid) if n >= 11 else None
        checks = {}
        if ac_row is not None:
            need(type(ac_row) is dict and
                 ac_row.get("requirement_sha256") ==
                    original["requirement_sha256"] and
                 ac_row.get("full_rule_pass") is False and
                 ac_row.get("individual_mg0") == "UNKNOWN" and
                 ac_row.get("owner_approval") == "UNKNOWN" and
                 ac_row.get("advancement_authorized") is False,
                 "C07_A001_C025_REFERENCE_NATIVE_CHANGED:" + rid)
            source_checks = ac_row.get("native_original_file_criteria")
            need(type(source_checks) is dict and len(source_checks) == 3 and
                 all(type(v) is bool for v in source_checks.values()),
                 "C07_A001_C025_THREE_ORIGINAL_REFERENCE_CHECKS:" + rid)
            checks.update({"reference:" + k: v for k, v in source_checks.items()})
        if bf_row is not None:
            need(type(bf_row) is dict and bf_row.get("rule_id") == rid and
                 bf_row.get("source_sha256") == original["source_sha256"] and
                 bf_row.get("requirement_sha256") ==
                    original["requirement_sha256"] and
                 bf_row.get("canonical_requirement") == original["requirement"] and
                 bf_row.get("applicability") == "DUE" and
                 bf_row.get("full_rule_semantics") == "UNKNOWN" and
                 bf_row.get("individual_mg0") == "UNKNOWN" and
                 bf_row.get("owner_approval") == "UNKNOWN" and
                 bf_row.get("advancement_authorized") is False,
                 "C07_A001_C025_BF_SOURCE_SCOPE_CHANGED:" + rid)
            bf_checks = bf_row.get("original_native_predicates")
            need(type(bf_checks) is dict and set(bf_checks) == set(SPEC[n]) and
                 all(type(v) is bool for v in bf_checks.values()),
                 "C07_A001_C025_FOUR_BF_MACHINE_CHECKS:" + rid)
            if n >= 21:
                # BF50 copies three R140 checks; compare but DO NOT double-count.
                need(list(bf_checks.values())[:3] == list(source_checks.values()) and
                     bf_checks[SPEC[n][-1]] is False,
                     "C07_A001_C025_REUSED_C_REFERENCE_CONTRADICTED:" + rid)
            else:
                checks.update({"planning:" + k: v for k, v in bf_checks.items()})
        need(len(checks) == (4 if 11 <= n <= 20 else 3),
             "C07_A001_C025_DISTINCT_SEMANTIC_MACHINE_CHECKS:" + rid)
        observation = mg0["rules"].get(rid, {})
        need(type(observation) is dict and
             observation.get("verdict") in ("UNKNOWN", "FAIL") and
             type(observation.get("uncorrected_failure_count")) is int and
             observation["uncorrected_failure_count"] >= 0 and
             type(observation.get("observation_sha256")) is str and
             HEX64.fullmatch(observation["observation_sha256"]),
             "C07_A001_C025_INDEPENDENT_MG0_NEGATIVE_MISSING:" + rid)
        bad = (observation["verdict"] == "FAIL" or
               observation["uncorrected_failure_count"] > 0)
        machine_checks += len(checks)
        machine_observed += sum(checks.values())
        negative_failures += int(bad)
        results[rid] = {
            "rule_id": rid, "canonical_requirement": original["requirement"],
            "source_sha256": original["source_sha256"],
            "requirement_sha256": original["requirement_sha256"],
            "phase": "P0", "applicability": "DUE",
            "original_machine_subchecks": checks,
            "machine_observed": sum(checks.values()),
            "machine_missing": sorted(k for k, v in checks.items() if not v),
            "mg0_negative_verdict": observation["verdict"],
            "mg0_observation_sha256": observation["observation_sha256"],
            "uncorrected_mg0_failures": observation["uncorrected_failure_count"],
            "semantic_verdict": "FAIL" if bad else "UNKNOWN",
            "full_rule_semantic_certified": False,
            "independent_mg0_certified": False, "advancement_authorized": False,
        }
    need(set(results) == set(IDS) and len(results) == 25 and machine_checks == 85,
         "C07_A001_C025_ALL_25_RULES_85_DISTINCT_CHECKS_REQUIRED")
    return {
        "schema": SCHEMA, "rule_count": 25,
        "canonical_source_clauses": 25,
        "actual_machine_subchecks_checked": machine_checks,
        "actual_machine_subchecks_observed": machine_observed,
        "mg0_individual_negative_checks": 25,
        "negative_mg0_failures": negative_failures,
        "original_audit_sha256": sha(audit),
        "original_audit_tail": mg0["audit_tail_sha256"],
        "master_sha256": work["master_sha256"],
        "attempt_id": work["attempt_id"],
        "operation_sha256": work["operation_sha256"],
        "full_rule_semantic_passes": 0, "individual_mg0_passes": 0,
        "advancement_authorized": False, "rules": results,
    }

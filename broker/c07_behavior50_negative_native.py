"""C07: 50 canonical BEHAVIOR-001..050 contradiction detectors.

Source-specific negative findings from an independently audited Controller trail.
These do NOT replace positive semantic validators, owner approval or MG0.
"""
import hashlib
import re

from real_work_intake import audit_check

SOURCE_SHA256 = "59f0565ca0842206b2649caa3d9a17c939507c3f74d445a21246732d00261e55"
TRIGGERS = {
    "BEHAVIOR-001": ("WORKSTREAM_SWITCH", "workstream switched without approval"),
    "BEHAVIOR-002": ("OFF_TOPIC_RESPONSE", "active question displaced"),
    "BEHAVIOR-003": ("METRIC_NOT_MEASURED", "primary work-hours not measured"),
    "BEHAVIOR-004": ("SECONDARY_OPTIMIZATION", "secondary telemetry before bottleneck"),
    "BEHAVIOR-005": ("REPORT_INSTEAD_OF_ASSET", "report counted as deliverable"),
    "BEHAVIOR-006": ("UNAUTHORIZED_SWITCH", "workstream switch without D0"),
    "BEHAVIOR-007": ("PREMATURE_PARALLEL_SYSTEM", "new system before original task closed"),
    "BEHAVIOR-008": ("CONTEXT_LOST", "current work identity absent"),
    "BEHAVIOR-009": ("PLAN_INSTEAD_OF_RESULT", "dispute answered with plan"),
    "BEHAVIOR-010": ("ACTIVITY_AS_COMPLETION", "activity count used as result"),
    "BEHAVIOR-011": ("COST_UNCHECKED", "cloud cost not checked"),
    "BEHAVIOR-012": ("PAID_OPTION_WITH_ZERO_COST_LOCK", "paid service offered"),
    "BEHAVIOR-013": ("UNVERIFIED_BILLING", "API billing not checked"),
    "BEHAVIOR-014": ("CONSTRAINTS_CHECKED_AFTER_BUILD", "constraints checked after coding"),
    "BEHAVIOR-015": ("USER_PC_DEPENDENCY", "user computer required"),
    "BEHAVIOR-016": ("THEORY_DECLARED_DEPLOYED", "hypothetical deployment called active"),
    "BEHAVIOR-017": ("REQUIREMENTS_NOT_COVERED", "objective cost environment authority mismatch"),
    "BEHAVIOR-018": ("UNPROVEN_DEPENDENCY", "new prerequisite without causality"),
    "BEHAVIOR-019": ("UNDEPLOYED_CLOUD_CLAIM", "permanent cloud claimed without deployment"),
    "BEHAVIOR-020": ("GATE_AS_FIX", "more gates substituted for correction"),
    "BEHAVIOR-021": ("CALENDAR_AS_RUNTIME", "calendar hours called execution"),
    "BEHAVIOR-022": ("HOURLY_RESTART_AS_CONTINUITY", "hourly restart called continuous production"),
    "BEHAVIOR-023": ("SCHEDULE_AS_PLATFORM_LIMIT", "hourly interval misreported as platform limit"),
    "BEHAVIOR-024": ("IMPOSSIBILITY_WITHOUT_MEASUREMENT", "impossibility declared without measurement"),
    "BEHAVIOR-025": ("TWO_SAMPLES_AS_GLOBAL_LIMIT", "two sessions used to infer max"),
    "BEHAVIOR-026": ("BUDGET_LABEL_AS_PROVIDER_PROOF", "budget label called provider cause"),
    "BEHAVIOR-027": ("LAST_RUN_AS_CHECKPOINT", "last_run mistaken for completion"),
    "BEHAVIOR-028": ("GUARDIAN_EXISTS_AS_DETECTION", "existence mistaken for detection"),
    "BEHAVIOR-029": ("ISOLATED_TEST_AS_AUTOMATION", "isolated test called production"),
    "BEHAVIOR-030": ("PLATFORM_ISSUE_AS_ASSET_FAILURE", "platform issue reported as Garden block"),
    "BEHAVIOR-031": ("DUTY_CYCLE_NOT_MEASURED", "unmeasured idle hours"),
    "BEHAVIOR-032": ("HYPOTHETICAL_PERCENT_AS_FACT", "example minutes stated as observed"),
    "BEHAVIOR-033": ("UNMEASURED_HOURS_LOST", "lost hours stated without measurement"),
    "BEHAVIOR-034": ("UNSUPPORTED_ETA_MULTIPLIER", "multiplicative ETA without remaining work"),
    "BEHAVIOR-035": ("PREAUDIT_AS_COMPLETE", "completion before Controller close"),
    "BEHAVIOR-036": ("UNKNOWN_TERMINATION_AS_KNOWN", "termination cause not sourced"),
    "BEHAVIOR-037": ("OBSERVER_CALLED_WATCHDOG", "watchdog lacks actual inspection"),
    "BEHAVIOR-038": ("NOTIFICATION_EQUALS_MONITORING", "notification and monitoring conflated"),
    "BEHAVIOR-039": ("R114_TEST_AS_GLOBAL_CLAIM", "process kill test called platform proof"),
    "BEHAVIOR-040": ("CHECKPOINT_RECOVERY_AS_UPTIME", "checkpoint recovery called continuous production"),
    "BEHAVIOR-041": ("UNIT_TESTS_AS_24_7", "9 unit tests claimed 24/7"),
    "BEHAVIOR-042": ("LOCAL_BENCH_AS_CLOUD", "local benchmark called cloud metric"),
    "BEHAVIOR-043": ("UNDEPLOYED_WORKER_AS_ACTIVE", "worker not deployed called working"),
    "BEHAVIOR-044": ("REPORT_AS_PRODUCTION", "R115 report called model work"),
    "BEHAVIOR-045": ("SCAN_AS_GAME_READY", "geometry scan called game-ready"),
    "BEHAVIOR-046": ("FILE_EXISTS_AS_USABLE", "stored file called usable feature"),
    "BEHAVIOR-047": ("PROMPT_UPDATE_AS_PROVEN_FIX", "prompt patch called run fix"),
    "BEHAVIOR-048": ("CONTROLLER_TESTS_AS_GLOBAL_ENFORCEMENT", "25 tests called global enforcement"),
    "BEHAVIOR-049": ("CHECKLIST_AS_ARTISTIC_QUALITY", "AAA checklist called artistic quality"),
    "BEHAVIOR-050": ("SAVE_WITHOUT_READBACK", "saved and verified without readback"),
}
assert len(TRIGGERS) == 50 and len({x[0] for x in TRIGGERS.values()}) == 50


class Behavior50Blocked(ValueError):
    pass


def inspect(inventory, audit_raw, asset, attempt_id, operation_sha256):
    """Only audit-authenticated recorded contradictions can produce FAIL.

    Mere absence of a contradictory event is UNKNOWN, never semantic PASS.
    The audit writer is not allowed to certify its own correctness.
    """
    if (type(inventory) is not dict or inventory.get("rule_count") != 763
            or inventory.get("schema") != "gg-effective-family-inventory-v1"
            or inventory.get("source_digests", {}).get("error_registry") != SOURCE_SHA256
            or type(audit_raw) is not bytes or type(asset) is not str
            or type(attempt_id) is not str or type(operation_sha256) is not str
            or not re.fullmatch("[a-f0-9]{64}", attempt_id)
            or not re.fullmatch("[a-f0-9]{64}", operation_sha256)):
        raise Behavior50Blocked("C07_BEHAVIOR50_TRUSTED_CANON_AND_AUDIT_REQUIRED")
    rows, tail = audit_check(audit_raw, asset)
    findings = {}
    for rid, (trigger, description) in TRIGGERS.items():
        canonical = inventory["rules"].get(rid)
        if (type(canonical) is not dict or canonical.get("family") != "BEHAVIOR_110"
                or canonical.get("source_sha256") != SOURCE_SHA256
                or not isinstance(canonical.get("requirement"), str)
                or hashlib.sha256(canonical["requirement"].encode()).hexdigest()
                   != canonical.get("requirement_sha256")
                or not canonical["requirement"].startswith("Errore:")):
            raise Behavior50Blocked("C07_BEHAVIOR50_CANONICAL_RULE_CHANGED:" + rid)
        # Only an independently recorded violation event in the exact attempt
        # gives a negative observation. Unknown or producer claims cannot PASS.
        matches = [row for row in rows
                   if row.get("event") == "INDEPENDENT_BEHAVIOR_VIOLATION"
                   and row.get("rule_id") == rid
                   and row.get("violation_kind") == trigger
                   and row.get("attempt_id") == attempt_id
                   and row.get("operation_sha256") == operation_sha256
                   and row.get("source_requirement_sha256") ==
                       canonical["requirement_sha256"]]
        findings[rid] = {
            "violation_kind": trigger,
            "semantic_failure": description,
            "canonical_requirement_sha256": canonical["requirement_sha256"],
            "verdict": "FAIL" if matches else "UNKNOWN",
            "record_hashes": [row["record_hash"] for row in matches],
            "full_rule_pass": False,
            "individual_mg0": "UNKNOWN",
            "advancement_authorized": False,
        }
    return {
        "schema": "gg-c07-behavior50-negative-native-v1",
        "audit_tail": tail, "source_sha256": SOURCE_SHA256,
        "rule_count": 50,
        "negative_findings": sum(v["verdict"] == "FAIL" for v in findings.values()),
        "certified_count": 0, "individual_mg0_passes": 0,
        "advancement_authorized": False, "rules": findings,
    }

"""C07 macro batch 001: 100 immutable canonical obligations, fail-closed.

This gate is NOT a semantic certifier. It binds 100 actual rule IDs and each
original source clause to independently enrolled reviewer evidence. Missing
reviewers, unknown evidence, or producer claims never become a PASS.
"""
import hashlib
import json

from c07_positive200_evidence import R122_FROZEN_IDS, R122_FROZEN_SHA256, digest
from approved_validators import REVIEWED

SCHEMA = "gg-c07-macro100-evidence-gate-v1"
BATCH_IDS = tuple(R122_FROZEN_IDS[:100])

class Macro100Blocked(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Macro100Blocked(why)

def inspect(inventory, enrolled, observations):
    """Read verified Controller inventory, reviewed enrollment and independent
    verdicts; return 100 individually traceable fail-closed decisions.

    observations[rid] must be sourced from the trusted independent reviewer,
    not from an asset producer. A successful source check alone is not PASS.
    """
    require(isinstance(inventory, dict) and
            inventory.get("schema") == "gg-effective-family-inventory-v1" and
            inventory.get("rule_count") == 763 and
            len(inventory.get("rules", {})) == 763,
            "C07_MACRO100_CANONICAL_INVENTORY_REQUIRED")
    require(len(R122_FROZEN_IDS) == 200 and
            digest(list(R122_FROZEN_IDS)) == R122_FROZEN_SHA256 and
            len(BATCH_IDS) == len(set(BATCH_IDS)) == 100,
            "C07_MACRO100_FROZEN_COHORT_CHANGED")
    require(isinstance(enrolled, dict) and isinstance(observations, dict),
            "C07_MACRO100_INPUT_SCHEMA")
    require(set(BATCH_IDS) <= set(inventory["rules"]),
            "C07_MACRO100_CANONICAL_IDS_MISSING")
    # Enrollment must first have been approved by approved_validators.validate;
    # never trust an arbitrary caller-supplied enrollment to create a PASS.
    rows = {}
    for rid in BATCH_IDS:
        rule = inventory["rules"][rid]
        clause = rule.get("requirement")
        requirement_hash = rule.get("requirement_sha256")
        source_hash = rule.get("source_sha256")
        require(isinstance(clause, str) and clause.strip() and
                isinstance(requirement_hash, str) and
                hashlib.sha256(clause.encode("utf-8")).hexdigest() == requirement_hash and
                isinstance(source_hash, str) and len(source_hash) == 64,
                "C07_MACRO100_SOURCE_CLAUSE_INVALID:" + rid)
        reviewer = REVIEWED.get(rid)
        spec = enrolled.get(rid)
        observed = observations.get(rid)
        registered = bool(reviewer is not None and isinstance(spec, dict) and
                          spec.get("validator_id") == reviewer[0] and
                          spec.get("requirement_sha256") == requirement_hash)
        independent = bool(registered and isinstance(observed, dict) and
                           observed.get("rule_id") == rid and
                           observed.get("requirement_sha256") == requirement_hash and
                           observed.get("source_sha256") == source_hash and
                           observed.get("validator_id") == reviewer[0] and
                           observed.get("independent_review") is True and
                           observed.get("mg0_independent") is True)
        # No positive verdict is accepted from an untrusted dict. This is only
        # a negative/unknown collection gate, not an MG0 signature verifier.
        negative = bool(independent and observed.get("verdict") == "FAIL")
        rows[rid] = {
            "rule_id": rid,
            "source_sha256": source_hash,
            "requirement_sha256": requirement_hash,
            "reviewer_registered": registered,
            "independent_negative_observed": negative,
            "verdict": "FAIL" if negative else "UNKNOWN",
            "full_rule_pass": False,
            "individual_mg0_pass": False,
            "advancement_authorized": False,
        }
    require(len(rows) == 100, "C07_MACRO100_INCOMPLETE")
    return {
        "schema": SCHEMA,
        "cohort_sha256": digest(list(BATCH_IDS)),
        "rule_count": 100,
        "fail_count": sum(r["verdict"] == "FAIL" for r in rows.values()),
        "unknown_count": sum(r["verdict"] == "UNKNOWN" for r in rows.values()),
        "certified_full_count": 0,
        "individual_mg0_passes": 0,
        "advancement_authorized": False,
        "rules": rows,
    }

def require_complete(report, inventory):
    """Only the trusted completion path may call this certification gate.

    Reject ID-count, CI, synthetic evidence and self-reported PASS as substitutes
    for individually approved reviewer + independent MG0 attestations.
    This negative gate cannot mint positive attestations by itself.
    """
    require(type(report) is dict and report.get("schema") == SCHEMA,
            "C07_MACRO100_CERTIFICATE_SCHEMA")
    require(type(report.get("rules")) is dict and
            set(report["rules"]) == set(BATCH_IDS) and
            report.get("rule_count") == 100,
            "C07_MACRO100_NOT_ALL_ONE_HUNDRED_RULES")
    require(type(inventory) is dict and
            set(BATCH_IDS) <= set(inventory.get("rules", {})),
            "C07_MACRO100_CANONICAL_RECHECK")
    for rid in BATCH_IDS:
        row = report["rules"][rid]
        canonical = inventory["rules"][rid]
        require(type(row) is dict and row.get("rule_id") == rid and
                row.get("requirement_sha256") == canonical.get("requirement_sha256") and
                row.get("source_sha256") == canonical.get("source_sha256"),
                "C07_MACRO100_WRONG_RULE_OR_SOURCE:" + rid)
        # This implementation currently has no trusted positive MG0 backend:
        # even an all-green dict cannot pass. The trusted certification backend
        # must be integrated before legitimate certification can be granted.
        raise Macro100Blocked("C07_MACRO100_INDEPENDENT_FULL_AND_MG0_MISSING:" + rid)
    raise Macro100Blocked("C07_MACRO100_CERTIFIER_NOT_INSTALLED")

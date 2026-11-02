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

def require_complete(report, inventory, *, independent_verifier=None):
    """Certify only after a trusted backend independently replays every rule.

    The caller must obtain independent_verifier from its authenticated Controller
    review boundary, NEVER from user/producer JSON or another work artifact.
    Without that backend this remains fail-closed.
    """
    require(type(report) is dict and report.get("schema") == SCHEMA,
            "C07_MACRO100_CERTIFICATE_SCHEMA")
    require(type(report.get("rules")) is dict and
            set(report["rules"]) == set(BATCH_IDS) and
            report.get("rule_count") == 100 and
            report.get("cohort_sha256") == digest(list(BATCH_IDS)),
            "C07_MACRO100_NOT_ALL_ONE_HUNDRED_RULES")
    require(type(inventory) is dict and
            inventory.get("schema") == "gg-effective-family-inventory-v1" and
            inventory.get("rule_count") == 763 and
            len(inventory.get("rules", {})) == 763 and
            set(BATCH_IDS) <= set(inventory["rules"]),
            "C07_MACRO100_CANONICAL_RECHECK")
    require(callable(independent_verifier),
            "C07_MACRO100_INDEPENDENT_VERIFIER_MISSING")
    verified = {}
    for rid in BATCH_IDS:
        row = report["rules"][rid]
        canonical = inventory["rules"][rid]
        clause = canonical.get("requirement")
        source = canonical.get("source_sha256")
        requirement = canonical.get("requirement_sha256")
        require(type(clause) is str and clause.strip() and
                hashlib.sha256(clause.encode("utf-8")).hexdigest() == requirement and
                type(source) is str and len(source) == 64,
                "C07_MACRO100_CANONICAL_SOURCE_CHANGED:" + rid)
        require(type(row) is dict and row.get("rule_id") == rid and
                row.get("requirement_sha256") == requirement and
                row.get("source_sha256") == source,
                "C07_MACRO100_WRONG_RULE_OR_SOURCE:" + rid)
        require(rid in REVIEWED,
                "C07_MACRO100_NO_APPROVED_SEMANTIC_REVIEWER:" + rid)
        # This is a fresh read from the Controller's authenticated review
        # backend, NOT the claims supplied by report.
        proof = independent_verifier(rid, canonical)
        require(type(proof) is dict and
                proof.get("rule_id") == rid and
                proof.get("requirement_sha256") == requirement and
                proof.get("source_sha256") == source and
                proof.get("validator_id") == REVIEWED[rid][0] and
                proof.get("semantic_verdict") == "PASS" and
                proof.get("mg0_verdict") == "PASS" and
                proof.get("independent") is True and
                type(proof.get("source_attestation_sha256")) is str and
                len(proof["source_attestation_sha256"]) == 64,
                "C07_MACRO100_INDEPENDENT_FULL_AND_MG0_MISSING:" + rid)
        verified[rid] = proof["source_attestation_sha256"]
    return {"schema": "gg-c07-macro100-trusted-certification-v1",
            "rule_count": 100, "certified_full_count": 100,
            "individual_mg0_passes": 100,
            "cohort_sha256": digest(list(BATCH_IDS)),
            "independent_attestation_digests": verified,
            "advancement_authorized": True}

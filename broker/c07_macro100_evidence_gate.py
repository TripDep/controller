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


def inspect_semantic_candidates(inventory, observations, blobs=None):
    """Execute development predicates without entering native certification.

    The report cannot be passed to require_complete: it has a separate schema,
    no trusted reviewer origin and no MG0 verdict. Enrollment remains unchanged.
    """
    from c07_macro100_semantics import inspect_candidate
    return inspect_candidate(inventory, observations, blobs)

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

def require_complete(report, inventory, *, work=None, offers=None, backend=None):
    """Reject user-supplied completions; replay trusted native proofs instead."""
    require(type(report) is dict and report.get("schema") == SCHEMA,
            "C07_MACRO100_CERTIFICATE_SCHEMA")
    require(type(report.get("rules")) is dict and
            set(report["rules"]) == set(BATCH_IDS) and
            report.get("rule_count") == 100 and
            report.get("cohort_sha256") == digest(list(BATCH_IDS)),
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
    return certify_native(inventory, work, offers, backend)


def certify_native(inventory, work, offers, backend):
    """100 original obligations, verified via existing authenticated native backend.

    No producer-supplied callback/JSON verdict can authorize certification.
    This is a cohort gate; it does not replace global 763-rule work admission.
    """
    from supervisor_judgment import NativeRuleBackend, validate_work, binding
    from approved_validators import validate as validate_reviewed
    require(type(backend) is NativeRuleBackend and backend.synthetic is False,
            "C07_MACRO100_TRUSTED_NATIVE_BACKEND_REQUIRED")
    require(type(inventory) is dict and inventory.get("rule_count") == 763 and
            len(inventory.get("rules", {})) == 763 and
            type(offers) is dict and type(work) is dict,
            "C07_MACRO100_REAL_WORK_CONTEXT_REQUIRED")
    validate_work(work, inventory)
    require(set(BATCH_IDS) <= set(inventory["rules"]),
            "C07_MACRO100_ORIGINAL_COHORT_MISSING")
    require(set(offers) <= set(inventory["rules"]),
            "C07_MACRO100_UNKNOWN_OFFER")
    # approved_validators checks the reviewed source-specific implementation,
    # immutable issuer and expected criteria for every enrolled validator.
    validate_reviewed(backend.enrolled, inventory)
    checked = {}
    for rid in BATCH_IDS:
        row = inventory["rules"][rid]
        clause = row.get("requirement")
        require(type(clause) is str and clause.strip() and
                hashlib.sha256(clause.encode("utf-8")).hexdigest() ==
                row.get("requirement_sha256"),
                "C07_MACRO100_SOURCE_CHANGED:" + rid)
        require(rid in REVIEWED and rid in backend.enrolled,
                "C07_MACRO100_MISSING_REVIEWED_VALIDATOR:" + rid)
        expected = binding(work, row, rid)
        result = backend.rule(rid, expected, offers.get(rid))
        require(type(result) is dict and result.get("result") == "PASS" and
                result.get("mg0") == "PASS" and
                type(result.get("proof_digest")) is str and
                len(result["proof_digest"]) == 64,
                "C07_MACRO100_REAL_SEMANTIC_OR_MG0_NOT_PASS:" + rid)
        checked[rid] = result["proof_digest"]
    require(len(checked) == 100, "C07_MACRO100_INCOMPLETE")
    return {"schema": "gg-c07-macro100-native-certified-v1",
            "cohort_sha256": digest(list(BATCH_IDS)),
            "rule_count": 100, "certified_full_count": 100,
            "individual_mg0_passes": 100,
            "verified_proof_digests": checked,
            "cohort_verified": True,
            "global_work_advancement_authorized": False}

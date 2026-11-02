"""C07: fail-closed completion of 25 real rules with external MG0 review.

An ordinary audit readback can identify known MG0 failures; it cannot certify
absence of undiscovered failures. An independently controlled Ed25519 key must
sign the entire *current* rule, native decision, audit, semantic proof and
five-trigger review. This module owns NO private key, creates NO attestations,
and cannot turn CI success or missing evidence into a positive certificate.
"""
import base64
import binascii
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{64}\Z")
SCHEMA = "gg-c07-independent-mg0-25-signed-review-v1"

class CertificationBlocked(ValueError):
    pass

def need(condition, reason):
    if not condition:
        raise CertificationBlocked(reason)

def digest(value):
    return hashlib.sha256(value).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def signature_valid(payload, signature, public_pem):
    """Verify detached Ed25519 over the canonical UTF-8 review payload.

    public_pem must be provisioned out-of-band from an authorized independent
    reviewer. Never accept a key embedded in the review itself.
    """
    need(type(public_pem) is bytes and public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
         and len(public_pem) < 8192, "MG0_TRUSTED_INDEPENDENT_PUBLIC_KEY_REQUIRED")
    need(type(signature) is str and len(signature) < 256,
         "MG0_INVALID_SIGNATURE")
    try:
        sig = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CertificationBlocked("MG0_INVALID_SIGNATURE") from exc
    need(len(sig) == 64, "MG0_INVALID_ED25519_SIGNATURE_LENGTH")
    with tempfile.TemporaryDirectory(prefix="c07-mg0-verifier-") as tmp:
        root = Path(tmp)
        (root / "review.json").write_bytes(canonical(payload))
        (root / "public.pem").write_bytes(public_pem)
        (root / "signature.bin").write_bytes(sig)
        try:
            check = subprocess.run([
                "openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(root / "public.pem"), "-rawin",
                "-in", str(root / "review.json"),
                "-sigfile", str(root / "signature.bin")],
                capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise CertificationBlocked("MG0_SIGNATURE_VERIFIER_UNAVAILABLE") from exc
    need(check.returncode == 0, "MG0_INDEPENDENT_REVIEW_SIGNATURE_REJECTED")
    return True

def certify_25(master_raw, audit_raw, asset, master_sha256, rule_ids,
               attempt_id, inventory, plan, work, native_decision,
               reviews, trusted_public_key_pem):
    """Require 25/25 independent certificates for an actual current attempt.

    The normal native report is recomputed through the existing 763-rule
    source-verified rollup. The negative MG0 layer still runs against original
    audit bytes. Only a separately authorized, signed *positive* review can
    close an UNKNOWN. Discovered uncorrected failures can NEVER be overridden.
    """
    from c07_mg0_individual import inspect_batch as read_mg0
    from c07_763_post_certification import inspect as read_native

    need(type(rule_ids) in (list, tuple) and len(rule_ids) == 25 and
         list(rule_ids) == sorted(set(rule_ids)), "MG0_MACRO_EXACT_25_UNIQUE_RULES_REQUIRED")
    need(type(reviews) is dict and set(reviews) == set(rule_ids),
         "MG0_MACRO_25_EXTERNAL_REVIEWS_REQUIRED")
    need(type(work) is dict and work.get("attempt_id") == attempt_id and
         work.get("master_sha256") == master_sha256 and
         type(inventory) is dict and inventory.get("canonical_master_sha256") == master_sha256,
         "MG0_MACRO_CURRENT_WORK_AND_MASTER_REQUIRED")
    need(type(master_raw) is bytes and digest(master_raw) == master_sha256 and
         type(audit_raw) is bytes and type(asset) is str,
         "MG0_MACRO_EXACT_ORIGINAL_MASTER_AND_AUDIT_REQUIRED")
    mg0 = read_mg0(master_raw, audit_raw, asset, master_sha256,
                   list(rule_ids), attempt_id)
    native = read_native(inventory, plan, work, native_decision)
    need(type(native) is dict and native.get("schema") ==
         "gg-c07-763-independent-post-operation-certification-v1" and
         native.get("attempt_id") == attempt_id and
         native.get("master_sha256") == master_sha256 and
         native.get("native_decision_sha256") == native_decision.get("decision_sha256"),
         "MG0_MACRO_ORIGINAL_NATIVE_DECISION_REQUIRED")
    need(mg0.get("rule_count") == 25 and mg0.get("audit_sha256") == digest(audit_raw) and
         mg0.get("attempt_id") == attempt_id and set(mg0.get("rules", {})) == set(rule_ids),
         "MG0_MACRO_ORIGINAL_AUDIT_READBACK_REQUIRED")
    completed = {}
    for rid in rule_ids:
        row = inventory.get("rules", {}).get(rid)
        r_native = native.get("rules", {}).get(rid)
        r_mg0 = mg0["rules"][rid]
        need(type(row) is dict and type(r_native) is dict and
             r_native.get("post_native_semantic") == "PASS" and
             r_native.get("individual_mg0") == "PASS" and
             r_native.get("source_specific_reviewer_approved") is True and
             r_native.get("semantically_certified") is True and
             SHA.fullmatch(str(r_native.get("verified_native_packet_digest", ""))) is not None,
             "MG0_UNCERTIFIED_NATIVE_SEMANTIC_RULE:" + rid)
        need(r_mg0.get("verdict") != "FAIL" and
             r_mg0.get("uncorrected_failure_count") == 0,
             "MG0_UNCORRECTED_ORIGINAL_AUDIT_FAILURE:" + rid)
        signed = reviews[rid]
        need(type(signed) is dict and set(signed) == {"payload", "signature_base64"},
             "MG0_EXTERNAL_REVIEW_SCHEMA:" + rid)
        payload = signed["payload"]
        need(type(payload) is dict and set(payload) == {
            "schema", "asset", "rule_id", "attempt_id", "master_sha256",
            "audit_sha256", "audit_tail_sha256", "requirement_sha256",
            "source_sha256", "native_decision_sha256", "native_packet_sha256",
            "original_mg0_observation_sha256", "external_evidence_sha256",
            "reviewer_id", "reviewed_trigger_ids", "independent_full_semantic_pass",
            "independent_mg0_pass", "owner_provenance_authenticated",
            "current_attempt_reapplication_verified"
        }, "MG0_EXTERNAL_REVIEW_FIELDS:" + rid)
        expected = {
            "schema": SCHEMA,
            "asset": asset,
            "rule_id": rid,
            "attempt_id": attempt_id,
            "master_sha256": master_sha256,
            "audit_sha256": mg0["audit_sha256"],
            "audit_tail_sha256": mg0["audit_tail_sha256"],
            "requirement_sha256": row["requirement_sha256"],
            "source_sha256": row["source_sha256"],
            "native_decision_sha256": native["native_decision_sha256"],
            "native_packet_sha256": r_native["verified_native_packet_digest"],
            "original_mg0_observation_sha256": r_mg0["observation_sha256"],
        }
        need(all(payload.get(key) == value for key, value in expected.items()),
             "MG0_EXTERNAL_REVIEW_CROSS_ATTEMPT_OR_SOURCE_MISMATCH:" + rid)
        need(type(payload["reviewer_id"]) is str and payload["reviewer_id"].strip() and
             SHA.fullmatch(str(payload["external_evidence_sha256"])) is not None and
             payload["reviewed_trigger_ids"] == [1, 2, 3, 4, 5] and
             all(payload[field] is True for field in (
                 "independent_full_semantic_pass", "independent_mg0_pass",
                 "owner_provenance_authenticated",
                 "current_attempt_reapplication_verified")),
             "MG0_INDEPENDENT_ALL_FIVE_TRIGGER_AND_OWNER_REVIEW_MISSING:" + rid)
        signature_valid(payload, signed["signature_base64"], trusted_public_key_pem)
        completed[rid] = {
            "result": "PASS", "individual_mg0": "PASS",
            "signature_review_sha256": digest(canonical(payload)),
            "native_packet_sha256": expected["native_packet_sha256"],
            "independent_reviewer": payload["reviewer_id"],
        }
    need(len(completed) == 25, "MG0_MACRO_25_NOT_COMPLETED")
    return {
        "schema": "gg-c07-final-signed-macro25-v1",
        "count": 25,
        "full_semantic_passes": 25,
        "independent_mg0_passes": 25,
        "signed_reviewer_public_key_sha256": digest(trusted_public_key_pem),
        "native_decision_sha256": native["native_decision_sha256"],
        "original_audit_sha256": mg0["audit_sha256"],
        "attempt_id": attempt_id,
        "rules": completed,
        "advancement_authorized": False,
    }

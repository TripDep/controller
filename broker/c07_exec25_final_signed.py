"""C07 EXEC-001..025: independent, evidence-backed final signed macro gate.

Unlike the full 763-rule *operation close*, this certifies exactly the current
EXEC25 macro without pretending that other rules have passed. Its only positive
authority is a separately owner-approved, Ed25519-signed review of the full
original requirement and five MG0 triggers, backed by *actual supplied evidence
bytes* and rechecks of the live 100 source-specific original-byte predicates.
It cannot issue a PASS on unsigned data, synthetic CI results, partial checks,
unknown owner, a stale attempt, missing evidence or any uncorrected MG0 failure.
Never mints a private key, signs on the owner's behalf or advances operations.
"""
import base64
import binascii
import hashlib
import json
import re
from c07_exec25_native_observation import IDS
from c07_exec25_original_reviewed_native import inspect as inspect_exec
from c07_mg0_individual import inspect_batch as read_mg0
from c07_mg0_signed25 import signature_valid, canonical

SCHEMA = "gg-c07-exec25-owner-signed-final-review-v1"
EVIDENCE_SCHEMA = "gg-c07-exec25-independent-evidence-v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
class FinalCertificationBlocked(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise FinalCertificationBlocked(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def checked_evidence(evidence_b64, rid, context, row):
    need(type(evidence_b64) is str and len(evidence_b64) <= 131072,
         "EXEC25_INDEPENDENT_EVIDENCE_BYTES_REQUIRED:" + rid)
    try:
        raw=base64.b64decode(evidence_b64, validate=True)
    except (ValueError,binascii.Error) as exc:
        raise FinalCertificationBlocked(
            "EXEC25_INDEPENDENT_EVIDENCE_NOT_BASE64:" + rid) from exc
    need(0 < len(raw) <= 98304, "EXEC25_INDEPENDENT_EVIDENCE_SIZE:" + rid)
    try:
        data=json.loads(raw.decode("utf-8"))
    except (ValueError,UnicodeDecodeError) as exc:
        raise FinalCertificationBlocked(
            "EXEC25_INDEPENDENT_EVIDENCE_NOT_JSON:" + rid) from exc
    need(type(data) is dict and set(data)=={
        "schema","rule_id","attempt_id","master_sha256",
        "requirement_sha256","full_clause_findings",
        "five_mg0_trigger_findings","independent_evidence_references",
        "independent_review_method"},
        "EXEC25_INDEPENDENT_EVIDENCE_SCHEMA:" + rid)
    need(data["schema"]==EVIDENCE_SCHEMA and data["rule_id"]==rid and
         data["attempt_id"]==context["work"]["attempt_id"] and
         data["master_sha256"]==context["work"]["master_sha256"] and
         data["requirement_sha256"]==row["requirement_sha256"],
         "EXEC25_INDEPENDENT_EVIDENCE_SOURCE_OR_ATTEMPT:" + rid)
    findings=data["full_clause_findings"]
    triggers=data["five_mg0_trigger_findings"]
    refs=data["independent_evidence_references"]
    need(type(findings) is list and len(findings)>=1 and len(findings)<=50 and
         all(type(v) is dict and set(v)=={"clause","finding","evidence_sha256"}
             and type(v["clause"]) is str and bool(v["clause"].strip())
             and v["finding"]=="PASS"
             and SHA.fullmatch(str(v["evidence_sha256"]))
             for v in findings),
         "EXEC25_INDEPENDENT_FULL_CLAUSE_FINDINGS_REQUIRED:" + rid)
    need(type(triggers) is list and
         [v.get("trigger_id") for v in triggers if type(v) is dict]==[1,2,3,4,5] and
         all(type(v) is dict and set(v)=={
             "trigger_id","independently_replayed","finding","evidence_sha256"}
             and v["independently_replayed"] is True and v["finding"]=="PASS"
             and SHA.fullmatch(str(v["evidence_sha256"]))
             for v in triggers),
         "EXEC25_INDEPENDENT_FIVE_MG0_TRIGGER_FINDINGS_REQUIRED:" + rid)
    referenced={v["evidence_sha256"] for v in findings+triggers}
    need(type(refs) is list and len(refs)>=1 and len(refs)<=100 and
         all(type(v) is dict and set(v)=={"sha256","source","verified"}
             and SHA.fullmatch(str(v["sha256"])) and
             type(v["source"]) is str and bool(v["source"].strip()) and
             v["verified"] is True for v in refs) and
         referenced.issubset({v["sha256"] for v in refs}) and
         type(data["independent_review_method"]) is str and
         len(data["independent_review_method"].strip())>=20,
         "EXEC25_INDEPENDENT_REFERENCED_PROOFS_REQUIRED:" + rid)
    # The signer attests having actually inspected these evidence references.
    # A digest or document title alone is not a software-verifiable file read;
    # the signature never pretends to independently replay inaccessible files.
    return sha(raw)

def certify(context, reviews, owner_public_key, owner_reviewer_id):
    """Certify only 25/25 after real current-source readback and signed proof.

    reviewers' evidence document bytes are embedded as base64; the signature
    covers their SHA and source/attempt/audit bindings, not just a YES list.
    """
    need(type(context) is dict and type(reviews) is dict and
         set(reviews)==set(IDS) and
         type(owner_reviewer_id) is str and owner_reviewer_id.strip(),
         "EXEC25_EXACT_25_OWNER_REVIEWS_REQUIRED")
    inv=context["inventory"];work=context["work"];c=context["controller"]
    need(inv.get("rule_count")==763 and
         inv.get("canonical_master_sha256")==work.get("master_sha256") and
         context["plan"].get("master_sha256")==work["master_sha256"],
         "EXEC25_CURRENT_CANONICAL_WORK_REQUIRED")
    master=c.master.read_bytes()
    need(type(master) is bytes and sha(master)==work["master_sha256"],
         "EXEC25_ORIGINAL_MASTER_BYTES_REQUIRED")
    audit=c.audit_path(context["asset"]).read_bytes()
    need(type(audit) is bytes, "EXEC25_ORIGINAL_AUDIT_BYTES_REQUIRED")
    original=inspect_exec(context)
    mg0=read_mg0(master,audit,context["asset"],work["master_sha256"],
                 list(IDS),work["attempt_id"])
    need(original["rule_count"]==mg0["rule_count"]==25 and
         original["criteria_count"]==100 and
         original["positive_scope_observations"]==100 and
         original["original_audit_sha256"]==mg0["audit_sha256"]==sha(audit) and
         original["original_audit_tail"]==mg0["audit_tail_sha256"] and
         original["attempt_id"]==mg0["attempt_id"]==work["attempt_id"] and
         original["master_sha256"]==work["master_sha256"] and
         original["full_rule_passes"]==original["individual_mg0_passes"]==0 and
         original["advancement_authorized"] is False and
         set(original["rules"])==set(mg0["rules"])==set(IDS) and
         mg0["failed_rule_ids"]==[] and mg0["counts"]["FAIL"]==0 and
         mg0["individual_mg0_passes"]==0,
         "EXEC25_ALL_100_ORIGINAL_CRITERIA_AND_NEGATIVE_MG0_REQUIRED")
    completed={}
    for rid in IDS:
        row=inv["rules"][rid]; observed=original["rules"][rid]
        baseline=mg0["rules"][rid]
        need(observed["scoped_positive_count"]==4 and
             set(observed["criteria"])==set(
                 __import__("c07_exec25_original_reviewed_native").CRITERIA[rid]) and
             all(v is True for v in observed["criteria"].values()) and
             observed["requirement_sha256"]==row["requirement_sha256"] and
             observed["source_sha256"]==row["source_sha256"] and
             baseline["verdict"]=="UNKNOWN" and
             baseline["uncorrected_failure_count"]==0 and
             SHA.fullmatch(str(baseline["observation_sha256"])),
             "EXEC25_RULE_OR_MG0_NEGATIVE_OBSERVATIONS_NOT_CLEAN:"+rid)
        signed=reviews[rid]
        need(type(signed) is dict and set(signed)=={
             "payload","signature_base64","evidence_base64"},
             "EXEC25_SIGNED_REVIEW_SCHEMA:"+rid)
        payload=signed["payload"]
        need(type(payload) is dict and set(payload)=={
             "schema","rule_id","asset","attempt_id","operation_sha256",
             "master_sha256","audit_sha256","audit_tail_sha256",
             "requirement_sha256","source_sha256",
             "original_exec25_observation_sha256",
             "original_mg0_observation_sha256",
             "external_evidence_sha256","reviewer_id",
             "full_original_clause_pass","five_independent_mg0_triggers_pass",
             "owner_provenance_authenticated","current_attempt_reapplication_verified"},
             "EXEC25_SIGNED_PAYLOAD_FIELDS:"+rid)
        expected={
            "schema":SCHEMA,
            "rule_id":rid,"asset":context["asset"],
            "attempt_id":work["attempt_id"],
            "operation_sha256":work["operation_sha256"],
            "master_sha256":work["master_sha256"],
            "audit_sha256":mg0["audit_sha256"],
            "audit_tail_sha256":mg0["audit_tail_sha256"],
            "requirement_sha256":row["requirement_sha256"],
            "source_sha256":row["source_sha256"],
            "original_exec25_observation_sha256":sha(canonical(observed)),
            "original_mg0_observation_sha256":baseline["observation_sha256"],
            "reviewer_id":owner_reviewer_id,
        }
        need(all(payload.get(k)==v for k,v in expected.items()) and
             payload["full_original_clause_pass"] is True and
             payload["five_independent_mg0_triggers_pass"] is True and
             payload["owner_provenance_authenticated"] is True and
             payload["current_attempt_reapplication_verified"] is True,
             "EXEC25_CROSS_ATTEMPT_OR_INDEPENDENT_REVIEW_MISMATCH:"+rid)
        actual_evidence_sha=checked_evidence(
            signed["evidence_base64"],rid,context,row)
        need(payload["external_evidence_sha256"]==actual_evidence_sha,
             "EXEC25_INDEPENDENT_EVIDENCE_BYTES_HASH_MISMATCH:"+rid)
        signature_valid(payload,signed["signature_base64"],owner_public_key)
        completed[rid]={
            "result":"PASS","independent_mg0":"PASS",
            "source_original_sha256":row["requirement_sha256"],
            "review_sha256":sha(canonical(payload)),
            "external_evidence_sha256":actual_evidence_sha,
            "original_audit_sha256":mg0["audit_sha256"],
        }
    need(len(completed)==25,"EXEC25_FINAL_ALL_25_REQUIRED")
    return {
        "schema":"gg-c07-exec25-final-signed-certification-v1",
        "attempt_id":work["attempt_id"],
        "master_sha256":work["master_sha256"],
        "original_audit_sha256":mg0["audit_sha256"],
        "owner_reviewer_id":owner_reviewer_id,
        "owner_public_key_sha256":sha(owner_public_key),
        "independent_full_semantic_passes":25,
        "independent_mg0_passes":25,
        "full_original_source_criteria_verified":100,
        "rules":completed,
        "other_738_rules_not_certified_by_this_report":True,
        "advancement_authorized":False,
    }

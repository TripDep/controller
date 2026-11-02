"""Reviewed exact source native semantic replay for TWO real C07 obligations.

R172: editable source, export, and delivery are genuinely distinct original
binary roles; original zip contents/manifest match the authenticated source.
R178: actual original Golden Controller state/audit and ALL original
dependency bytes are still present and match their source registration.

There is NO authority to mint individual MG0 or owner approval here.
Both source rules may have a real positive literal semantic observation, but
the complete operational rule remains UNKNOWN until independent MG0 evidence.

Original registered model bytes remain LOCAL. The consumer rereads them
inside the locked Controller, while the canonical public rule source is
independently fetched from an immutable private Git revision.
"""
import hashlib
import re
from pathlib import Path

from c07_two_exact_process_semantics import inspect as inspect_original
from c07_positive_native_process import RULES
from family_coverage import SOURCES
import supervisor_judgment as j

VALIDATOR="GG_C07_R172_R178_LOCAL_ORIGINAL_NATIVE_REPLAYER_V1"
ADDITIONAL={
    "AAA-200-R-172":(
        "source_export_delivery_exact_source_bound",
        "correct_current_attempt_bound",
    ),
    "AAA-200-R-178":(
        "persisted_live_controller_state",
        "all_declared_dependency_bytes_rechecked",
        "enrolled_operation_scope_authenticated",
    ),
}
CRITERIA={
    rid:tuple(RULES[rid][2])+ADDITIONAL[rid]
    for rid in ADDITIONAL
}
CATALOG_PATH=SOURCES["aaa_catalog"]
class ExactLocalReviewBlocked(ValueError):pass

def need(condition,msg):
    if not condition:raise ExactLocalReviewBlocked(msg)

def _original_report(context,rid,expected):
    need(type(context) is dict and
         set(context)=={"inventory","plan","controller","asset","step",
                        "work","source_loader"} and
         callable(context["source_loader"]) and rid in CRITERIA,
         "R172_R178_ORIGINAL_CONTROLLER_CONTEXT_REQUIRED")
    inv=context["inventory"];work=context["work"];plan=context["plan"]
    need(inv.get("schema")=="gg-effective-family-inventory-v1" and
         inv.get("rule_count")==763 and
         type(plan) is dict and type(work) is dict and
         expected==j.binding(work,inv["rules"][rid],rid) and
         plan.get("master_sha256")==work.get("master_sha256") and
         inv.get("canonical_master_sha256")==work.get("master_sha256"),
         "R172_R178_SOURCE_ATTEMPT_OR_PLAN_CHANGED")
    inspected=inspect_original(
        inv,plan,context["controller"],context["asset"],context["step"],
        work,source_loader=context["source_loader"])
    need(inspected["schema"]=="gg-c07-native-2-exact-process-semantics-v1"
         and inspected["source_rule_count"]==2
         and set(inspected["rules"])==set(CRITERIA)
         and inspected["attempt_id"]==work["attempt_id"]
         and inspected["operation_sha256"]==work["operation_sha256"]
         and inspected["master_sha256"]==work["master_sha256"]
         and inspected["individual_mg0_passes"]==0
         and inspected["full_work_rule_passes"]==0
         and inspected["advancement_authorized"] is False,
         "R172_R178_FALSE_ORIGINAL_COMPLETION")
    row=inspected["rules"][rid]
    need(row["source_sha256"]==inv["rules"][rid]["source_sha256"]
         and row["requirement_sha256"]==expected["requirement_sha256"]
         and set(row["original_machine_criteria"])==set(RULES[rid][2])
         and set(row["additional_full_literal_criteria"])==set(ADDITIONAL[rid])
         and row["individual_mg0"]=="UNKNOWN"
         and row["full_work_rule_pass"] is False,
         "R172_R178_ORIGINAL_SOURCE_OR_RULE_REPLAY")
    checks={**row["original_machine_criteria"],
            **row["additional_full_literal_criteria"]}
    need(set(checks)==set(CRITERIA[rid])
         and all(type(v) is bool for v in checks.values()) and
         row["literal_process_semantics"]==
            ("PASS" if all(checks.values()) else "UNKNOWN"),
         "R172_R178_SOURCE_SPECIFIC_CRITERIA_MISMATCH")
    return inspected,checks

def packet_for_original(context,rid,expected):
    """For an authorized originating native producer; NEVER mint MG0 PASS."""
    original,checks=_original_report(context,rid,expected)
    result="PASS" if all(checks.values()) else "UNKNOWN"
    proof=j.digest({
        "rule_id":rid,"current_attempt_id":expected["attempt_id"],
        "operation_sha256":expected["operation_sha256"],
        "original_audit_sha256":original["original_audit_sha256"],
        "original_audit_tail":original["original_audit_tail"],
        "current_persisted_state_rechecked":
            original["original_persisted_state_rechecked"],
        "source_requirement_sha256":expected["requirement_sha256"],
        "checks":checks,"literal_semantics":result,
    })
    return {
       "schema":"gg-semantic-rule-v1",
       "scope":j.SEMANTIC_SCOPE,
       "validator_id":VALIDATOR,
       "binding":expected,
       "rule":{"result":result,"checks":checks,"proof_digest":proof},
       "mg0":{"binding":expected,"triggered":None,"result":"UNKNOWN",
              "checks":{"canonical_triggers_checked":False},
              "proof_digest":j.digest({
                  "rule_id":rid,
                  "attempt_id":expected["attempt_id"],
                  "reason":"INDEPENDENT_OWNER_MG0_UNPROVEN",
              })},
    }

def native_rule_readback(api,packet,expected,enrolled_spec,context):
    """Consumer replays BOTH original local bytes and immutable Git catalog.

    Git workflow provenance is verified by NativeRuleBackend BEFORE this
    function is called; a producer's claims/hashes NEVER replace readback.
    """
    from broker_live_review import decode_file
    rid=expected.get("rule_id")
    need(rid in CRITERIA and
         enrolled_spec.get("validator_id")==VALIDATOR and
         set(enrolled_spec.get("criteria",()))==set(CRITERIA[rid]) and
         type(enrolled_spec.get("source_ref")) is str and
         re.fullmatch(r"[0-9a-f]{40}",enrolled_spec["source_ref"]),
         "R172_R178_ORIGINAL_REVIEWER_AND_IMMUTABLE_SOURCE_REQUIRED")
    raw=decode_file(api.call(
        "GET","/contents/"+CATALOG_PATH+"?ref="+enrolled_spec["source_ref"]),
        CATALOG_PATH)
    need(hashlib.sha256(raw).hexdigest()==
         context["inventory"].get("source_digests",{}).get("aaa_catalog"),
         "R172_R178_INDEPENDENT_PRIVATE_GIT_CANONICAL_SOURCE_CHANGED")
    recomputed=packet_for_original(context,rid,expected)
    need(packet==recomputed and
         recomputed["mg0"]["result"]=="UNKNOWN" and
         recomputed["mg0"]["triggered"] is None,
         "R172_R178_UNTRUSTED_PRODUCER_RULE_OR_MG0_CLAIM")
    return {"rule_id":rid,"literal_semantics":recomputed["rule"]["result"],
            "individual_mg0":"UNKNOWN","advancement_authorized":False}

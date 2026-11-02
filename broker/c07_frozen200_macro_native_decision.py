"""C07 first-frozen-200 macro positive semantic decision gate.

Only trusted fresh j.judge + Git-native reviewed validators + individual MG0
can establish full PASS. This module is called exclusively on the in-memory
fresh verdict after comparison with independently fetched Git native decision.
No file existence, green CI, self-description, or checksum alone is PASS.
"""
import hashlib
import re

from c07_positive200_evidence import (
    R122_FROZEN_IDS,R122_FROZEN_SHA256,digest as cohort_digest
)
from approved_validators import REVIEWED,validate as validate_reviewed
from supervisor_judgment import binding,digest as judgment_digest
from family_coverage import expected_result

SCHEMA="gg-c07-frozen200-native-positive-verdict-gate-v1"
SHA=re.compile("[0-9a-f]{64}\\Z")
class Macro200Blocked(ValueError): pass
def need(ok,message):
    if not ok:raise Macro200Blocked(message)

def inspect(inv,work,plan,fresh):
    """Read native review result without inventing either a reviewer or PASS.

    Caller must have freshly recomputed j.judge through NativeRuleBackend and
    verified byte-equality against real immutable Git-native decision.
    This observer is not a new standalone source of authority.
    """
    need(type(inv) is dict and
         inv.get("schema")=="gg-effective-family-inventory-v1" and
         inv.get("rule_count")==len(inv.get("rules",{}))==763 and
         len(inv.get("families",{}))==20 and
         len(R122_FROZEN_IDS)==len(set(R122_FROZEN_IDS))==200 and
         cohort_digest(list(R122_FROZEN_IDS))==R122_FROZEN_SHA256,
         "MACRO200_CANONICAL_200_COHORT_OR_763_INVENTORY_CHANGED")
    need(type(plan) is dict and type(plan.get("enrolled")) is dict and
         plan.get("master_sha256")==work.get("master_sha256")==
              inv.get("canonical_master_sha256"),
         "MACRO200_CURRENT_MASTER_AND_PLAN_REQUIRED")
    need(type(fresh) is dict and fresh.get("schema")=="gg-process-judgment-v1"
         and fresh.get("synthetic_backend") is False and
         fresh.get("attempt_id")==work.get("attempt_id") and
         fresh.get("operation_sha256")==work.get("operation_sha256") and
         fresh.get("work_item_sha256")==work.get("work_item_sha256") and
         fresh.get("master_sha256")==work.get("master_sha256") and
         fresh.get("phase")==work.get("phase") and
         fresh.get("rule_count")==763 and
         fresh.get("decision_sha256")==judgment_digest({
              k:v for k,v in fresh.items() if k!="decision_sha256"}),
         "MACRO200_TRUSTED_CURRENT_NATIVE_DECISION_REQUIRED")
    try:
        validate_reviewed(plan["enrolled"],inv)
    except (ValueError,TypeError,KeyError) as exc:
        raise Macro200Blocked(
            "MACRO200_UNTRUSTED_REVIEWED_VALIDATOR_ENROLLMENT") from exc
    native={}
    for family,rows in fresh.get("families",{}).items():
        need(family in inv["families"] and type(rows) is dict and
             set(rows)==set(inv["families"][family]),
             "MACRO200_NATIVE_FAMILY_ROWS_CHANGED:"+str(family))
        for rid,row in rows.items():
            need(rid not in native and type(row) is dict,
                 "MACRO200_DUPLICATED_NATIVE_VERDICT:"+rid)
            native[rid]=row
    need(set(native)==set(inv["rules"]),
         "MACRO200_INCOMPLETE_763_NATIVE_RULE_JUDGMENTS")
    out={};counts={"PASS":0,"FAIL":0,"UNKNOWN":0,"FUTURE_PHASE":0,"N_A":0}
    for rid in R122_FROZEN_IDS:
        canonical=inv["rules"][rid]
        need(type(canonical.get("requirement")) is str and
             bool(canonical["requirement"].strip()) and
             hashlib.sha256(canonical["requirement"].encode()).hexdigest()==
                  canonical.get("requirement_sha256") and
             rid in inv["families"].get(canonical.get("family"),()),
             "MACRO200_ORIGINAL_SOURCE_REQUIREMENT_TAMPERED:"+rid)
        item=native[rid]
        due=expected_result(canonical,work["phase"],work["asset_type"],
                            work["profiles"])
        need(item.get("binding_sha256")==judgment_digest(
                  binding(work,canonical,rid)) and
             item.get("expected_applicability")==due,
             "MACRO200_NATIVE_RULE_CONTEXT_OR_SOURCE_REPLAY:"+rid)
        status=item.get("result")
        allowed=(("PASS","FAIL","UNKNOWN") if due=="PASS" else
                 ("FUTURE_PHASE",) if due=="FUTURE_PHASE" else ("N_A",))
        need(status in allowed,
             "MACRO200_RULE_STATE_NOT_SOURCE_DERIVED:"+rid)
        approved=REVIEWED.get(rid)
        spec=plan["enrolled"].get(rid)
        enrolled=bool(approved and spec and
                      spec.get("validator_id")==approved[0] and
                      spec.get("requirement_sha256")==
                          canonical["requirement_sha256"])
        if status=="PASS":
            need(enrolled and item.get("mg0")=="PASS" and
                 SHA.fullmatch(str(item.get("evidence_digest",""))),
                 "MACRO200_POSITIVE_WITHOUT_APPROVED_REPLAYER_AND_MG0:"+rid)
        counts[status]+=1
        outstanding=[]
        if due=="PASS" and not enrolled:
            outstanding.append("APPROVED_SOURCE_SPECIFIC_NATIVE_SEMANTIC_VERIFIER")
        if due=="PASS" and status!="PASS":
            outstanding.extend(("INDEPENDENT_FULL_RULE_VERDICT",
                                "INDEPENDENT_INDIVIDUAL_MG0"))
        if due!="PASS":
            outstanding.append("NOT_DUE_IN_THIS_CANONICAL_CONTEXT")
        out[rid]={
           "rule_id":rid,"family":canonical["family"],
           "source_sha256":canonical["source_sha256"],
           "requirement_sha256":canonical["requirement_sha256"],
           "applicability":due,"reviewed_and_enrolled":enrolled,
           "native_rule_verdict":status,
           "native_individual_mg0":item.get("mg0","UNKNOWN"),
           "native_positive_proof_digest":(
               item.get("evidence_digest") if status=="PASS" else None),
           "missing_independent_semantic_proof":outstanding,
           "full_rule_and_mg0_pass":status=="PASS",
           "advancement_authorized":False,
        }
    need(len(out)==200 and sum(counts.values())==200,
         "MACRO200_NOT_ALL_200_SOURCE_RULES_JUDGED")
    return {
        "schema":SCHEMA,"rule_count":200,
        "cohort_sha256":R122_FROZEN_SHA256,
        "counts":counts,
        "verified_full_semantic_and_mg0_passes":counts["PASS"],
        "reviewed_positive_implementations_enrolled":sum(
            row["reviewed_and_enrolled"] for row in out.values()),
        "all_due_full_semantic_and_mg0_verified":counts["FAIL"]==0 and
             counts["UNKNOWN"]==0 and counts["PASS"]>0,
        "master_sha256":work["master_sha256"],
        "attempt_id":work["attempt_id"],
        "operation_sha256":work["operation_sha256"],
        "native_decision_sha256":fresh["decision_sha256"],
        "advancement_authorized":False,
        "rules":out,
    }

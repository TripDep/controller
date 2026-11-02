"""C07 single-pass FINAL semantic certification rollup for ALL 763 canonical rules.

Run ONLY on the independent, recomputed Git-native post-operation decision,
after the Controller has verified exact-current attempt, original audit, work
scope, and an independent Git run started *after* the operation began.
This module never awards a pass from source coverage, positive component
observations, a green workflow, an audit event label, or a missing MG0.

A source-specific independently replayed Git-native semantic rule packet,
a verified per-rule MG0 packet, and an approved enrollment are all necessary.
No synthetic fixture may be presented as real certification.
"""
import hashlib
import re
from approved_validators import REVIEWED,validate as validate_reviewed
from supervisor_judgment import digest,binding
from family_coverage import expected_result
from c07_positive200_evidence import R122_FROZEN_IDS,R122_FROZEN_SHA256,digest as frozen_digest

SCHEMA="gg-c07-763-independent-post-operation-certification-v1"
SHA=re.compile(r"[a-f0-9]{64}\Z")
class Uncertified(ValueError):pass

def need(ok,reason):
    if not ok:raise Uncertified(reason)

def inspect(inv,plan,work,native):
    """Read-only consumer of independently verified post-run j.judge output."""
    need(type(inv) is dict and inv.get("schema")==
         "gg-effective-family-inventory-v1" and
         inv.get("rule_count")==763 and len(inv.get("rules",{}))==763 and
         len(inv.get("families",{}))==20 and
         inv.get("canonical_master_sha256")==work.get("master_sha256")==
         plan.get("master_sha256") and
         len(R122_FROZEN_IDS)==len(set(R122_FROZEN_IDS))==200 and
         frozen_digest(list(R122_FROZEN_IDS))==R122_FROZEN_SHA256,
         "C07_763_CANONICAL_SOURCE_OR_COHORT_CHANGED")
    need(type(native) is dict and native.get("schema")==
         "gg-process-judgment-v1" and
         native.get("synthetic_backend") is False and
         native.get("rule_count")==763 and
         native.get("attempt_id")==work.get("attempt_id") and
         native.get("operation_sha256")==work.get("operation_sha256") and
         native.get("work_item_sha256")==work.get("work_item_sha256") and
         native.get("master_sha256")==work.get("master_sha256") and
         native.get("phase")==work.get("phase") and
         native.get("decision_sha256")==digest({
             k:v for k,v in native.items() if k!="decision_sha256"}),
         "C07_763_ORIGINAL_POST_NATIVE_DECISION_REQUIRED")
    try:
        validate_reviewed(plan["enrolled"],inv)
    except (KeyError,ValueError,TypeError) as exc:
        raise Uncertified("C07_763_APPROVED_SOURCE_REPLAYER_REQUIRED") from exc
    allrows={}
    for family,rows in native.get("families",{}).items():
        need(family in inv["families"] and type(rows) is dict and
             set(rows)==set(inv["families"][family]),
             "C07_763_NATIVE_FAMILY_INCOMPLETE")
        for rid,data in rows.items():
            need(rid not in allrows and type(data) is dict,
                 "C07_763_DUPLICATE_NATIVE_RULE:"+rid)
            allrows[rid]=data
    need(set(allrows)==set(inv["rules"]),
         "C07_763_INCOMPLETE_NATIVE_SOURCE_COVERAGE")
    groups={}
    counts={"PASS":0,"FAIL":0,"UNKNOWN":0,"FUTURE_PHASE":0,"N_A":0}
    rules={};frozen={"PASS":0,"FAIL":0,"UNKNOWN":0,"FUTURE_PHASE":0,"N_A":0}
    for rid,original in inv["rules"].items():
        need(type(original.get("requirement")) is str and
             bool(original["requirement"].strip()) and
             hashlib.sha256(original["requirement"].encode()).hexdigest()==
                 original.get("requirement_sha256"),
             "C07_763_ORIGINAL_REQUIREMENT_MUTATED:"+rid)
        output=allrows[rid]
        due=expected_result(original,work["phase"],work["asset_type"],
                            work["profiles"])
        need(output.get("binding_sha256")==digest(binding(work,original,rid))
             and output.get("expected_applicability")==due,
             "C07_763_RULE_ATTEMPT_OR_SOURCE_REPLAY:"+rid)
        verdict=output.get("result")
        valid=("PASS","FAIL","UNKNOWN") if due=="PASS" else (
            ("FUTURE_PHASE",) if due=="FUTURE_PHASE" else ("N_A",))
        need(verdict in valid,"C07_763_ORIGINAL_APPLICABILITY_CHANGED:"+rid)
        enrolled_spec=plan["enrolled"].get(rid)
        reviewer=REVIEWED.get(rid)
        approved=bool(reviewer and enrolled_spec and
             enrolled_spec.get("validator_id")==reviewer[0] and
             enrolled_spec.get("requirement_sha256")==original["requirement_sha256"])
        if verdict=="PASS":
            need(approved and output.get("mg0")=="PASS" and
                 SHA.fullmatch(str(output.get("evidence_digest",""))),
                 "C07_763_FALSE_SEMANTIC_OR_INDIVIDUAL_MG0_PASS:"+rid)
        counts[verdict]+=1
        if rid in R122_FROZEN_IDS:frozen[verdict]+=1
        family=original["family"]
        bucket=groups.setdefault(family,{"PASS":0,"FAIL":0,"UNKNOWN":0,
                                         "FUTURE_PHASE":0,"N_A":0})
        bucket[verdict]+=1
        rules[rid]={
           "rule_id":rid,
           "family":family,
           "source_sha256":original["source_sha256"],
           "requirement_sha256":original["requirement_sha256"],
           "due":due,
           "post_native_semantic":verdict,
           "individual_mg0":output.get("mg0","UNKNOWN"),
           "source_specific_reviewer_approved":approved,
           "verified_native_packet_digest":(
               output.get("evidence_digest") if verdict=="PASS" else None),
           "semantically_certified":verdict=="PASS",
           "missing_proof":(
              [] if verdict=="PASS" else
              (["SOURCE_SPECIFIC_NATIVE_REVIEWER"] if due=="PASS" and not approved else [])+
              (["INDEPENDENT_FULL_RULE_AND_MG0"] if due=="PASS" else
               ["OUTSIDE_CURRENT_WORK_PHASE"])),
        }
    need(sum(counts.values())==763 and sum(frozen.values())==200 and
         sum(sum(v.values()) for v in groups.values())==763,
         "C07_763_NATIVE_SOURCE_TOTAL_DRIFT")
    return {
       "schema":SCHEMA,
       "stage":"POST_OPERATION_INDEPENDENT_GIT_READBACK",
       "canonical_rule_count":763,
       "frozen200_rule_count":200,
       "individual_native_and_mg0_certifications":counts["PASS"],
       "first_200_certifications":frozen["PASS"],
       "all_763_approved":counts["PASS"]==763,
       "all_current_due_certified":counts["UNKNOWN"]==0 and
                                   counts["FAIL"]==0,
       "counts":counts,"first_200_counts":frozen,
       "family_counts":groups,
       "native_decision_sha256":native["decision_sha256"],
       "attempt_id":work["attempt_id"],
       "operation_sha256":work["operation_sha256"],
       "master_sha256":work["master_sha256"],
       "original_frozen200_cohort_sha256":R122_FROZEN_SHA256,
       "rules":rules,
       "owner_approval_inferred":False,
       "advancement_authorized":False,
    }

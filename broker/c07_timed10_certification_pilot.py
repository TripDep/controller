"""C07 original 10-rule certification pilot with REAL scoped timing.

Strictly measures a complete SOURCE-CHECK -> MG0-CHECK -> reviewed-verifier
eligibility attempt for the immutable R171..180 group. This is the first
measurement of one macro, not an estimate of remaining person-hours.
The duration measures executing validators; it DOES NOT measure development
time, thinking, human QA, waiting or owner acceptance.

Real work result can be CERTIFIED only if original native full-rule evidence,
independent reviewed native Git replay AND individual owner-authenticated
MG0 all pass; none of those may be fabricated from structural source proofs.
"""
import datetime
import time
from approved_validators import REVIEWED
from c07_mg0_individual import inspect_batch as inspect_mg0
from c07_r171_r180_source_native import IDS,SCHEMA as TEN_SCHEMA,inspect as inspect10
from c07_positive_native_process import sha

SCHEMA="gg-c07-ten-original-rules-measured-certification-pilot-v1"

class PilotBlocked(ValueError):pass
def need(ok,message):
    if not ok:raise PilotBlocked(message)

def measure(inv,plan,controller,asset,step,work,*,source_loader):
    """Use original audited work; inputs cannot be positive self-attestations.

    The source-specific inspector is always called directly from within this
    locked Controller context. For post-open measurements an earlier begin
    decision is not approval of output created later.
    """
    need(type(inv) is dict and inv.get("rule_count")==763 and
         inv.get("schema")=="gg-effective-family-inventory-v1" and
         all(rid in inv.get("rules",{}) for rid in IDS) and
         len(IDS)==10 and type(work) is dict and
         work.get("master_sha256")==inv.get("canonical_master_sha256") and
         callable(source_loader),
         "PILOT10_ORIGINAL_763_CANONICAL_SCOPE_REQUIRED")
    start_utc=datetime.datetime.now(datetime.timezone.utc)
    p0=time.perf_counter_ns()
    r10=inspect10(inv,plan,controller,asset,step,work,
                   source_loader=source_loader)
    p1=time.perf_counter_ns()
    raw_master=controller.master.read_bytes()
    raw_audit=controller.audit_path(asset).read_bytes()
    mg0=inspect_mg0(raw_master,raw_audit,asset,
                    work["master_sha256"],list(IDS),work["attempt_id"])
    p2=time.perf_counter_ns()
    end_utc=datetime.datetime.now(datetime.timezone.utc)
    need(type(r10) is dict and r10.get("schema")==TEN_SCHEMA and
         set(r10.get("rules",{}))==set(IDS) and
         r10.get("source_rules_examined")==r10.get("rule_count")==10 and
         r10.get("attempt_id")==work.get("attempt_id") and
         r10.get("operation_sha256")==work.get("operation_sha256") and
         r10.get("master_sha256")==work.get("master_sha256") and
         r10.get("original_audit_sha256")==sha(raw_audit) and
         r10.get("original_audit_tail")==mg0["audit_tail_sha256"] and
         r10.get("full_rule_passes")==0 and
         r10.get("individual_mg0_passes")==0 and
         r10.get("advancement_authorized") is False and
         mg0["rule_count"]==10 and
         set(mg0.get("rules",{}))==set(IDS) and
         mg0.get("individual_mg0_passes")==0 and
         mg0.get("advancement_authorized") is False and
         isinstance(p0,int) and p0<=p1<=p2,
         "PILOT10_ORIGINAL_NATIVE_MG0_SOURCE_OR_CLOCK_DRIFT")
    # These are independent permissions; absence of enrolled reviewers is a
    # measured blocker, not evidence that an individual rule is "passed".
    results={};counts={"FAIL":0,"UNKNOWN":0,"CERTIFIED":0}
    for rid in IDS:
        row=r10["rules"][rid]
        mg=mg0["rules"][rid]
        need(row.get("rule_id")==rid and
             row.get("source_sha256")==inv["rules"][rid]["source_sha256"] and
             row.get("requirement_sha256")==inv["rules"][rid]["requirement_sha256"] and
             row.get("full_rule_pass") is False and
             row.get("independent_mg0")=="UNKNOWN" and
             mg.get("verdict") in ("FAIL","UNKNOWN"),
             "PILOT10_RULE_SOURCE_OR_INDEPENDENCE_BROKEN:"+rid)
        enrolled=rid in REVIEWED and rid in plan.get("enrolled",{})
        # No native full-rule reviewer in this pilot: these exact rules have
        # only scoped machine evidence, never a complete semantic certification.
        verdict="FAIL" if mg["verdict"]=="FAIL" else "UNKNOWN"
        counts[verdict]+=1
        results[rid]={
            "rule_id":rid,
            "requirement_sha256":inv["rules"][rid]["requirement_sha256"],
            "machine_predicates_observed":len(row["observed_criteria"]),
            "machine_predicates_total":len(row["original_machine_criteria"]),
            "reviewed_native_full_rule_verifier_enrolled":enrolled,
            "independent_rule_mg0":mg["verdict"],
            "certification":verdict,
            "missing":(
                [] if verdict=="FAIL" else
                (["REVIEWED_FULL_RULE_NATIVE_REPLAYER"] if not enrolled else [])+
                ["CURRENT_INDEPENDENT_FULL_RULE_PROOF",
                 "OWNER_AUTHENTICATED_INDIVIDUAL_MG0"]),
        }
    need(sum(counts.values())==10 and counts["CERTIFIED"]==0,
         "PILOT10_FALSE_MG0_OR_FULL_SEMANTIC_CERTIFICATION")
    report={
        "schema":SCHEMA,
        "source_rules":10,"ids":list(IDS),
        "attempt_id":work["attempt_id"],
        "operation_sha256":work["operation_sha256"],
        "master_sha256":work["master_sha256"],
        "original_audit_sha256":sha(raw_audit),
        "original_audit_tail":mg0["audit_tail_sha256"],
        "started_utc":start_utc.isoformat(),
        "ended_utc":end_utc.isoformat(),
        "original_source_validation_ns":p1-p0,
        "mg0_readback_ns":p2-p1,
        "total_measured_execution_ns":p2-p0,
        "duration_scope":"NATIVE_VERIFIER_EXECUTION_ONLY_NOT_ACTIVE_DEVELOPMENT_HOURS",
        "counts":counts,
        "individually_approved_positive_reviewers_enrolled":sum(
            x["reviewed_native_full_rule_verifier_enrolled"]
            for x in results.values()),
        "certifications_per_active_development_hour":None,
        "remaining_763_person_hours":None,
        "reason_no_person_hours":"NO_MEASURED_ACTIVE_DEVELOPMENT_INTERVAL_AND_NO_COMPLETE_CERTIFICATION",
        "advancement_authorized":False,
        "rules":results,
    }
    return report,r10

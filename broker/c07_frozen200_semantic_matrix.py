"""C07 frozen 200: ONE bounded semantic work matrix from original consumers.

Unlike a 200-item source-ID coverage report, this joins actual rule-specific
error/prevention meaning, independently reread machine outcome witnesses,
literal source subclauses, audit counterexamples and individual MG0 status.
The 110 behavior rules are NOT passed by mere absence of known error events.
All 25 EXEC positive scopes use actual R129+outcome readbacks. The remaining
65 original clauses retain R122 exhaustive gap reporting and approved native
positive decision requirements. No claim of full-rule or MG0 completion.
"""
from c07_positive200_evidence import R122_FROZEN_IDS, R122_FROZEN_SHA256,digest
from c07_positive_native_process import _original_attempt,sha

SCHEMA="gg-c07-frozen200-semantic-evidence-reconciliation-v1"
class FullMatrixBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise FullMatrixBlocked(why)

def inspect(inv,plan,controller,asset,step,work,*,semantic200,exec25,
            behavior_first50,behavior_last60,positive200):
    original=R122_FROZEN_IDS
    need(len(original)==len(set(original))==200 and
         digest(list(original))==R122_FROZEN_SHA256 and
         inv.get("schema")=="gg-effective-family-inventory-v1" and
         inv.get("rule_count")==763 and
         len(inv.get("rules",{}))==763 and
         sha(controller.master.read_bytes())==
            inv.get("canonical_master_sha256")==work.get("master_sha256"),
         "C07_MATRIX_ORIGINAL_COHORT_OR_MASTER_CHANGED")
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail and
         (state.get("active_step") or {}).get("step")==step,
         "C07_MATRIX_AUDIT_OR_ORIGINAL_STATE_CHANGED")
    chain={r.get("record_hash") for r in rows}
    inputs=(
        ("NEGATIVE_SEMANTICS",semantic200,200,"original_audit_tail"),
        ("EXEC25_OUTCOMES",exec25,25,"original_audit_tail"),
        ("BEHAVIOR_001_050",behavior_first50,50,"original_audit_tail"),
        ("BEHAVIOR_051_110",behavior_last60,100,"original_audit_tail"),
        ("ORIGINAL_GAPS",positive200,200,"original_controller_audit_tail"),
    )
    for name,data,n,tail_key in inputs:
        need(type(data) is dict and data.get("attempt_id")==work["attempt_id"]
             and data.get("operation_sha256")==work["operation_sha256"]
             and data.get(tail_key) in chain
             and data.get("advancement_authorized") is False
             and type(data.get("rules")) is dict,
             "C07_MATRIX_CROSS_ATTEMPT_OR_SOURCE_REPLAY:"+name)
    need(set(semantic200["rules"])==set(original)
         and set(positive200["rules"])==set(original)
         and set(exec25["rules"])=={"EXEC-%03d"%i for i in range(1,26)}
         and set(behavior_first50["rules"])=={
             "BEHAVIOR-%03d"%i for i in range(1,51)}
         and set(behavior_last60["rules"]).issuperset({
             "BEHAVIOR-%03d"%i for i in range(51,111)})
         and semantic200["individual_mg0_passes"]==0
         and exec25["individual_mg0_passes"]==0
         and positive200["individual_mg0_passes"]==0,
         "C07_MATRIX_REQUIRED_AUTHENTIC_200_SOURCE_OR_MG0")
    result={};seen={"BEHAVIOR":0,"EXEC":0,"OTHER":0};observed=0
    for rid in original:
        row=inv["rules"][rid]
        bad=semantic200["rules"][rid]
        gaps=positive200["rules"][rid]
        need(bad.get("rule_id")==rid and
             bad.get("source_sha256")==row["source_sha256"] and
             bad.get("requirement_sha256")==row["requirement_sha256"] and
             gaps.get("rule_id")==rid and
             gaps.get("requirement_sha256")==row["requirement_sha256"] and
             gaps.get("source_sha256")==row["source_sha256"] and
             bad.get("semantic_result") in ("FAIL","UNKNOWN") and
             bad.get("current_attempt_mg0_result") in ("FAIL","UNKNOWN") and
             gaps.get("full_semantics")=="UNKNOWN" and
             gaps.get("individual_mg0")=="UNKNOWN" and
             gaps.get("work_pass") is False,
             "C07_MATRIX_SOURCE_OR_SEMANTIC_FAKED:"+rid)
        source=bad["original_required_prevention"]
        if rid.startswith("BEHAVIOR-"):
            seen["BEHAVIOR"]+=1
            data=(behavior_first50["rules"].get(rid) if
                  int(rid.split("-")[-1])<=50 else
                  behavior_last60["rules"].get(rid))
            need(type(data) is dict and
                 data.get("rule_id")==rid and
                 data.get("source_sha256")==row["source_sha256"] and
                 data.get("requirement_sha256")==row["requirement_sha256"] and
                 bad.get("semantic_kind")=="ERROR_PREVENTION" and
                 type(bad.get("original_prohibited_error")) is str and
                 bool(bad["original_prohibited_error"]) and
                 type(source) is str and bool(source),
                 "C07_MATRIX_BEHAVIOR_ERROR_VS_PREVENTION_MISSING:"+rid)
            observations=(data.get("original_machine_checks") if
                           rid in behavior_first50["rules"] else
                           data.get("original_native_criteria"))
            need(type(observations) is dict and
                 len(observations)==3 and
                 all(type(v) is bool for v in observations.values()),
                 "C07_MATRIX_BEHAVIOR_MEANING_NOT_MACHINE_CHECKED:"+rid)
        elif rid.startswith("EXEC-"):
            seen["EXEC"]+=1
            data=exec25["rules"].get(rid)
            need(type(data) is dict and
                 data.get("rule_id")==rid and
                 data.get("source_sha256")==row["source_sha256"] and
                 data.get("requirement_sha256")==row["requirement_sha256"] and
                 bad.get("semantic_kind")=="EXECUTION_REQUIREMENT" and
                 type(source) is str and bool(source),
                 "C07_MATRIX_EXEC_LITERAL_ORIGINAL_INCOMPLETE:"+rid)
            observations=data.get("independent_outcome_checks")
            need(type(observations) is dict and len(observations)==2 and
                 all(type(v) is bool for v in observations.values()),
                 "C07_MATRIX_EXEC_POSITIVE_ACTUAL_OUTCOME_MISSING:"+rid)
        else:
            seen["OTHER"]+=1
            need(bad.get("semantic_kind")==
                    "CANONICAL_GOVERNANCE_OR_ASSET",
                 "C07_MATRIX_65_LITERAL_SOURCE_INCOMPLETE:"+rid)
            observations={
                "machine_scope_observed":gaps["machine_scoped_positive_observed"],
                "original_subclauses_registered":gaps["canonical_clause_count"]>=1,
                "original_source_decomposition_reviewed":gaps["source_decomposition"]
                     not in ("SINGLE_SOURCE_OBLIGATION_REVIEW_PENDING",
                             "EXACT_110_SOURCE_ITEMS_NOT_YET_REVIEWED"),
            }
            need(all(type(v) is bool for v in observations.values()),
                 "C07_MATRIX_SOURCE_CLAUSE_PROBES_NOT_BOOLEAN:"+rid)
        observed+=sum(observations.values())
        result[rid]={
            "rule_id":rid,
            "family":row["family"],
            "source_sha256":row["source_sha256"],
            "requirement_sha256":row["requirement_sha256"],
            "original_semantic_obligation":source,
            "source_specific_positive_components":observations,
            "original_counterexample_status":bad["semantic_result"],
            "individual_mg0":bad["current_attempt_mg0_result"],
            "full_rule_semantics":bad["semantic_result"],
            "original_full_clause_gaps":gaps["missing_evidence"],
            "semantic_decision":"FAIL" if bad["semantic_result"]=="FAIL" else "UNKNOWN",
            "owner_acceptance":"UNKNOWN",
            "advancement_authorized":False,
        }
    need(seen=={"BEHAVIOR":110,"EXEC":25,"OTHER":65} and
         len(result)==200 and all(not row["advancement_authorized"]
         for row in result.values()),
         "C07_MATRIX_110_25_65_REAL_SEMANTICS_NOT_COMPLETE")
    return {
       "schema":SCHEMA,"source_rule_count":200,
       "original_audit_sha256":audit_sha,
       "original_audit_tail":tail,
       "attempt_id":work["attempt_id"],
       "operation_sha256":work["operation_sha256"],
       "source_groups":seen,
       "source_specific_positive_components_observed":observed,
       "full_semantic_passes":0,"individual_mg0_passes":0,
       "current_failures":sum(v["semantic_decision"]=="FAIL" for v in result.values()),
       "current_unknowns":sum(v["semantic_decision"]=="UNKNOWN" for v in result.values()),
       "advancement_authorized":False,"rules":result,
    }

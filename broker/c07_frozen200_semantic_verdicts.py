"""C07 first frozen 200: source-exact semantic counterexample adjudication.

Unlike a file/sha/green-CI coverage report, this consumer evaluates actual
rule-specific original failures, correction state, and source semantics. The
110 original "Errore -> prevenzione" rules are kept as *two different
obligations*, not collapsed into presence of a file. Master/EXEC/AAA rules
preserve the original full clause. A FAIL is allowed only when a real
exact-attempt negative audit record or independent MG0 negative exists.
No "no failures found" => PASS. No synthetic-positive or reviewer spoofing.
"""
import hashlib
import re

from c07_positive200_evidence import (
    R122_FROZEN_IDS, R122_FROZEN_SHA256, digest
)
from c07_positive_native_process import (
    _original_attempt, _registered_artifacts, sha
)
from c07_behavior_110 import parse_registry
from c07_mg0_individual import inspect_batch as inspect_mg0_batch
from real_work_intake import audit_check

SCHEMA="gg-c07-frozen200-semantic-counterexample-v1"
FAIL_EVENTS=frozenset((
    "QUALITY_FINDING", "VERIFIED_STATE_REVOKED",
    "SUPERVISOR_RULE_FAILURE", "SUPERVISOR_NATIVE_SEMANTIC_FAIL",
    "USER_REVIEW"
))
class Semantic200Blocked(ValueError):pass
def need(condition,code):
    if not condition:raise Semantic200Blocked(code)

def _semantic_source(row,rid):
    """Derive two *meaningful* source obligations for a BEHAVIOR rule."""
    text=row["requirement"]
    if rid.startswith("BEHAVIOR-"):
        hit=re.fullmatch(r"Errore: (.+?) → (.+)",text)
        need(hit is not None,"SEM200_ERROR_PREVENTION_MISSING:"+rid)
        return {
          "kind":"ERROR_PREVENTION",
          "prohibited_failure":hit.group(1),
          "required_prevention":hit.group(2),
          "semantic_target":hit.group(2),
        }
    if rid.startswith("EXEC-"):
        # EXEC is a whole, imperative original clause; we do not infer that
        # a matching keyword proves execution of its intended meaning.
        cleaned=re.sub(r"\*\*VERIFIED_FILE\.\*\*\s*","",text).strip()
        need(bool(cleaned),"SEM200_EMPTY_EXEC_SOURCE:"+rid)
        return {
          "kind":"EXECUTION_REQUIREMENT",
          "prohibited_failure":None,
          "required_prevention":cleaned,
          "semantic_target":cleaned,
        }
    need(type(text) is str and bool(text.strip()),
         "SEM200_EMPTY_ORIGINAL_SOURCE:"+rid)
    return {
       "kind":"CANONICAL_GOVERNANCE_OR_ASSET",
       "prohibited_failure":None,
       "required_prevention":text,
       "semantic_target":text,
    }

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(callable(source_loader),"SEM200_ORIGINAL_FILE_READER_REQUIRED")
    cohort=R122_FROZEN_IDS
    need(len(cohort)==len(set(cohort))==200
         and digest(list(cohort))==R122_FROZEN_SHA256
         and inventory.get("schema")=="gg-effective-family-inventory-v1"
         and inventory.get("rule_count")==763
         and len(inventory.get("rules",{}))==763
         and set(cohort)<=set(inventory["rules"]),
         "SEM200_FROZEN_200_CANONICAL_COHORT_CHANGED")
    original_master=controller.master.read_bytes()
    need(sha(original_master)==inventory.get("canonical_master_sha256")
         ==work.get("master_sha256")==plan.get("master_sha256"),
         "SEM200_MASTER_ORIGIN_CHANGED")
    for rid in cohort:
        row=inventory["rules"][rid]
        need(type(row) is dict and
             type(row.get("requirement")) is str and
             sha(row["requirement"].encode("utf-8"))==row.get("requirement_sha256")
             and row.get("family") in inventory["families"] and
             rid in inventory["families"][row["family"]] and
             row.get("source_sha256")==inventory["source_digests"].get(row.get("source")),
             "SEM200_ORIGINAL_CLAUSE_CHANGED:"+rid)
    records,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail and
         (state.get("active_step") or {}).get("step")==step,
         "SEM200_ORIGINAL_AUDIT_STATE_DRIFT")
    registered=_registered_artifacts(records,state,step,source_loader,work)
    provenance={digest for _,_,digest,_ in registered}
    # Keep original-current attempt failures separate from prior failures and
    # from unverified producer-supplied declarations. Original audit chain is
    # already read and authenticated by _original_attempt.
    relevant=[r for r in records if
        r.get("attempt_id")==work["attempt_id"] and
        r.get("operation_sha256")==work["operation_sha256"] and
        r.get("step")==step]
    fail_by_id={}
    for event in relevant:
        rid=event.get("rule_id")
        if rid not in cohort or event.get("event") not in FAIL_EVENTS:
            continue
        if event.get("result") not in ("FAIL","BLOCKED"):
            continue
        # An event alone can prove a *reported* negative. Actual semantic
        # failure requires an ORIGINAL artifact source matched to that exact
        # rule, and a source clause digest proving which requirement failed.
        if event.get("requirement_sha256")!=inventory["rules"][rid]["requirement_sha256"]:
            continue
        artifact=event.get("artifact_sha256")
        if artifact not in provenance:
            continue
        fail_by_id.setdefault(rid,[]).append(event["record_hash"])
    # All 200 individual MG0s are assessed from one original chain. MG0
    # negative findings can indicate failure; missing MG0 is never PASS.
    mg0=inspect_mg0_batch(
        original_master,controller.audit_path(asset).read_bytes(),asset,
        work["master_sha256"],list(cohort),work["attempt_id"])
    need(mg0.get("rule_count")==200 and set(mg0.get("rules",{}))==set(cohort)
         and mg0.get("individual_mg0_passes")==0
         and mg0.get("advancement_authorized") is False,
         "SEM200_ORIGINAL_INDEPENDENT_MG0_READBACK_REQUIRED")
    statuses={}
    for rid in cohort:
        original=inventory["rules"][rid]
        source=_semantic_source(original,rid)
        observed_failures=sorted(set(fail_by_id.get(rid,())))
        mg0_status=mg0["rules"][rid]["verdict"]
        need(mg0_status in ("FAIL","UNKNOWN"),
             "SEM200_UNVERIFIED_MG0_POSITIVE:"+rid)
        status="FAIL" if observed_failures or mg0_status=="FAIL" else "UNKNOWN"
        statuses[rid]={
          "rule_id":rid,"family":original["family"],
          "source_sha256":original["source_sha256"],
          "requirement_sha256":original["requirement_sha256"],
          "semantic_kind":source["kind"],
          "original_prohibited_error":source["prohibited_failure"],
          "original_required_prevention":source["required_prevention"],
          "semantic_target_sha256":sha(source["semantic_target"].encode("utf-8")),
          "current_attempt_original_counterexample_hashes":observed_failures,
          "current_attempt_mg0_result":mg0_status,
          "semantic_result":status,
          "semantic_reason":(
              "AUTHENTIC_ORIGINAL_RULE_SPECIFIC_FAILURE"
              if observed_failures else
              "INDIVIDUAL_MG0_UNRESOLVED_FAILURE"
              if mg0_status=="FAIL" else
              "FULL_PREVENTION_AND_INDEPENDENT_PROOF_NOT_YET_ESTABLISHED"),
          "required_to_certify":(
              "INDEPENDENT_SOURCE_SPECIFIC_NATIVE_VERIFIER_AND_INDIVIDUAL_MG0"),
          "independent_positive_semantics":"UNKNOWN",
          "owner_approval":"UNKNOWN",
          "advancement_authorized":False,
        }
    need(len(statuses)==200 and
         len({row["semantic_target_sha256"]+rid
              for rid,row in statuses.items()})==200
         and all(row["semantic_result"] in ("FAIL","UNKNOWN")
                 and row["advancement_authorized"] is False
                 for row in statuses.values()),
         "SEM200_FIRST_200_ACTUAL_OBLIGATIONS_UNRESOLVED")
    return {
      "schema":SCHEMA,"source_rules_evaluated":200,
      "behavior_prevention_obligations":sum(
          row["semantic_kind"]=="ERROR_PREVENTION"
          for row in statuses.values()),
      "exec_obligations":sum(
          row["semantic_kind"]=="EXECUTION_REQUIREMENT"
          for row in statuses.values()),
      "original_audit_sha256":audit_sha,
      "original_audit_tail":tail,
      "attempt_id":work["attempt_id"],
      "operation_sha256":work["operation_sha256"],
      "semantic_failures":sum(x["semantic_result"]=="FAIL" for x in statuses.values()),
      "semantic_unknowns":sum(x["semantic_result"]=="UNKNOWN" for x in statuses.values()),
      "semantic_positive_passes":0,
      "individual_mg0_passes":0,
      "advancement_authorized":False,
      "rules":statuses,
    }

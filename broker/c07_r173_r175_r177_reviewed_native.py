"""C07 P0 original source process validators R173, R175 and R177.

Independently reruns original Controller-source and hash-chain proofs. R173
requires immutable Git retrieval of actual edited *source*, not a Git mention.
R175 recomputes both durations and output identity; machine timing is only a
bounded, relative benefit observation, never financial/owner signoff.
R177 reopens the originally recorded approved baseline and distinct post-
automation copy byte-for-byte, not just an APPROVED event.

Never certify the individual MG0 or the owner's identity. Missing independent
observations always remain UNKNOWN and do not advance the operation.
"""
from datetime import datetime
import hashlib
from pathlib import Path
import re
from urllib.parse import quote

from c07_r171_r180_source_native import (
    inspect as inspect_ten,CLAUSES,SCHEMA as TEN_SCHEMA,
)
from c07_positive_native_process import (
    _original_attempt,_registered_artifacts,sha,
)
from c07_r171_r180_positive_source_oracles import (
    automation_preserved_approved_bytes,native_script_output_matches_oracle)
from glb_machine_qa import audit_bytes,GLBError
from family_coverage import SOURCES
import supervisor_judgment as j

VALIDATOR="GG_C07_R173_R175_R177_ACTUAL_SOURCE_REPLAY_V1"
IDS=("AAA-200-R-173","AAA-200-R-175","AAA-200-R-177")
SOURCE_KEYS={
 "AAA-200-R-173":(
    "protected_editable_original_bytes_present",
    "original_version_audit_chain_contains_exact_attempt",
    "independent_version_storage_readback",
    "baseline_before_current_change_available"),
 "AAA-200-R-175":(
    "repeated_checks_performed_on_exact_attempt",
    "distinct_recorded_check_runs",
    "original_output_not_only_exit_status",
    "measured_net_benefit_independently_proven"),
 "AAA-200-R-177":(
    "existing_approved_copy_reopened",
    "copy_sha_does_not_equal_changed_current_output",
    "original_approved_bytes_rechecked",
    "independent_pre_and_post_approved_copy_hashes_equal"),
}
EXTRA={
 "AAA-200-R-173":(
    "actual_original_source_bytes_in_immutable_git",
    "previous_version_original_bytes_in_distinct_immutable_git_commit"),
 "AAA-200-R-175":(
    "manual_and_automated_runs_all_bind_verified_binary",
    "two_actual_automated_runs_faster_than_manual_baseline"),
 "AAA-200-R-177":(
    "original_and_post_approved_source_reopened_equal",
    "baseline_original_unchanged_after_current_automation"),
}
CRITERIA={rid:SOURCE_KEYS[rid]+EXTRA[rid] for rid in IDS}
CATALOG_PATH=SOURCES["aaa_catalog"]
class RemainderBlocked(ValueError):pass
def need(v,msg):
    if not v:raise RemainderBlocked(msg)

def _one(items,role):
    matches=items.get(role,())
    return matches[0] if len(matches)==1 else None

def _bound(event,work,step):
    return (event.get("step")==step and
            event.get("attempt_id")==work.get("attempt_id") and
            event.get("operation_sha256")==work.get("operation_sha256"))

def _relative_seconds(start,finish):
    def stamp(t):
        if type(t) is not str:return None
        try:
            value=datetime.fromisoformat(t.replace("Z","+00:00"))
            return value.timestamp() if value.tzinfo else None
        except (ValueError,OverflowError):return None
    a=stamp(start);b=stamp(finish)
    return b-a if a is not None and b is not None and b>a else None

def measured_repeated_automation(records,work,step,export_hash):
    """Measured machine-positive benefit, not producer assertion of savings.

    Compare two *individually bound* actual automation runs to the original
    manual QA baseline on the identical authenticated output. A RUN_FINISHED
    record on a different binary/run/work attempt is not comparable.
    """
    groups={}
    for row in records:
        if (not _bound(row,work,step) or
            row.get("event") not in ("QA_RUN_STARTED","QA_RUN_FINISHED")):
            continue
        key=row.get("run_id")
        if type(key) is not str or re.fullmatch("[a-f0-9]{64}",key) is None:
            return False
        if row.get("output_sha256")!=export_hash or row.get("result")=="FAIL":
            return False
        groups.setdefault(key,[]).append(row)
    if len(groups)!=3:return False
    elapsed={}
    for key,rows in groups.items():
        starts=[r for r in rows if r["event"]=="QA_RUN_STARTED"]
        ends=[r for r in rows if r["event"]=="QA_RUN_FINISHED"]
        if len(rows)!=2 or len(starts)!=len(ends)!=1:return False
        if len(starts)!=1 or len(ends)!=1:return False
        if ends[0].get("result")!="PASS":return False
        kind=starts[0].get("run_kind")
        if kind not in ("MANUAL_QA_BASELINE","AUTOMATED_QA"):return False
        if ends[0].get("run_kind")!=kind:return False
        duration=_relative_seconds(starts[0].get("timestamp_utc"),
                                   ends[0].get("timestamp_utc"))
        if duration is None:return False
        elapsed[key]=(kind,duration)
    baseline=[d for kind,d in elapsed.values() if kind=="MANUAL_QA_BASELINE"]
    automatic=[d for kind,d in elapsed.values() if kind=="AUTOMATED_QA"]
    return (len(baseline)==1 and len(automatic)==2 and
            baseline[0]>max(automatic) and
            2*baseline[0]>sum(automatic))

def original_immutable_git_versions(api,records,by_role,work,step):
    """Verify original editable current and prior source binaries in Git.

    Mere Git SHA in Controller audit is not version evidence; fetch immutable
    exact source bytes from two independent commit refs, reread their original
    corresponding Controller source and verify both registered SHA256s.
    """
    from broker_live_review import decode_file
    current=_one(by_role,"SOURCE_EDITABLE")
    historical=_one(by_role,"SOURCE_VERSION_BASELINE")
    if current is None or historical is None or current[1]==historical[1]:
        return False
    versions=[r for r in records if
        r.get("event")=="SOURCE_VERSION_INDEPENDENTLY_VERIFIED" and
        _bound(r,work,step) and r.get("result")=="PASS"]
    if len(versions)!=1:return False
    row=versions[0];path=row.get("repo_path")
    ref=row.get("current_git_ref");previous=row.get("previous_git_ref")
    if not (type(path) is str and path and
            path==path.strip("/") and
            not any(p in ("",".","..") for p in path.split("/")) and
            "\\" not in path and
            type(ref) is str and re.fullmatch("[a-f0-9]{40}",ref) and
            type(previous) is str and re.fullmatch("[a-f0-9]{40}",previous) and
            ref!=previous and
            row.get("original_current_sha256")==current[1] and
            row.get("original_previous_sha256")==historical[1]):
        return False
    escaped="/".join(quote(p,safe="") for p in path.split("/"))
    try:
        fetched_current=decode_file(api.call(
            "GET","/contents/"+escaped+"?ref="+ref),path)
        fetched_previous=decode_file(api.call(
            "GET","/contents/"+escaped+"?ref="+previous),path)
    except (KeyError,TypeError,ValueError,AttributeError,OSError):
        return False
    return (type(fetched_current) is bytes and
            type(fetched_previous) is bytes and
            fetched_current==current[2] and
            fetched_previous==historical[2] and
            sha(fetched_current)==current[1] and
            sha(fetched_previous)==historical[1])

def _replay(context,rid,expected,api):
    need(type(context) is dict and set(context)=={
            "inventory","plan","controller","asset","step","work","source_loader"}
         and rid in IDS and callable(context["source_loader"]),
         "R173_R175_R177_LOCAL_ORIGINAL_CONTEXT_REQUIRED")
    inv=context["inventory"];plan=context["plan"];work=context["work"]
    row=inv.get("rules",{}).get(rid,{})
    need(inv.get("schema")=="gg-effective-family-inventory-v1" and
         inv.get("rule_count")==763 and
         row.get("requirement")==CLAUSES[int(rid[-3:])] and
         row.get("requirement_sha256")==sha(
             CLAUSES[int(rid[-3:])].encode("utf-8")) and
         expected==j.binding(work,row,rid) and
         plan.get("master_sha256")==work.get("master_sha256")==
             inv.get("canonical_master_sha256"),
         "R173_R175_R177_CANONICAL_SOURCE_OR_OPERATION_CHANGED")
    ctl=context["controller"];asset=context["asset"];step=context["step"]
    report=inspect_ten(inv,plan,ctl,asset,step,work,
                       source_loader=context["source_loader"])
    need(report.get("schema")==TEN_SCHEMA and
         report.get("source_rules_examined")==report.get("rule_count")==10 and
         report.get("attempt_id")==work["attempt_id"] and
         report.get("operation_sha256")==work["operation_sha256"] and
         report.get("full_rule_passes")==0 and
         report.get("individual_mg0_passes")==0 and
         report.get("advancement_authorized") is False,
         "R173_R175_R177_SOURCE_INSPECT_NOT_INDEPENDENT")
    records,tail,state,audit_sha=_original_attempt(
        inv,plan,ctl,asset,step,work)
    need(report["original_audit_sha256"]==audit_sha and
         report["original_audit_tail"]==tail and
         sha(ctl.master.read_bytes())==work["master_sha256"],
         "R173_R175_R177_CONTROLLER_ORIGINAL_CHANGED")
    artifacts=_registered_artifacts(
        records,state,step,context["source_loader"],work)
    by_role={}
    for role,path,digest,raw in artifacts:
        by_role.setdefault(role,[]).append((Path(path),digest,raw))
    original=report["rules"][rid]
    checks=original["original_machine_criteria"]
    need(original["source_sha256"]==row["source_sha256"] and
         original["requirement_sha256"]==row["requirement_sha256"] and
         original["full_rule_pass"] is False and
         original["independent_mg0"]=="UNKNOWN" and
         set(checks)==set(SOURCE_KEYS[rid]),
         "R173_R175_R177_RULE_SOURCE_BROKEN")
    n=int(rid[-3:])
    if n==173:
        source=_one(by_role,"SOURCE_EDITABLE")
        history=_one(by_role,"SOURCE_VERSION_BASELINE")
        independent=original_immutable_git_versions(
            api,records,by_role,work,step)
        checks=dict(checks,independent_version_storage_readback=independent)
        extra={
            "actual_original_source_bytes_in_immutable_git":
                independent and source is not None,
            "previous_version_original_bytes_in_distinct_immutable_git_commit":
                independent and history is not None,
        }
    elif n==175:
        export=_one(by_role,"NATIVE_EXPORT")
        measurements=(export is not None and measured_repeated_automation(
            records,work,step,export[1]))
        # Measured time on a file is not a benefit if the output never
        # passed the originally enrolled *binary* acceptance contract.
        actual=_one(by_role,"NATIVE_REIMPORT")
        binary_ok=bool(actual and
                       native_script_output_matches_oracle(plan,by_role))
        benefit=bool(measurements and binary_ok)
        checks=dict(checks,measured_net_benefit_independently_proven=benefit)
        qa=[r for r in records if
            _bound(r,work,step) and
            r.get("event")=="NATIVE_OUTPUT_INDEPENDENT_QA" and
            type(r.get("evidence_operation")) is dict and
            export is not None and
            r["evidence_operation"].get("artifact_sha256")==export[1]]
        extra={
            "manual_and_automated_runs_all_bind_verified_binary":
                bool(benefit and qa),
            "two_actual_automated_runs_faster_than_manual_baseline":
                bool(benefit),
        }
    else:
        original_copy=_one(by_role,"BASELINE_SNAPSHOT")
        protected=_one(by_role,"APPROVED_COPY_POST_AUTOMATION")
        remains=automation_preserved_approved_bytes(
            records,by_role,work,step)
        after=[r for r in records if
            r.get("event")=="APPROVED_ORIGINAL_BYTES_RECHECKED" and
            _bound(r,work,step) and
            r.get("approved_original_sha256")==(
                original_copy[1] if original_copy else None)]
        extra={
            "original_and_post_approved_source_reopened_equal":
                bool(remains and protected and original_copy and
                     original_copy[2]==protected[2]),
            "baseline_original_unchanged_after_current_automation":
                bool(remains and len(after)==1),
        }
    merged={**checks,**extra}
    need(set(merged)==set(CRITERIA[rid]) and
         all(type(v) is bool for v in merged.values()),
         "R173_R175_R177_SOURCE_SPECIFIC_CRITERIA_MISSING")
    return report,merged

def packet_for_original(context,rid,expected,api):
    report,checks=_replay(context,rid,expected,api)
    return {
      "schema":"gg-semantic-rule-v1",
      "scope":j.SEMANTIC_SCOPE,
      "validator_id":VALIDATOR,
      "binding":expected,
      "rule":{"result":"PASS" if all(checks.values()) else "UNKNOWN",
              "checks":checks,
              "proof_digest":j.digest({
                   "rule":rid,"source":expected["requirement_sha256"],
                   "attempt":expected["attempt_id"],
                   "audit":report["original_audit_sha256"],
                   "audit_tail":report["original_audit_tail"],
                   "original_source_checks":checks})},
      "mg0":{"binding":expected,"triggered":None,
             "result":"UNKNOWN",
             "checks":{"canonical_triggers_checked":False},
             "proof_digest":j.digest({
                "rule":rid,"attempt":expected["attempt_id"],
                "reason":"NO_INDEPENDENT_AUTHENTICATED_INDIVIDUAL_MG0"})},
    }

def native_rule_readback(api,packet,expected,spec,context):
    from broker_live_review import decode_file
    rid=expected.get("rule_id")
    need(rid in IDS and
         type(context) is dict and
         set(context)=={
            "inventory","plan","controller","asset","step","work","source_loader"} and
         spec.get("validator_id")==VALIDATOR and
         set(spec.get("criteria",()))==set(CRITERIA[rid]) and
         re.fullmatch("[a-f0-9]{40}",str(spec.get("source_ref",""))),
         "R173_R175_R177_REVIEWER_ORIGINAL_REQUIRED")
    raw=decode_file(api.call(
        "GET","/contents/"+CATALOG_PATH+"?ref="+spec["source_ref"]),
        CATALOG_PATH)
    need(sha(raw)==context["inventory"].get("source_digests",{}).get("aaa_catalog"),
         "R173_R175_R177_PRIVATE_CANONICAL_CATALOG_DRIFT")
    actual=packet_for_original(context,rid,expected,api)
    need(actual==packet and
         actual["mg0"]["result"]=="UNKNOWN" and
         actual["mg0"]["triggered"] is None,
         "R173_R175_R177_PRODUCER_SOURCE_OR_MG0_UNTRUSTED")
    return {"rule_id":rid,"literal_semantics":actual["rule"]["result"],
            "individual_mg0":"UNKNOWN","advancement_authorized":False}

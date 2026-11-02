"""C07 four original source-specific positive semantic consumers: R171/176/179/180.

This is the FULL *literal source-process obligation* reviewer for four clauses,
not asset acceptance, owner approval, runtime QA, correction signoff, or MG0.
All claims are rerun from original byte-authenticated Controller and immutable
private AAA catalog. Missing data remains UNKNOWN. No source/QA bytes go to Git.
"""
import hashlib
import json
import re
from pathlib import Path

from c07_r171_r180_source_native import (
    inspect as native_ten, CLAUSES as ORIGINAL_CLAUSES,
    SCHEMA as TEN_SCHEMA,
)
from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from c07_r171_r180_positive_source_oracles import (
    native_script_output_matches_oracle,
    real_checkpoint_restored_without_duplicate,
    _mesh_signature,
)
from glb_machine_qa import audit_bytes,GLBError,MAX_BYTES
from family_coverage import SOURCES
import supervisor_judgment as j

VALIDATOR="GG_C07_R171_R176_R179_R180_NATIVE_LITERAL_REPLAYER_V1"
CATALOG_PATH=SOURCES["aaa_catalog"]
SOURCE_KEYS={
 "AAA-200-R-171":(
    "registered_original_editable_bytes",
    "editable_file_names_unique_and_structurally_valid",
    "roles_not_inferred_from_document_names",
    "original_source_paths_are_distinct"),
 "AAA-200-R-176":(
    "original_export_output_bytes_sha_verified",
    "current_script_result_checked_against_binary_reimport",
    "original_native_qa_event_recorded",
    "expected_result_oracle_independently_verified"),
 "AAA-200-R-179":(
    "actual_prior_checkpoint_exists",
    "recovery_event_matches_exact_current_attempt",
    "original_previous_and_current_operations_different",
    "checkpoint_bytes_and_no_duplicate_work_independently_replayed"),
 "AAA-200-R-180":(
    "current_original_model_export_exists",
    "registered_output_is_new_original_model_bytes",
    "real_output_differs_from_registered_original_baseline",
    "progress_not_derived_from_document_event_count"),
}
EXTRA_KEYS={
 "AAA-200-R-171":(
    "editable_original_anchored_to_active_root",
    "role_paths_distinct_under_active_root"),
 "AAA-200-R-176":(
    "preauthorized_numeric_criteria_and_mesh_reimport",
    "current_attempt_native_qa_audit_binds_binary"),
 "AAA-200-R-179":(
    "historical_checkpoint_original_bytes_independently_read",
    "current_restore_unreplayed_operation"),
 "AAA-200-R-180":(
    "original_and_baseline_glb_valid_geometry",
    "actual_geometric_change_not_document_count"),
}
CRITERIA={rid:SOURCE_KEYS[rid]+EXTRA_KEYS[rid] for rid in SOURCE_KEYS}
class OriginalSemanticsBlocked(ValueError):pass
def need(v,why):
    if not v:raise OriginalSemanticsBlocked(why)

def _one(roles,role):
    x=roles.get(role,())
    return x[0] if len(x)==1 else None

def _original(context,rid,expected):
    need(type(context) is dict and set(context)=={
        "inventory","plan","controller","asset","step","work","source_loader"}
        and callable(context["source_loader"]) and rid in CRITERIA,
        "R171_176_179_180_ORIGINAL_LOCKED_CONTROLLER_CONTEXT_REQUIRED")
    inv=context["inventory"];work=context["work"];plan=context["plan"]
    n=int(rid.rsplit("-",1)[-1])
    row=inv.get("rules",{}).get(rid,{})
    need(inv.get("schema")=="gg-effective-family-inventory-v1" and
         inv.get("rule_count")==763 and
         row.get("requirement")==ORIGINAL_CLAUSES[n] and
         row.get("requirement_sha256")==sha(
             ORIGINAL_CLAUSES[n].encode("utf-8")) and
         expected==j.binding(work,row,rid) and
         plan.get("master_sha256")==work.get("master_sha256")==
         inv.get("canonical_master_sha256"),
         "R171_176_179_180_CANONICAL_SOURCE_AND_ATTEMPT_REQUIRED")
    c=context["controller"];asset=context["asset"];step=context["step"]
    report=native_ten(inv,plan,c,asset,step,work,
                      source_loader=context["source_loader"])
    need(report.get("schema")==TEN_SCHEMA and
         report.get("rule_count")==10 and
         report.get("source_rules_examined")==10 and
         report.get("attempt_id")==work["attempt_id"] and
         report.get("operation_sha256")==work["operation_sha256"] and
         report.get("master_sha256")==work["master_sha256"] and
         report.get("full_rule_passes")==0 and
         report.get("individual_mg0_passes")==0 and
         report.get("advancement_authorized") is False,
         "R171_176_179_180_SOURCE_REPLAYER_SCOPE_CHANGED")
    records,tail,state,audit_sha=_original_attempt(
        inv,plan,c,asset,step,work)
    need(report["original_audit_sha256"]==audit_sha and
         report["original_audit_tail"]==tail and
         sha(c.master.read_bytes())==work["master_sha256"],
         "R171_176_179_180_CURRENT_ORIGINAL_AUDIT_DRIFT")
    artifacts=_registered_artifacts(
        records,state,step,context["source_loader"],work)
    by_role={}
    for role,path,digest,raw in artifacts:
        by_role.setdefault(role,[]).append((Path(path),digest,raw))
    base=report["rules"][rid]
    standard=base.get("original_machine_criteria")
    need(base.get("source_sha256")==row["source_sha256"] and
         base.get("requirement_sha256")==expected["requirement_sha256"] and
         type(standard) is dict and
         set(standard)==set(SOURCE_KEYS[rid]) and
         all(type(v) is bool for v in standard.values()) and
         base.get("independent_mg0")=="UNKNOWN" and
         base.get("full_rule_pass") is False,
         "R171_176_179_180_MACHINE_OBSERVATION_CHANGED")
    def good_glb(item):
        if (not item or item[0].suffix.lower()!=".glb" or
            type(item[2]) is not bytes or not 0<len(item[2])<=MAX_BYTES):
            return None
        try:
            measured=audit_bytes(item[2])
            signature=_mesh_signature(item[2])
            return signature if (
                signature and measured["triangles_examined"]>0 and
                not measured["errors"] and
                measured["machine_evidence_status"]==
                    "NO_FATAL_STRUCTURAL_DEFECT_DETECTED") else None
        except (GLBError,ValueError,TypeError,KeyError,IndexError,OverflowError):
            return None

    extra={}
    if n==171:
        sources=by_role.get("SOURCE_EDITABLE",[])
        root=getattr(c,"root",None)
        def in_root(item):
            if not isinstance(root,Path):return False
            p=item[0]
            return (p.is_absolute() and p.resolve().is_relative_to(root.resolve())
                    and not p.is_symlink() and p.is_file() and
                    p.read_bytes()==item[2] and
                    sha(item[2])==item[1])
        kinds=("SOURCE_EDITABLE","NATIVE_EXPORT","DELIVERY_PACKAGE")
        role_paths=[a[0] for k in kinds for a in by_role.get(k,())]
        extra={
            "editable_original_anchored_to_active_root":
                bool(sources) and all(in_root(x) for x in sources),
            "role_paths_distinct_under_active_root":
                len(role_paths)>=3 and len(role_paths)==len(set(role_paths))
                and all(in_root(x) for k in kinds for x in by_role.get(k,())),
        }
    elif n==176:
        original=_one(by_role,"NATIVE_EXPORT")
        reimport=_one(by_role,"NATIVE_REIMPORT")
        check=native_script_output_matches_oracle(plan,by_role)
        native_qa=[r for r in records if
             r.get("event")=="NATIVE_OUTPUT_INDEPENDENT_QA" and
             r.get("step")==step and
             r.get("attempt_id")==work["attempt_id"] and
             r.get("operation_sha256")==work["operation_sha256"] and
             r.get("result")=="PASS" and
             type(r.get("evidence_operation")) is dict and
             r["evidence_operation"].get("artifact_sha256") in
              ({original[1],reimport[1]} if original and reimport else set())]
        extra={
            "preauthorized_numeric_criteria_and_mesh_reimport":
                check and good_glb(original) is not None and
                good_glb(original)==good_glb(reimport),
            "current_attempt_native_qa_audit_binds_binary":
                len(native_qa)==1,
        }
    elif n==179:
        inherited=real_checkpoint_restored_without_duplicate(
            records,by_role,work,step,context["source_loader"])
        duplicates=[x for x in records if
            x.get("event")=="CHECKPOINT_RESTORED_AND_VERIFIED" and
            x.get("attempt_id")==work["attempt_id"] and
            x.get("operation_sha256")==work["operation_sha256"]]
        extra={
            "historical_checkpoint_original_bytes_independently_read":inherited,
            "current_restore_unreplayed_operation":
                inherited and len(duplicates)==1,
        }
    elif n==180:
        baseline=_one(by_role,"BASELINE_SNAPSHOT")
        output=_one(by_role,"NATIVE_EXPORT")
        old_sig=good_glb(baseline);new_sig=good_glb(output)
        # A changed ZIP, log, timestamp or material filename is not evidence
        # of changed model geometry. Require real independent mesh difference.
        extra={
            "original_and_baseline_glb_valid_geometry":
                old_sig is not None and new_sig is not None,
            "actual_geometric_change_not_document_count":
                old_sig is not None and new_sig is not None and old_sig!=new_sig,
        }
    need(set(extra)==set(EXTRA_KEYS[rid]) and
         all(type(v) is bool for v in extra.values()),
         "R171_176_179_180_EXACT_EXTRA_SOURCE_SEMANTICS")
    checks={**standard,**extra}
    need(set(checks)==set(CRITERIA[rid]),
         "R171_176_179_180_SOURCE_SUBCLAUSE_COVERAGE")
    return report,checks

def packet_for_original(context,rid,expected):
    doc,checks=_original(context,rid,expected)
    affirmative=all(checks.values())
    rule_result="PASS" if affirmative else "UNKNOWN"
    return {
      "schema":"gg-semantic-rule-v1",
      "scope":j.SEMANTIC_SCOPE,
      "validator_id":VALIDATOR,
      "binding":expected,
      "rule":{"result":rule_result,"checks":checks,
              "proof_digest":j.digest({
                  "rid":rid,"attempt":expected["attempt_id"],
                  "operation":expected["operation_sha256"],
                  "audit":doc["original_audit_sha256"],
                  "audit_tail":doc["original_audit_tail"],
                  "requirement":expected["requirement_sha256"],
                  "original_checks":checks,
              })},
      "mg0":{"binding":expected,
             "triggered":None,"result":"UNKNOWN",
             "checks":{"canonical_triggers_checked":False},
             "proof_digest":j.digest({
                  "rid":rid,"attempt":expected["attempt_id"],
                  "reason":"NO_AUTHENTICATED_INDEPENDENT_MG0_DECISION",
              })},
    }

def native_rule_readback(api,packet,expected,enrolled_spec,context):
    from broker_live_review import decode_file
    rid=expected.get("rule_id")
    need(rid in CRITERIA and
         type(context) is dict and
         set(context)=={
            "inventory","plan","controller","asset","step","work","source_loader"} and
         enrolled_spec.get("validator_id")==VALIDATOR and
         set(enrolled_spec.get("criteria",()))==set(CRITERIA[rid]) and
         re.fullmatch("[0-9a-f]{40}",str(enrolled_spec.get("source_ref",""))),
         "R171_176_179_180_REVIEWER_OR_REAL_ORIGINAL_CONTEXT_REQUIRED")
    raw=decode_file(api.call("GET","/contents/"+CATALOG_PATH+
           "?ref="+enrolled_spec["source_ref"]),CATALOG_PATH)
    need(sha(raw)==context["inventory"].get("source_digests",{}).get("aaa_catalog"),
         "R171_176_179_180_PRIVATE_IMMUTABLE_SOURCE_CHANGED")
    actual=packet_for_original(context,rid,expected)
    need(packet==actual and
         actual["mg0"]["result"]=="UNKNOWN" and
         actual["mg0"]["triggered"] is None,
         "R171_176_179_180_UNTRUSTED_POSITIVE_OR_FORGED_MG0")
    return {"rule_id":rid,
            "literal_semantics":actual["rule"]["result"],
            "individual_mg0":"UNKNOWN",
            "advancement_authorized":False}

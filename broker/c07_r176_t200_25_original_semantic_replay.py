"""C07 cohort R176..T200: 25 exact original semantic source reviews.

This actually executes the preexisting two independent original-byte QA
engines and the *separate* canonical individual MG0 audit negative reader on
the same real active work attempt. It is a source/semantic review with
evidence-specific per-rule criteria, NOT 25 final PASS/MG0 or owner approval.
No new asset, geometry, source or prior accepted state is changed.

The five R176..R180 rules apply at P0. The twenty S/T181..200 rules apply at
P8, and MUST NOT become 'PASS' on a P0 work attempt.
"""
import hashlib
import re

from c07_r171_r180_source_native import (
    CLAUSES as R_CLAUSES, SCHEMA as R_SCHEMA, inspect as inspect_r)
from c07_batch100_canonical import (
    AAA as B_CLAUSES, CATALOG_SHA)
from c07_batch100_native import (
    SCHEMA as B_SCHEMA, inspect as inspect_batch)
from c07_mg0_individual import inspect_batch as inspect_mg0
from family_coverage import SOURCES

SCHEMA="gg-c07-r176-t200-25-original-triple-source-verdict-v1"
IDS=tuple(
    "AAA-200-%s-%03d" % (
        "R" if n<=180 else "S" if n<=190 else "T", n)
    for n in range(176,201))
CATEGORIZED={
    rid: ("P0" if n<=180 else "P8")
    for n,rid in zip(range(176,201),IDS)
}
# The meanings of each rule are pinned to its *exact* immutable canonical
# clause, not a class-wide regex or a generic 'QA has been performed' label.
ORIGINAL={
    "AAA-200-R-%03d"%n:R_CLAUSES[n] for n in range(176,181)
}
ORIGINAL.update({
    "AAA-200-%s-%03d"%(B_CLAUSES[n][0],n):B_CLAUSES[n][1]
    for n in range(181,201)
})
CONCERNS={
 176:"script_output_matches_expected_actual_result",
 177:"approved_original_is_never_overwritten",
 178:"source_bound_work_dependencies_and_actual_state",
 179:"verified_checkpoint_resume_without_duplicate_work",
 180:"actual_model_production_not_document_counts",
 181:"multiple_verified_model_views",
 182:"measured_alignment_proportion_axes",
 183:"actual_component_intersections",
 184:"normal_surface_artifact_examination",
 185:"exported_asset_material_quality",
 186:"surrounding_environment_coherence",
 187:"post_correction_retests",
 188:"automatic_visual_engine_test_separation",
 189:"critical_error_delivery_block",
 190:"internal_quality_before_customer",
 191:"real_usable_delivery_files",
 192:"all_required_files_present",
 193:"actual_open_and_integrity_of_delivered_files",
 194:"source_version_deliverable_provenance",
 195:"minimal_necessary_maintenance_docs",
 196:"truthful_test_execution_and_unknown_disclosure",
 197:"no_unapproved_delivery_or_owner_signature_forgery",
 198:"recurring_failure_root_cause_elimination",
 199:"measured_improvement_without_excess_checks",
 200:"all_agreed_requirements_evidence_before_done",
}
class Cohort25Blocked(ValueError):pass
def need(cond,reason):
    if not cond:raise Cohort25Blocked(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def canonical_requirements(inventory):
    """Exact 25 original AAA source clauses; never trust producer-supplied text."""
    need(type(inventory) is dict and
         inventory.get("schema")=="gg-effective-family-inventory-v1" and
         inventory.get("rule_count")==763 and
         inventory.get("source_digests",{}).get("aaa_catalog")==CATALOG_SHA and
         set(ORIGINAL)==set(IDS) and len(CONCERNS)==25 and
         all(type(x) is str and x.strip() for x in CONCERNS.values()) and
         len(set(CONCERNS.values()))==25,
         "C07_R176_T200_CANONICAL_25_SOURCE_REQUIRED")
    for n,rid in enumerate(IDS,176):
        row=inventory.get("rules",{}).get(rid,{})
        need(row.get("family")=="AAA-200" and
             row.get("catalog_number")==n and
             row.get("catalog_section")==rid.split("-")[2] and
             row.get("catalog_phase")==CATEGORIZED[rid] and
             row.get("source_sha256")==CATALOG_SHA and
             row.get("requirement")==ORIGINAL[rid] and
             row.get("requirement_sha256")==sha(ORIGINAL[rid].encode("utf-8")),
             "C07_R176_T200_UNTRUSTED_ORIGINAL_CLAUSE:"+rid)

def inspect(context):
    """25 actual independent source-bound observations, never 25 MG0 PASS."""
    need(type(context) is dict and set(context)=={
        "inventory","plan","controller","asset","step","work","source_loader"
    } and callable(context["source_loader"]),
    "C07_R176_T200_REAL_CONTROLLER_CONTEXT_REQUIRED")
    inv=context["inventory"];work=context["work"]
    controller=context["controller"]
    canonical_requirements(inv)
    need(type(work) is dict and
         inv["canonical_master_sha256"]==work.get("master_sha256")==
             context["plan"].get("master_sha256") and
         type(work.get("attempt_id")) is str and
         re.fullmatch("[a-f0-9]{64}",work["attempt_id"]) and
         type(work.get("operation_sha256")) is str and
         re.fullmatch("[a-f0-9]{64}",work["operation_sha256"]) and
         work.get("phase") in ("P0","P1","P2","P3","P4","P5","P6","P7","P8"),
         "C07_R176_T200_EXACT_ORIGINAL_WORK_REQUIRED")
    master=controller.master.read_bytes()
    need(type(master) is bytes and sha(master)==work["master_sha256"],
         "C07_R176_T200_ORIGINAL_MASTER_CHANGED")
    params=(inv,context["plan"],controller,context["asset"],
            context["step"],work)
    kw={"source_loader":context["source_loader"]}
    r=inspect_r(*params,**kw)
    b=inspect_batch(*params,**kw)
    audit=controller.audit_path(context["asset"]).read_bytes()
    need(type(audit) is bytes,"C07_R176_T200_REAL_AUDIT_BYTES_REQUIRED")
    mg0=inspect_mg0(master,audit,context["asset"],work["master_sha256"],
                    list(IDS),work["attempt_id"])
    need(r["schema"]==R_SCHEMA and b["schema"]==B_SCHEMA and
         r["rule_count"]==10 and b["source_rules_examined"]==100 and
         mg0["rule_count"]==25 and
         r["original_audit_sha256"]==b["original_audit_sha256"]==
             mg0["audit_sha256"]==sha(audit) and
         r["original_audit_tail"]==b["original_audit_tail"]==
             mg0["audit_tail_sha256"] and
         r["attempt_id"]==b["attempt_id"]==mg0["attempt_id"]==
             work["attempt_id"] and
         r["operation_sha256"]==b["operation_sha256"]==
             work["operation_sha256"] and
         r["master_sha256"]==work["master_sha256"] and
         r["full_rule_passes"]==b["full_rule_passes"]==0 and
         r["individual_mg0_passes"]==b["individual_mg0_passes"]==
             mg0["individual_mg0_passes"]==0 and
         r["advancement_authorized"] is False and
         b["advancement_authorized"] is False and
         mg0["advancement_authorized"] is False and
         set(mg0["rules"])==set(IDS),
         "C07_R176_T200_THREE_ORIGINAL_SOURCE_REPLAYS_DIVERGED")
    rules={}
    for rid in IDS:
        n=int(rid[-3:])
        source=r["rules"][rid] if n<=180 else b["rules"][rid]
        row=inv["rules"][rid]
        checks=(source["original_machine_criteria"] if n<=180
                else source["original_native_criteria"])
        need(type(source) is dict and
             source["rule_id"]==rid and
             source["requirement_sha256"]==row["requirement_sha256"] and
             source["source_sha256"]==row["source_sha256"] and
             source["canonical_requirement"]==ORIGINAL[rid] and
             type(checks) is dict and len(checks)==4 and
             len(set(checks))==4 and
             all(type(v) is bool for v in checks.values()) and
             source["advancement_authorized"] is False and
             source["independent_mg0" if n<=180 else "individual_mg0"]==
                 "UNKNOWN",
             "C07_R176_T200_SPECIFIC_ORIGINAL_MACHINE_RULE_CHANGED:"+rid)
        observation=mg0["rules"][rid]
        need(observation["verdict"] in ("FAIL","UNKNOWN") and
             type(observation["uncorrected_failure_count"]) is int and
             observation["uncorrected_failure_count"]>=0 and
             re.fullmatch("[a-f0-9]{64}",observation["observation_sha256"]),
             "C07_R176_T200_INDEPENDENT_MG0_NOT_REAL:"+rid)
        phase=CATEGORIZED[rid]
        phase_order=("P0","P1","P2","P3","P4","P5","P6","P7","P8")
        due=phase_order.index(work["phase"])>=phase_order.index(phase)
        blocker=(observation["verdict"]=="FAIL" or
                 observation["uncorrected_failure_count"]>0)
        rules[rid]={
          "rule_id":rid,"canonical_requirement":ORIGINAL[rid],
          "semantic_concern":CONCERNS[n],
          "requirement_sha256":row["requirement_sha256"],
          "source_sha256":row["source_sha256"],
          "required_phase":phase,
          "applicability":"DUE" if due else "FUTURE_PHASE",
          "machine_checks":checks,
          "machine_scoped_observed":sum(checks.values()),
          "missing_machine_checks":sorted(k for k,v in checks.items() if not v),
          "uncorrected_independent_mg0_failures":observation["uncorrected_failure_count"],
          "original_negative_verdict":observation["verdict"],
          "independent_mg0_observation_sha256":observation["observation_sha256"],
          "semantic_verdict":"FAIL" if blocker else "UNKNOWN",
          "full_clause_positive_certified":False,
          "independent_mg0_certified":False,
          "advancement_authorized":False,
        }
        # Invalid claims on a FUTURE_PHASE rule remain negative evidence,
        # not source approval or a P8 model delivery authorization.
    need(len(rules)==25 and set(rules)==set(IDS) and
         sum(len(z["machine_checks"]) for z in rules.values())==100,
         "C07_R176_T200_25_RULES_100_SEMANTIC_CRITERIA_REQUIRED")
    return {
      "schema":SCHEMA,
      "rule_count":25,
      "source_rules_exact":25,
      "original_semantic_criteria_checked":100,
      "source_scope_conditions_observed":sum(z["machine_scoped_observed"] for z in rules.values()),
      "due_rules":sum(z["applicability"]=="DUE" for z in rules.values()),
      "future_phase_rules":sum(z["applicability"]=="FUTURE_PHASE" for z in rules.values()),
      "negative_failures":sum(z["semantic_verdict"]=="FAIL" for z in rules.values()),
      "original_audit_sha256":sha(audit),
      "original_audit_tail":mg0["audit_tail_sha256"],
      "master_sha256":work["master_sha256"],
      "attempt_id":work["attempt_id"],
      "operation_sha256":work["operation_sha256"],
      "independent_mg0_passes":0,
      "full_rule_semantic_passes":0,
      "advancement_authorized":False,
      "rules":rules
    }

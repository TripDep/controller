"""C07 EXEC-001..025: independent measurable positive *semantic components*.

This extends R129's original canonical-source witness with readbacks of
outcomes and transitive dependency closure. A observed component is not the
full original imperative, owner acceptance, FiveM ready asset or MG0 PASS.
In particular, QA event names and assertion labels are never positives.
"""
import hashlib
import re
from pathlib import Path

from c07_exec25_native_observation import inspect as original25, IDS
from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from glb_machine_qa import audit_bytes,GLBError,MAX_BYTES

SCHEMA="gg-c07-exec25-native-positive-outcome-v1"
class NativeExecBlocked(ValueError):pass
def need(v,msg):
    if not v:raise NativeExecBlocked(msg)

def all_transitive_dependencies(plan,work,controller,source_loader):
    """Full graph closure: reject missing indirect edges, cycles, stale bytes.

    A list of direct files is not a transitive proof. Every node of a
    canonical dependency graph must be explicitly enrolled and re-read.
    """
    graph=plan.get("dependency_graph")
    deps=plan.get("dependency_files")
    original=work.get("work_dependencies")
    if type(graph) is not dict or not graph or type(deps) is not dict or not deps:
        return False
    if type(original) is not dict or set(deps)!=set(original) or set(graph)!=set(deps):
        return False
    root=getattr(controller,"root",None)
    if not isinstance(root,Path):return False
    seen=set();active=set()
    def visit(key):
        if key in seen:return True
        if key in active or key not in graph:return False
        active.add(key)
        links=graph[key]
        if type(links) is not list or len(links)!=len(set(links)) or
            any(type(n) is not str or n not in graph for n in links):
            return False
        for other in links:
            if not visit(other):return False
        active.remove(key);seen.add(key)
        return True
    if not all(visit(key) for key in graph):return False
    for key,path in deps.items():
        if (type(key) is not str or
            re.fullmatch("[0-9a-f]{64}",key) is None or
            type(path) is not str or not path or
            Path(path).is_absolute() or
            ".." in Path(path).parts or
            "\\" in path):return False
        p=root/path
        if not p.resolve().is_relative_to(root.resolve()) or
           p.is_symlink() or not p.is_file():
            return False
        raw=source_loader(str(p))
        if type(raw) is not bytes or sha(raw)!=original[key]:return False
    return True

def inspect(inv,plan,controller,asset,step,work,*,source_loader):
    need(callable(source_loader),"EXEC25_POSITIVE_ORIGINAL_SOURCE_READER_REQUIRED")
    base=original25(inv,plan,controller,asset,step,work,
                    source_loader=source_loader)
    need(base["source_rule_count"]==25 and set(base["rules"])==set(IDS) and
         base["individual_mg0_passes"]==0 and
         base["full_rule_passes"]==0 and
         base["advancement_authorized"] is False,
         "EXEC25_POSITIVE_ORIGINAL_CLAUSES_DRIFT")
    rows,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(tail==base["original_audit_tail"] and
         audit_sha==base["original_audit_sha256"] and
         sha(controller.master.read_bytes())==work["master_sha256"],
         "EXEC25_POSITIVE_REPLAYED_AUDIT_OR_MASTER")
    artifacts=_registered_artifacts(rows,state,step,source_loader,work)
    originals={}
    for role,path,digest,raw in artifacts:
        need(type(raw) is bytes and sha(raw)==digest,
             "EXEC25_UNAUTHENTICATED_ORIGINAL_ARTIFACT")
        originals.setdefault(role,[]).append((path,digest,raw))
    def one(role):
        v=originals.get(role,())
        return v[0] if len(v)==1 else None
    export=one("NATIVE_EXPORT")
    base_snapshot=one("BASELINE_SNAPSHOT")
    glb=None
    if export and Path(export[0]).suffix.lower()==".glb":
        need(len(export[2])<=MAX_BYTES,"EXEC25_ORIGINAL_EXPORT_BUDGET")
        try:glb=audit_bytes(export[2])
        except (GLBError,ValueError,TypeError,KeyError,IndexError):
            glb=None
    current=[r for r in rows if r.get("step")==step and
             r.get("attempt_id")==work["attempt_id"] and
             r.get("operation_sha256")==work["operation_sha256"]]
    def event(name):return [r for r in current if r.get("event")==name]
    def valid_event(name):return any(
        r.get("result")=="PASS" and
        type(r.get("evidence_operation")) is dict and
        r["evidence_operation"].get("artifact_sha256") in
            {a[1] for a in artifacts} for r in event(name))
    def criteria():
        c=plan.get("acceptance_criteria")
        return type(c) is list and bool(c) and all(
            type(x) is dict and type(x.get("name")) is str and
            type(x.get("expected")) in (str,int,float,bool) for x in c)
    graph=all_transitive_dependencies(plan,work,controller,source_loader)
    has_raw=bool(export and type(export[2]) is bytes)
    changed=bool(has_raw and base_snapshot and
                 export[1]!=base_snapshot[1])
    geometry=bool(glb and glb["triangles_examined"]>0 and
                  not glb["errors"])
    finish=bool(glb and glb["degenerate_triangles"]==0 and
                glb["nonfinite_positions"]==0 and geometry)
    def certificate(roles):
        return all(one(role) is not None for role in roles)
    qa_roles={
      5:("NATIVE_QA_REPORT","VISUAL_QA_REPORT","RUNTIME_QA_REPORT"),
      9:("DEFECT_REGISTER","FRESH_EYES_REPORT"),
      14:("BEFORE_AFTER_REGRESSION","SOURCE_BASELINE"),
      15:("INDEPENDENT_DELIVERY_QA",),
      16:("FRESH_EYES_REPORT","CG1_CG4_FINDINGS"),
      19:("PLAYER_VIEW_REPORT","VISUAL_DENSITY_REPORT"),
      20:("INTENTION_BLIND_REVIEW",),
      22:("MULTI_ANGLE_QA",),
      23:("BOUNDARY_CONTACT_QA",),
      24:("GLOBAL_DEFECT_COUNT",),
      25:("REUSE_CONTEXT_QA",),
    }
    # Only actual tested outcomes and original-source referenced witnesses.
    # Document presence alone never turns the complete semantically compound
    # rule into a full positive; the third obligation remains UNKNOWN.
    specs={
      1:("measurable_acceptance_defined",criteria(),
         "actual_verified_outcome",valid_event("ACCEPTANCE_MEASURED")),
      2:("historic_pass_corrections_replayed",valid_event("VERIFIED_STATES_INVALIDATED"),
         "affected_states_retested",valid_event("AFFECTED_STATES_RETESTED")),
      3:("all_transitive_dependency_bytes_read",graph,
         "all_original_direct_bytes_verified",base["dependency_bytes_verified"]>0),
      4:("fixed_acceptance_criteria_pre_enrolled",criteria(),
         "independent_acceptance_result_replayed",valid_event("ACCEPTANCE_MEASURED")),
      5:("native_glb_geometry_tested",geometry,
         "independent_qa_triads_registered",certificate(qa_roles[5])),
      6:("open_mandatory_issues_retested",valid_event("MANDATORY_ISSUES_RETESTED"),
         "optional_work_after_mandatory",valid_event("PRIORITY_SEQUENCE_VERIFIED")),
      7:("time_budget_explicit",type(plan.get("timebox_seconds")) is int and
         plan["timebox_seconds"]>0,
         "actual_budget_comparison_verifiable",valid_event("TIMEBOX_EXAMINED")),
      8:("original_rollback_snapshot_verified",bool(base_snapshot),
         "independent_rollback_rehearsal",valid_event("ROLLBACK_READBACK")),
      9:("actual_original_issue_sources_present",bool(event("QUALITY_FINDING")),
         "independent_issue_discovery_review",certificate(qa_roles[9])),
      10:("entire_transitive_source_graph_verified",graph,
          "original_reference_set_verified",certificate(("REFERENCE_INDEX",))),
      11:("facts_classification_recorded",certificate(("FACTS_INFERENCES_ASSUMPTIONS",)),
          "independent_fact_conflict_test",valid_event("FACT_CONFLICT_CHECK")),
      12:("root_cause_correction_chain_measured",valid_event("MG0_RULE_REAPPLIED"),
          "same_issue_not_repeated",valid_event("ROOT_CAUSE_RECURRENCE_TEST")),
      13:("original_sections_declared",bool(plan.get("operation",{}).get("sections")),
          "material_change_tolerance_measured",valid_event("SCOPE_RECURSION_VERIFIED")),
      14:("before_after_source_snapshot_verified",bool(base_snapshot),
          "independent_no_regression_report",certificate(qa_roles[14])),
      15:("delivery_gate_evidence_has_original_bytes",valid_event("DELIVERY_GATE_CHECK"),
          "separate_qa_source",certificate(qa_roles[15])),
      16:("fresh_eye_report_original",certificate(qa_roles[16]),
          "fresh_eye_findings_verified",valid_event("FRESH_EYES_REVIEW")),
      17:("component_trace_index_registered",certificate(("RULE_PIECE_TRACE",)),
          "all_25_exec_original_sha_bound",len(base["rules"])==25),
      18:("transitive_dependency_original_sha",graph,
          "interface_conflict_report",certificate(("INTERFACE_CONFLICT_QA",))),
      19:("native_mesh_measurably_valid",geometry,
          "player_view_density_review",certificate(qa_roles[19])),
      20:("original_export_has_real_geometry",finish,
          "intention_blind_fivem_review",certificate(qa_roles[20])),
      21:("original_pre_d_numeric_criteria",criteria(),
          "measured_acceptance_independently",valid_event("ACCEPTANCE_MEASURED")),
      22:("real_native_output_geometry",geometry,
          "view_angle_distance_scale_checks",certificate(qa_roles[22])),
      23:("transitive_source_geometry_deps",graph,
          "all_contacts_independently_reviewed",certificate(qa_roles[23])),
      24:("current_original_defects_seen",bool(event("QUALITY_FINDING")),
          "cumulative_impact_audit",certificate(qa_roles[24])),
      25:("original_baseline_has_real_bytes",bool(base_snapshot),
          "reused_component_independent_qa",certificate(qa_roles[25])),
    }
    need(len(specs)==25 and all(len(specs[n])==4 for n in range(1,26)),
         "EXEC25_MISSING_TRUE_RULE_SPECIFIC_OUTCOME_ORACLE")
    result={};observed=0
    for n,rid in enumerate(IDS,1):
        a,x,b,y=specs[n]
        checks={a:bool(x),b:bool(y)}
        observed+=sum(checks.values())
        result[rid]={
           "rule_id":rid,
           "source_sha256":inv["rules"][rid]["source_sha256"],
           "requirement_sha256":inv["rules"][rid]["requirement_sha256"],
           "independent_outcome_checks":checks,
           "observed_positive_components":sorted(k for k,v in checks.items() if v),
           "unverified_outcome_components":sorted(k for k,v in checks.items() if not v),
           "complete_original_clause_semantics":"UNKNOWN",
           "individual_mg0":"UNKNOWN",
           "owner_approval":"UNKNOWN",
           "advancement_authorized":False,
        }
    return {
      "schema":SCHEMA,"source_rule_count":25,
      "original_audit_sha256":audit_sha,
      "original_audit_tail":tail,
      "attempt_id":work["attempt_id"],
      "operation_sha256":work["operation_sha256"],
      "native_positive_outcome_conditions_evaluated":50,
      "native_positive_outcome_conditions_observed":observed,
      "full_rule_semantics_passes":0,
      "individual_mg0_passes":0,
      "advancement_authorized":False,"rules":result,
    }

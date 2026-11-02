"""C07 native partial semantics for fifty BEHAVIOR-001..050 original rules.

Exactly scoped immutable Controller audit, current attempt and independently
reopened original registered bytes. A record is a machine observation only,
NEVER behavioral compliance, owner approval, production proof or MG0 PASS.
"""
import hashlib
import re
from datetime import datetime
from pathlib import Path

from c07_positive_native_process import _original_attempt, _registered_artifacts, sha
from c07_behavior_001_050_canonical import IDS, CLAUSES, SOURCE_SHA
from c07_behavior_001_050_spec import SPEC

SCHEMA="gg-c07-behavior001-050-fifty-source-native-v1"
class Behavior50Blocked(ValueError):pass
def need(ok,why):
    if not ok:raise Behavior50Blocked(why)
def nonempty(s):return type(s) is str and bool(s.strip())
def number(s):return type(s) in (int,float) and s>=0

def exact_source(inv):
    need(type(inv) is dict and inv.get("schema")=="gg-effective-family-inventory-v1"
         and inv.get("rule_count")==763
         and inv.get("source_digests",{}).get("error_registry")==SOURCE_SHA
         and len(CLAUSES)==50 and len(IDS)==50 and len(SPEC)==50,
         "C07_B50_CANONICAL_SOURCE_MISSING_OR_CHANGED")
    for n,wording in CLAUSES.items():
        rid=IDS[n-1];row=inv.get("rules",{}).get(rid,{})
        need(row.get("family")=="BEHAVIOR_110" and
             row.get("source")=="error_registry" and
             row.get("source_path")==
                "governance/sources/REGISTRO_110_ERRORI_E_PREVENZIONE.md"
             and row.get("source_sha256")==SOURCE_SHA and
             row.get("requirement")==wording and
             row.get("requirement_sha256")==sha(wording.encode("utf-8"))
             and row.get("required_mg0") is True,
             "C07_B50_ORIGINAL_ERROR_TO_PREVENTION_CHANGED:"+rid)

def _utc(s):
    if not nonempty(s):return None
    try:
        d=datetime.fromisoformat(s.replace("Z","+00:00"))
        return d.timestamp() if d.tzinfo is not None else None
    except (ValueError,OverflowError):return None

def scoped_original_features(rows,artifacts,state,plan,work,asset,step,controller,source_loader):
    """No synthetic/replayed source decision can be used as work PASS."""
    roles={};paths=set()
    for role,path,digest,raw in artifacts:
        need(type(role) is str and type(path) is str and path not in paths
             and type(raw) is bytes and len(raw)>0 and sha(raw)==digest,
             "C07_B50_ORIGINAL_BYTES_REPLAY_OR_PATH_DUPLICATE")
        paths.add(path);roles.setdefault(role,[]).append((path,digest,raw))
    def role(name):return len(roles.get(name,()))==1
    def item(name):
        return roles[name][0] if role(name) else None
    def prior(name):
        return any(x.get("event")==name and x.get("step")!=step for x in rows)
    this=[r for r in rows if r.get("step")==step
          and r.get("attempt_id")==work.get("attempt_id")
          and r.get("operation_sha256")==work.get("operation_sha256")]
    def event(name):return any(r.get("event")==name for r in this)
    def records(name):return [r for r in this if r.get("event")==name]
    plan_op=plan.get("operation",{})
    if type(plan_op) is not dict:plan_op={}
    deps=plan.get("dependency_files",{})
    deps_ok=(type(deps) is dict and bool(deps)
             and type(work.get("work_dependencies")) is dict
             and set(deps)==set(work["work_dependencies"]))
    if deps_ok:
        for key,path in deps.items():
            need(type(key) is str and re.fullmatch("[0-9a-f]{64}",key)
                 and nonempty(path) and not Path(path).is_absolute()
                 and ".." not in Path(path).parts
                 and (controller.root/path).resolve().is_relative_to(
                     controller.root.resolve()),
                 "C07_B50_DEPENDENCY_PATH_OUTSIDE_CANONICAL_ROOT")
            actual=source_loader(str(controller.root/path))
            if type(actual) is not bytes or sha(actual)!=work["work_dependencies"][key]:
                deps_ok=False
                break
    run_starts=records("RUN_STARTED")
    run_ends=records("RUN_FINISHED")
    run_spans=[]
    for start in run_starts:
        x=_utc(start.get("timestamp_utc"))
        if x is None:continue
        for end in run_ends:
            y=_utc(end.get("timestamp_utc"))
            if y is not None and y>=x:
                run_spans.append(y-x)
                break
    step_spans=[_utc(r.get("timestamp_utc")) for r in this]
    step_spans=[x for x in step_spans if x is not None]
    original_export=item("NATIVE_EXPORT")
    baseline=item("BASELINE_SNAPSHOT")
    original_state=state.get("last_audit_hash")
    policy=plan.get("cost_policy",{})
    if type(policy) is not dict:policy={}
    original_registered=len(artifacts)>0
    deliverable=plan_op.get("deliverables",[])
    if type(deliverable) is not list:deliverable=[]
    F={
       "work_asset_matches_target":work.get("asset")==asset or
             (plan.get("asset_id")==asset),
       "operation_scope_bound":nonempty(plan_op.get("action")),
       "operation_action_declared":nonempty(plan_op.get("action")),
       "real_output_original_bytes":bool(original_export),
       "baseline_output_difference":bool(original_export and baseline and
                                          original_export[1]!=baseline[1]),
       "canonical_master_bytes_match":sha(controller.master.read_bytes())==
                                      work.get("master_sha256"),
       "work_item_digest_stable":bool(re.fullmatch(
           "[a-f0-9]{64}",work.get("work_item_sha256",""))),
       "native_qa_entry_present":event("SUPERVISOR_NATIVE_QA"),
       "quality_findings_recorded":event("QUALITY_FINDING"),
       "master_immutable_digest_proven":sha(controller.master.read_bytes())==
                                        work.get("master_sha256"),
       "delivery_state_pending":state.get("delivery_status") in
                                ("NOT_DELIVERABLE","PENDING","BLOCKED"),
       "actual_deliverable_fields_present":bool(deliverable),
       "financial_limit_present":number(policy.get("max_extra_cost")),
       "cost_policy_present":bool(policy),
       "pricing_source_attached":role("PRICING_SOURCE"),
       "cost_constraint_declared":number(policy.get("max_extra_cost")),
       "cloud_source_paths_observed":role("CLOUD_EXECUTION_RECORD"),
       "deployment_target_declared":nonempty(plan.get("deployment_target")),
       "source_rule_requirements_verified":bool(work.get("master_sha256")),
       "dependency_sha_verified":deps_ok,
       "worker_install_recorded":role("WORKER_INSTALL_RECEIPT"),
       "original_work_sequence_recorded":event("SUPERVISOR_OPERATION_OPENED"),
       "schedule_record_original":role("RUN_SCHEDULE"),
       "original_run_start_observed":bool(run_starts),
       "schedule_configuration_declared":bool(plan.get("schedule")),
       "available_execution_method_recorded":role("EXECUTION_CAPABILITY"),
       "actual_distinct_run_samples":len(run_spans)>=2,
       "original_budget_field_observed":number(plan.get("execution_budget")),
       "last_run_marker_original":role("LAST_RUN_STATE"),
       "guardian_cycle_record_original":event("GUARDIAN_CHECK"),
       "checkpoint_resume_record_original":event("CHECKPOINT_RESTORED"),
       "provider_incident_record_original":role("PROVIDER_ERROR"),
       "run_start_finish_pairs_measured":bool(run_spans),
       "original_simulation_marked":bool(plan.get("simulated_test")),
       "elapsed_calendar_seconds_measured":len(step_spans)>=2,
       "remaining_real_tasks_identified":bool(plan.get("remaining_work")),
       "close_event_original":event("STEP_CLOSE") or event("SUPERVISOR_OPERATION_CLOSED"),
       "close_reason_original":any(nonempty(e.get("reason"))
                   for e in records("STEP_CLOSE")),
       "guardian_start_event_original":event("GUARDIAN_RUN_STARTED"),
       "notification_preference_recorded":role("NOTIFICATION_POLICY"),
       "process_termination_test_recorded":event("PROCESS_TERMINATION_TEST"),
       "checkpoint_source_bytes_verified":role("CHECKPOINT_SOURCE"),
       "machine_unit_tests_recorded":event("MACHINE_TEST_RESULT"),
       "benchmark_environment_declared":nonempty(plan.get("benchmark_environment")),
       "worker_deployment_receipt_present":role("WORKER_INSTALL_RECEIPT"),
       "original_report_artifact_present":role("REPORT"),
       "geometry_scan_record_original":event("SUPERVISOR_NATIVE_QA"),
       "output_sha_readback_verified":bool(original_export),
       "original_prompt_artifact_present":role("PROMPT_SOURCE"),
       "current_controller_selftest_recorded":event("CONTROLLER_SELFTEST"),
       "aaa200_catalog_source_pinned":bool(
                    plan.get("inventory_sha256") and
                    work.get("master_sha256")),
       "library_save_event_original":event("LIBRARY_SAVE_RECEIPT"),
    }
    # Second predicate on each clause is a *separate evidence observation*.
    # Missing records are UNKNOWN, never an inferred compliant answer.
    F.update({
       "trusted_original_plan_enrolled":bool(work.get("operation_sha256")),
       "deliverable_roles_distinct":len(set(deliverable))==len(deliverable) and bool(deliverable)
                  if all(type(v) is str for v in deliverable) else False,
       "original_baseline_sha_differs":bool(baseline and original_export and
                                         baseline[1]!=original_export[1]),
       "plan_lock_names_declared":bool(plan_op.get("locks")),
       "operation_digest_stable":bool(re.fullmatch(
                     "[a-f0-9]{64}",work.get("operation_sha256",""))),
       "output_bytes_present":bool(original_export),
       "regression_evidence_bytes_present":role("REGRESSION_EVIDENCE"),
       "source_fact_hashes_present":bool(plan.get("fact_source_hashes")),
       "native_artifact_hash_rechecked":bool(original_export),
       "selected_process_method_present":nonempty(plan_op.get("method")),
       "pricing_document_declared":role("PRICING_SOURCE"),
       "service_endpoint_recorded":nonempty(plan.get("deployment_service")),
       "provider_cost_reference_declared":role("PRICING_SOURCE"),
       "initial_plan_timestamp_exists":event("SUPERVISOR_PLAN_ENROLLED"),
       "working_root_declared":nonempty(str(getattr(controller,"root",""))),
       "live_run_checkpoint_observed":role("RUN_CHECKPOINT"),
       "plan_dependencies_enrolled":deps_ok,
       "dependency_origin_recorded":bool(deps),
       "operation_steps_bound":event("SUPERVISOR_OPERATION_OPENED"),
       "real_active_duration_measured":bool(run_spans),
       "run_finish_timestamp_verified":bool(run_ends),
       "scheduled_run_event_observed":event("SCHEDULED_RUN_STARTED"),
       "installed_execution_origin_proven":role("WORKER_INSTALL_RECEIPT"),
       "measured_elapsed_seconds":bool(run_spans),
       "provider_error_original":role("PROVIDER_ERROR"),
       "completed_checkpoint_original":role("RUN_CHECKPOINT"),
       "guardian_diagnostic_output_present":role("GUARDIAN_DIAGNOSTICS"),
       "actual_resumed_output_bytes":bool(original_export and event("CHECKPOINT_RESTORED")),
       "asset_failure_event_present":event("QUALITY_FINDING"),
       "idle_interval_seconds_computed":len(run_spans)>=2,
       "duration_values_explicit":bool(run_spans),
       "active_seconds_measured":bool(run_spans),
       "elapsed_work_samples_observed":len(run_spans)>=2,
       "asset_state_audit_hash_consistent":nonempty(original_state),
       "original_stop_reason_present":any(nonempty(e.get("reason")) for e in this),
       "guardian_end_event_original":event("GUARDIAN_RUN_FINISHED"),
       "guardian_event_original":event("GUARDIAN_CHECK"),
       "test_environment_recorded":nonempty(plan.get("test_environment")),
       "resume_event_original":event("CHECKPOINT_RESTORED"),
       "actual_day_long_coverage_recorded":role("DAY_LONG_RUN_MEASUREMENTS"),
       "original_benchmark_samples":role("BENCHMARK_SAMPLES"),
       "worker_real_output_bytes_present":bool(original_export),
       "native_export_original_present":bool(original_export),
       "game_native_resource_original":role("FIVEM_RESOURCE"),
       "registered_artifact_bytes_verified":original_registered,
       "post_prompt_run_original":event("PROMPT_REVISION_TESTED"),
       "validator_scope_record_original":role("VALIDATOR_SCOPE"),
       "artistic_review_original":role("ARTISTIC_REVIEW"),
       "library_readback_verified":role("LIBRARY_READBACK"),
    })
    F.update({
       "requested_api_in_plan":nonempty(plan.get("api_service")),
       "deployment_reference_recorded":role("DEPLOYMENT_RECEIPT"),
       "native_delivery_bytes":role("DELIVERY_PACKAGE"),
       "original_schedule_present":bool(plan.get("schedule")),
       "active_run_interval_observed":bool(run_spans),
       "actual_provider_run_verified":False,
       "two_run_durations_observed":len(run_spans)>=2,
       "original_provider_error_record":role("PROVIDER_ERROR"),
       "last_run_timestamp_present":role("LAST_RUN_STATE"),
       "true_checkpoint_completion_observed":False,
       "guardian_audit_event_present":event("GUARDIAN_CHECK"),
       "checkpoint_before_restart_present":role("CHECKPOINT_SOURCE"),
       "post_resume_output_original":bool(original_export and
                                           event("CHECKPOINT_RESTORED")),
       "provider_failure_event_present":event("PROVIDER_FAILURE"),
       "controller_test_record_original":event("CONTROLLER_SELFTEST"),
    })
    first_and_second={k for triple in SPEC.values() for k in triple[:2]}
    need(first_and_second==set(F),"C07_B50_MISSING_NATIVE_READBACK_PREDICATES")
    need(all(type(v) is bool for v in F.values()),"C07_B50_NATIVE_BOOL_REQUIRED")
    return F

def inspect(inv,plan,controller,asset,step,work,*,source_loader):
    need(callable(source_loader),"C07_B50_ORIGINAL_FILE_READBACK_REQUIRED")
    exact_source(inv)
    records,tail,state,audit_sha=_original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes())==
         inv["canonical_master_sha256"]==work["master_sha256"]
         and state.get("last_audit_hash")==tail and
         (state.get("active_step") or {}).get("step")==step,
         "C07_B50_ORIGINAL_MASTER_OR_AUDIT_STATE_DRIFT")
    artifacts=_registered_artifacts(records,state,step,source_loader,work)
    F=scoped_original_features(records,artifacts,state,plan,work,
                               asset,step,controller,source_loader)
    rules={};evaluated=0;observed=0
    for n,wording in CLAUSES.items():
        rid=IDS[n-1];names=SPEC[n]
        need(len(names)==3 and len(set(names))==3 and
             names[-1] not in F and all(k in F for k in names[:2]),
             "C07_B50_RULE_SCOPE_UNIMPLEMENTED:"+rid)
        checks={names[0]:F[names[0]],names[1]:F[names[1]],
                names[2]:False}
        evaluated+=len(checks);observed+=sum(checks.values())
        rules[rid]={
            "rule_id":rid,"canonical_clause":wording,
            "source_sha256":SOURCE_SHA,
            "requirement_sha256":inv["rules"][rid]["requirement_sha256"],
            "original_machine_checks":checks,
            "observed_machine_evidence":sorted(k for k,v in checks.items() if v),
            "not_independently_proven":sorted(k for k,v in checks.items() if not v),
            "full_prevention_semantics":"UNKNOWN",
            "individual_mg0":"UNKNOWN","owner_approval":"UNKNOWN",
            "advancement_authorized":False,
        }
    need(evaluated==150 and len(rules)==50,"C07_B50_FIFTY_NATIVE_RULES_MISSING")
    return {"schema":SCHEMA,"source_rules_examined":50,
       "original_audit_sha256":audit_sha,"original_audit_tail":tail,
       "attempt_id":work["attempt_id"],"operation_sha256":work["operation_sha256"],
       "native_conditions_evaluated":evaluated,"native_conditions_observed":observed,
       "full_rule_passes":0,"individual_mg0_passes":0,
       "advancement_authorized":False,"rules":rules}

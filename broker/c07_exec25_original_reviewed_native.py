"""C07 EXEC-001..025: original-source, per-rule, reviewed semantic observations.

Each of 25 canonical requirements has four separately named original-data
criteria: two independent outcome checks and two independent domain checks.
Neither these subsets nor positive CI grant full literal semantic certification,
owner approval, or individual MG0. The private-Git consumer always replays
original current Controller bytes and immutable Master before accepting results.
"""
import re
from c07_exec25_native_observation import IDS
from c07_exec25_positive_outcomes import inspect as outcome_inspect, SCHEMA as OUTCOME_SCHEMA
from c07_exec25_domain_machine_probes import inspect as domain_inspect, SCHEMA as DOMAIN_SCHEMA
from c07_positive_native_process import sha
from family_coverage import SOURCES
import supervisor_judgment as j

VALIDATOR="GG_C07_EXEC25_ORIGINAL_SOURCE_REPLAY_V1"
MASTER_PATH=SOURCES["master"]
SCHEMA="gg-c07-exec25-original-independent-review-v1"
CRITERIA={"EXEC-001":["measurable_acceptance_defined","actual_verified_outcome","pre_d_action_bound_to_original_plan","output_binary_exists_for_measurable_goal"],"EXEC-002":["historic_pass_corrections_replayed","affected_states_retested","prior_accepted_versions_present","current_export_distinct_from_old_accepted_bytes"],"EXEC-003":["all_transitive_dependency_bytes_read","all_original_direct_bytes_verified","declared_direct_dependencies_current_bytes_verified","dependency_set_has_unique_pinned_keys"],"EXEC-004":["fixed_acceptance_criteria_pre_enrolled","independent_acceptance_result_replayed","pre_d_expected_oracle_criteria_stored_in_enrolled_plan","current_operation_bound_before_step"],"EXEC-005":["native_glb_geometry_tested","independent_qa_triads_registered","actual_export_has_nondegenerate_geometry","registered_source_and_export_distinct_bytes"],"EXEC-006":["open_mandatory_issues_retested","optional_work_after_mandatory","open_quality_finding_history_independently_read","mandatory_issue_ids_in_plan"],"EXEC-007":["time_budget_explicit","outcome_contract","original_plan_has_documented_time_budget","original_step_has_native_timestamps"],"EXEC-008":["original_rollback_snapshot_verified","independent_rollback_rehearsal","two_original_rollback_bytes_identical","rollback_backup_file_verified_from_disk"],"EXEC-009":["actual_original_issue_sources_present","independent_issue_discovery_review","original_findings_preserved_in_audit","actual_finding_source_attached"],"EXEC-010":["entire_transitive_source_graph_verified","original_reference_set_verified","original_direct_input_dependencies_hash_verified","original_editable_source_binary_reopened"],"EXEC-011":["facts_classification_recorded","FACTS_INFERENCES_ASSUMPTIONS","pre_d_scope_is_original_audited_input","source_artifacts_distinguished_from_output"],"EXEC-012":["root_cause_correction_chain_measured","same_issue_not_repeated","original_failure_record_identified","actual_before_after_binary_pair"],"EXEC-013":["original_sections_declared","operation","nested_components_declared_before_work","original_work_is_one_controller_step"],"EXEC-014":["before_after_source_snapshot_verified","independent_no_regression_report","original_verified_baseline_present","current_export_actual_bytes_distinct"],"EXEC-015":["delivery_gate_evidence_has_original_bytes","separate_qa_source","pre_delivery_source_reopened","export_structure_checked_independently"],"EXEC-016":["fresh_eye_report_original","fresh_eye_findings_verified","fresh_eye_original_audit_event_present","multi_angle_images_really_registered"],"EXEC-017":["component_trace_index_registered","RULE_PIECE_TRACE","distinct_source_and_export_provenance","pre_d_sections_belong_to_original_plan"],"EXEC-018":["transitive_dependency_original_sha","interface_conflict_report","declared_dependency_bytes_unchanged","artifacts_have_no_reused_original_path"],"EXEC-019":["native_mesh_measurably_valid","player_view_density_review","nonempty_real_export_independently_parsed","pre_d_visual_hierarchy_defined"],"EXEC-020":["original_export_has_real_geometry","intention_blind_fivem_review","export_was_not_merely_producer_report","source_original_current_attempt_bound"],"EXEC-021":["original_pre_d_numeric_criteria","measured_acceptance_independently","measurable_pre_d_oracle_committed_before_execution","native_export_actual_bytes_accessible"],"EXEC-022":["real_native_output_geometry","view_angle_distance_scale_checks","nondegenerate_actual_export_geometry","different_view_artifacts_from_original_bytes"],"EXEC-023":["transitive_source_geometry_deps","all_contacts_independently_reviewed","site_connector_sections_named_pre_d","actual_export_geometry_independently_decoded"],"EXEC-024":["current_original_defects_seen","cumulative_impact_audit","actual_quality_finding_records_consulted","multiple_original_finding_classes_observed"],"EXEC-025":["original_baseline_has_real_bytes","reused_component_independent_qa","prior_protected_original_byte_snapshot_reopened","reused_component_differs_from_current_attempt"]}
class ExecReviewBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise ExecReviewBlocked(why)

def check_context(context,rid,expected):
    need(type(context) is dict and set(context)=={
         "inventory","plan","controller","asset","step","work","source_loader"}
         and callable(context["source_loader"]) and rid in IDS,
         "EXEC25_CURRENT_ORIGINAL_CONTEXT_REQUIRED")
    inv=context["inventory"];work=context["work"];row=inv["rules"][rid]
    need(inv.get("schema")=="gg-effective-family-inventory-v1" and
         inv.get("rule_count")==763 and
         row.get("family")=="EXECUTION" and row.get("source")=="master" and
         row.get("source_sha256")==inv.get("canonical_master_sha256")==
         work.get("master_sha256")==context["plan"].get("master_sha256") and
         type(row.get("requirement")) is str and
         row["requirement"].startswith("## "+rid+" —") and
         sha(row["requirement"].encode())==row.get("requirement_sha256") and
         type(expected) is dict and expected.get("rule_id")==rid and
         expected.get("attempt_id")==work.get("attempt_id") and
         expected.get("operation_sha256")==work.get("operation_sha256") and
         expected.get("source_sha256")==row["source_sha256"] and
         expected.get("requirement_sha256")==row["requirement_sha256"] and
         expected.get("master_sha256")==work["master_sha256"],
         "EXEC25_CANONICAL_CLAUSE_ATTEMPT_OR_BINDING_DRIFT:"+rid)
    original=context["controller"].master.read_bytes()
    need(type(original) is bytes and sha(original)==work["master_sha256"],
         "EXEC25_CANONICAL_MASTER_BYTES_DRIFT")
    return inv,work

def inspect(context):
    """Execute 25 original semantically distinct process criteria sets."""
    inv=context["inventory"];work=context["work"]
    for rid in IDS:
        row=inv["rules"][rid]
        expected={"rule_id":rid,"attempt_id":work["attempt_id"],
                  "operation_sha256":work["operation_sha256"],
                  "source_sha256":row["source_sha256"],
                  "requirement_sha256":row["requirement_sha256"],
                  "master_sha256":work["master_sha256"]}
        check_context(context,rid,expected)
    params=(inv,context["plan"],context["controller"],context["asset"],
            context["step"],work)
    kw={"source_loader":context["source_loader"]}
    outcome=outcome_inspect(*params,**kw)
    domain=domain_inspect(*params,**kw)
    need(outcome.get("schema")==OUTCOME_SCHEMA and domain.get("schema")==DOMAIN_SCHEMA and
         outcome.get("source_rule_count")==domain.get("source_rule_count")==25 and
         set(outcome.get("rules",{}))==set(domain.get("rules",{}))==set(IDS) and
         outcome["attempt_id"]==domain["attempt_id"]==work["attempt_id"] and
         outcome["operation_sha256"]==domain["operation_sha256"]==
             work["operation_sha256"] and
         outcome["original_audit_sha256"]==domain["original_audit_sha256"] and
         outcome["original_audit_tail"]==domain["original_audit_tail"] and
         outcome["full_rule_semantics_passes"]==domain["full_native_semantics_passes"]==0 and
         outcome["individual_mg0_passes"]==domain["individual_mg0_passes"]==0 and
         outcome["advancement_authorized"] is False and
         domain["advancement_authorized"] is False,
         "EXEC25_TWO_ORIGINAL_SOURCE_ENGINES_DIVERGED")
    rows={};unique=set()
    for rid in IDS:
        x=outcome["rules"][rid];y=domain["rules"][rid]
        need(x["rule_id"]==y["rule_id"]==rid and
             x["source_sha256"]==y["source_sha256"]==inv["rules"][rid]["source_sha256"] and
             x["requirement_sha256"]==y["requirement_sha256"]==
                 inv["rules"][rid]["requirement_sha256"] and
             x["individual_mg0"]==y["individual_mg0"]=="UNKNOWN" and
             x["complete_original_clause_semantics"]==
                 y["whole_source_requirement"]=="UNKNOWN",
             "EXEC25_PARTIAL_SOURCE_CANNOT_BE_FULL_PASS:"+rid)
        left=x["independent_outcome_checks"]
        right=y["additional_domain_machine_criteria"]
        need(type(left) is dict and type(right) is dict and
             len(left)==len(right)==2 and
             set(left).isdisjoint(set(right)) and
             set(left)|set(right)==set(CRITERIA[rid]) and
             all(type(v) is bool for v in (*left.values(),*right.values())),
             "EXEC25_EXACT_FOUR_CANONICAL_PREDICATES_REQUIRED:"+rid)
        checks={**left,**right}
        need(not unique.intersection(checks), "EXEC25_CROSS_RULE_CRITERION_REUSED")
        unique.update(checks)
        rows[rid]={"rule_id":rid,"source_sha256":x["source_sha256"],
                   "requirement_sha256":x["requirement_sha256"],
                   "criteria":checks,
                   "scoped_positive_count":sum(checks.values()),
                   "full_literal_semantics":"UNKNOWN",
                   "individual_mg0":"UNKNOWN",
                   "advancement_authorized":False}
    need(len(rows)==25 and len(unique)==100,
         "EXEC25_ONE_HUNDRED_DISTINCT_ORIGINAL_CRITERIA_REQUIRED")
    return {"schema":SCHEMA,"rule_count":25,"criteria_count":100,
            "positive_scope_observations":sum(v["scoped_positive_count"] for v in rows.values()),
            "attempt_id":work["attempt_id"],"master_sha256":work["master_sha256"],
            "operation_sha256":work["operation_sha256"],
            "original_audit_sha256":outcome["original_audit_sha256"],
            "original_audit_tail":outcome["original_audit_tail"],
            "full_rule_passes":0,"individual_mg0_passes":0,
            "advancement_authorized":False,"rules":rows}

def packet_for_original(context,rid,expected):
    check_context(context,rid,expected)
    report=inspect(context)
    checks=report["rules"][rid]["criteria"]
    # Even 4/4 is not a FULL original imperative or human/artist judgment.
    return {"schema":"gg-semantic-rule-v1",
            "scope":j.SEMANTIC_SCOPE,"validator_id":VALIDATOR,
            "binding":expected,
            "rule":{"result":"UNKNOWN","checks":checks,
                    "proof_digest":j.digest({
                        "rule":rid,"attempt":expected["attempt_id"],
                        "master":expected["master_sha256"],
                        "audit":report["original_audit_sha256"],
                        "tail":report["original_audit_tail"],
                        "checks":checks,"full_rule_not_claimed":True})},
            "mg0":{"binding":expected,"triggered":None,"result":"UNKNOWN",
                   "checks":{"canonical_triggers_checked":False},
                   "proof_digest":j.digest({
                       "rule":rid,"attempt":expected["attempt_id"],
                       "reason":"NO_AUTHENTICATED_INDEPENDENT_MG0"})}}

def native_rule_readback(api,packet,expected,spec,context):
    from broker_live_review import decode_file
    rid=expected.get("rule_id")
    need(rid in IDS and type(spec) is dict and
         spec.get("validator_id")==VALIDATOR and
         set(spec.get("criteria",()))==set(CRITERIA[rid]) and
         re.fullmatch("[a-f0-9]{40}",str(spec.get("source_ref",""))),
         "EXEC25_ENROLLMENT_OR_IMMUTABLE_MASTER_REF_MISSING")
    inv,work=check_context(context,rid,expected)
    try:
        pinned=decode_file(api.call(
            "GET","/contents/"+MASTER_PATH+"?ref="+spec["source_ref"]),MASTER_PATH)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        raise ExecReviewBlocked("EXEC25_PRIVATE_IMMUTABLE_MASTER_UNAVAILABLE") from exc
    need(type(pinned) is bytes and sha(pinned)==work["master_sha256"] and
         pinned==context["controller"].master.read_bytes(),
         "EXEC25_PRIVATE_ORIGINAL_MASTER_REPLACED")
    actual=packet_for_original(context,rid,expected)
    need(packet==actual and actual["rule"]["result"]=="UNKNOWN" and
         actual["mg0"]["result"]=="UNKNOWN" and
         actual["mg0"]["triggered"] is None,
         "EXEC25_UNTRUSTED_FULL_SEMANTIC_OR_MG0_CLAIM")
    return {"rule_id":rid,"native_scoped_predicates":actual["rule"]["checks"],
            "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
            "advancement_authorized":False}

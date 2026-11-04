"""C07 seventh 25-rule original P1 semantic evidence: D036..F060.

Read both independently authored original-byte Controller engines on the
same active audit, verify every canonical literal source clause and correlate
25 independent MG0-negative observations. No source machine subcriterion
ever confers full semantic PASS, owner's signoff or advancement.
"""
import hashlib
import re

from c07_bf50_canonical import CLAUSES, CATALOG_SHA
from c07_bf50_predicates import SPEC
from c07_b011_f060_fifty_native import SCHEMA as BF_SCHEMA, inspect as inspect_bf
from c07_p1_thirty_native_domain import SCHEMA as P1_SCHEMA, TEXT as P1_TEXT, inspect as inspect_p1
from c07_mg0_individual import inspect_batch as inspect_mg0

SCHEMA="gg-c07-d036-f060-exact25-original-p1-v1"
IDS=tuple("AAA-200-%s-%03d"%("D" if n<=40 else "E" if n<=50 else "F",n)
          for n in range(36,61))
PHASES=("P1","P2","P3","P4","P5","P6","P7","P8")
TOPICS={
36:"readable_scene_focal_points",37:"nonrepeating_eyeline_rhythm",
38:"natural_style_variations",39:"original_player_camera_composition",
40:"purpose_of_every_visible_asset",41:"real_site_footprint_dimensions",
42:"coordinate_axes_and_origin",43:"building_spacing_measured",
44:"main_and_secondary_pedestrian_routes",45:"accessible_zone_boundaries",
46:"entrance_exit_lines_of_sight",47:"structure_clearance_before_build",
48:"building_ground_height_contact",49:"prior_asset_intersections",
50:"approved_scene_placement_locked",
51:"simple_blockout_geometry_original",52:"blockout_model_scale_check",
53:"original_orientation_measured",54:"module_junction_alignment",
55:"actual_player_clearance_blockout",56:"four_independent_camera_views",
57:"design_faults_identified_pre_detail",58:"adjacent_component_joins",
59:"structural_errors_corrected_pre_final",60:"blockout_gate_must_block_detail"
}
class Source25Blocked(ValueError):pass
def need(v,reason):
    if not v: raise Source25Blocked(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def canonical(inv):
    need(type(inv) is dict and
         inv.get("schema")=="gg-effective-family-inventory-v1" and
         inv.get("rule_count")==763 and
         inv.get("source_digests",{}).get("aaa_catalog")==CATALOG_SHA and
         len(IDS)==len(set(IDS))==len(TOPICS)==25 and
         set(TOPICS)==set(range(36,61)) and
         len(set(TOPICS.values()))==25,
         "C07_D036_F060_EXACT_25_ORIGINAL_CLAUSES_REQUIRED")
    for n,rid in enumerate(IDS,36):
        sec,clause,phase,kind=CLAUSES[n]
        row=inv.get("rules",{}).get(rid,{})
        need(sec==rid.split("-")[2] and phase=="P1" and kind=="all" and
             P1_TEXT.get(str(n))==clause and
             row.get("family")=="AAA-200" and
             row.get("catalog_number")==n and
             row.get("catalog_section")==sec and
             row.get("catalog_phase")=="P1" and
             row.get("asset_type")=="all" and
             row.get("source_sha256")==CATALOG_SHA and
             row.get("requirement")==clause and
             row.get("requirement_sha256")==sha(clause.encode("utf-8")) and
             type(SPEC.get(n)) in (tuple,list) and len(SPEC[n])==4 and
             len(set(SPEC[n]))==4,
             "C07_D036_F060_CANONICAL_REQUIREMENT_CHANGED:"+rid)

def inspect(context):
    need(type(context) is dict and
         set(context)=={"inventory","plan","controller","asset",
                        "step","work","source_loader"} and
         callable(context["source_loader"]),
         "C07_D036_F060_REAL_SOURCE_CONTEXT_REQUIRED")
    inv=context["inventory"];plan=context["plan"];work=context["work"]
    ctrl=context["controller"];asset=context["asset"];step=context["step"]
    canonical(inv)
    need(type(plan) is dict and type(work) is dict and
         plan.get("phase")==work.get("phase") and
         work.get("phase") in PHASES and
         plan.get("master_sha256")==work.get("master_sha256")==
             inv.get("canonical_master_sha256") and
         type(work.get("attempt_id")) is str and
         re.fullmatch("[a-f0-9]{64}",work["attempt_id"]) and
         type(work.get("operation_sha256")) is str and
         re.fullmatch("[a-f0-9]{64}",work["operation_sha256"]),
         "C07_D036_F060_CURRENT_PHASE_ATTEMPT_REQUIRED")
    master=ctrl.master.read_bytes()
    need(type(master) is bytes and sha(master)==work["master_sha256"],
         "C07_D036_F060_MASTER_BYTES_CHANGED")
    args=(inv,plan,ctrl,asset,step,work)
    kw={"source_loader":context["source_loader"]}
    bf=inspect_bf(*args,**kw)
    p1=inspect_p1(*args,**kw)
    audit=ctrl.audit_path(asset).read_bytes()
    need(type(audit) is bytes,"C07_D036_F060_REAL_AUDIT_BYTES_REQUIRED")
    mg0=inspect_mg0(master,audit,asset,work["master_sha256"],
                    list(IDS),work["attempt_id"])
    need(bf.get("schema")==BF_SCHEMA and
         p1.get("schema")==P1_SCHEMA and
         bf.get("source_rules_examined")==50 and
         p1.get("source_rules_examined")==30 and
         bf.get("native_conditions_evaluated")==200 and
         p1.get("native_domain_criteria")==90 and
         set(mg0.get("rules",{}))==set(IDS) and
         mg0.get("rule_count")==25 and
         mg0.get("counts",{}).get("PASS")==0 and
         bf.get("original_audit_sha256")==
           p1.get("original_audit_sha256")==
           mg0.get("audit_sha256")==sha(audit) and
         bf.get("original_audit_tail")==
           p1.get("original_audit_tail")==mg0.get("audit_tail_sha256") and
         bf.get("attempt_id")==p1.get("attempt_id")==
           mg0.get("attempt_id")==work["attempt_id"] and
         bf.get("operation_sha256")==p1.get("operation_sha256")==
           work["operation_sha256"] and
         p1.get("master_sha256")==work["master_sha256"] and
         bf.get("full_rule_passes")==p1.get("full_semantic_passes")==0 and
         bf.get("individual_mg0_passes")==
           p1.get("individual_mg0_passes")==
           mg0.get("individual_mg0_passes")==0 and
         all(v.get("advancement_authorized") is False for v in (bf,p1,mg0)),
         "C07_D036_F060_ORIGINAL_EVIDENCE_REPLAY_DIVERGED")
    result={};checked=observed=failures=0
    for n,rid in enumerate(IDS,36):
        a=bf.get("rules",{}).get(rid);b=p1.get("rules",{}).get(rid)
        orig=inv["rules"][rid]
        need(type(a) is dict and type(b) is dict and
             a.get("rule_id")==b.get("rule_id")==rid and
             a.get("source_sha256")==b.get("source_sha256")==
                orig["source_sha256"] and
             a.get("requirement_sha256")==b.get("requirement_sha256")==
                orig["requirement_sha256"] and
             a.get("canonical_requirement")==orig["requirement"] and
             a.get("applicability")=="DUE" and
             a.get("full_rule_semantics")==b.get("full_rule_semantics")=="UNKNOWN" and
             a.get("individual_mg0")==b.get("individual_mg0")=="UNKNOWN" and
             a.get("owner_approval")=="UNKNOWN" and
             b.get("artistic_approval")=="UNKNOWN" and
             a.get("advancement_authorized") is False and
             b.get("advancement_authorized") is False,
             "C07_D036_F060_ORIGINAL_PER_RULE_SOURCE_DRIFT:"+rid)
        native=a.get("original_native_predicates")
        second=b.get("original_native_measured_criteria")
        need(type(native) is dict and set(native)==set(SPEC[n]) and
             len(native)==4 and all(type(x) is bool for x in native.values()) and
             type(second) is dict and len(second)==3 and
             all(type(x) is bool for x in second.values()),
             "C07_D036_F060_REQUIRED_SEVEN_SEMANTIC_SUBCHECKS:"+rid)
        checks={**{"native:"+k:v for k,v in native.items()},
                **{"independent:"+k:v for k,v in second.items()}}
        need(len(checks)==7,
             "C07_D036_F060_SEVEN_INDEPENDENT_SOURCE_KEYS_REQUIRED:"+rid)
        observation=mg0["rules"].get(rid,{})
        need(type(observation) is dict and
             observation.get("verdict") in ("UNKNOWN","FAIL") and
             type(observation.get("uncorrected_failure_count")) is int and
             observation["uncorrected_failure_count"]>=0 and
             type(observation.get("observation_sha256")) is str and
             re.fullmatch("[a-f0-9]{64}",observation["observation_sha256"]),
             "C07_D036_F060_REAL_INDEPENDENT_MG0_NEGATIVE:"+rid)
        bad=observation["verdict"]=="FAIL" or observation["uncorrected_failure_count"]>0
        checked+=len(checks);observed+=sum(checks.values());failures+=int(bad)
        result[rid]={
           "rule_id":rid,"original_clause":orig["requirement"],
           "source_sha256":orig["source_sha256"],
           "requirement_sha256":orig["requirement_sha256"],
           "semantic_subject":TOPICS[n],"required_phase":"P1",
           "applicability":"DUE","original_machine_subchecks":checks,
           "machine_subchecks_observed":sum(checks.values()),
           "missing_machine_subchecks":sorted(k for k,v in checks.items() if not v),
           "original_negative_mg0_verdict":observation["verdict"],
           "uncorrected_independent_mg0_failures":observation["uncorrected_failure_count"],
           "mg0_observation_sha256":observation["observation_sha256"],
           "semantic_verdict":"FAIL" if bad else "UNKNOWN",
           "full_clause_semantic_certified":False,
           "independent_mg0_certified":False,
           "advancement_authorized":False,
        }
    need(len(result)==25 and set(result)==set(IDS) and checked==175,
         "C07_D036_F060_FULL_25_BY_7_SOURCE_SUBCHECKS_REQUIRED")
    return {
      "schema":SCHEMA,"rule_count":25,"canonical_source_clauses":25,
      "actual_machine_subchecks_checked":checked,
      "actual_machine_subchecks_observed":observed,
      "negative_mg0_failures":failures,
      "original_audit_sha256":sha(audit),
      "original_audit_tail":mg0["audit_tail_sha256"],
      "master_sha256":work["master_sha256"],
      "attempt_id":work["attempt_id"],
      "operation_sha256":work["operation_sha256"],
      "full_rule_semantic_passes":0,"individual_mg0_passes":0,
      "advancement_authorized":False,"rules":result
    }

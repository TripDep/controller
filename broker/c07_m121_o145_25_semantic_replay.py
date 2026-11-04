"""C07 M121..O145: 25 original-source material/light/LOD semantic reviews.

Reuses TWO independently authored, real-byte Controller evidence readers:
M121-Q170 original GLB/PBR/material/visual analysis and R146 P3-P5
technical geometry/raster/LOD evidence; verifies individual MG0 negative
findings on the same active work and immutable catalog. Does not accept a
producer PASS, invent art/engine tests, forge owner review, or certify MG0.

For P3 the entire cohort is future, at P4 M/N (20) are due, and at P5
all 25 are due. Each rule retains its original entire clause.
"""
import hashlib
import re

from c07_m121_q170_fifty_native import (
    SCHEMA as MQ_SCHEMA, CATALOG_SHA, CLAUSES as MQ_CLAUSES,
    RULE_PREDICATES as MQ_PREDICATES, inspect as inspect_mq)
from c07_p345_forty_native_evidence import (
    SCHEMA as R146_SCHEMA, TEXT as R146_TEXT, inspect as inspect_r146)
from c07_mg0_individual import inspect_batch as inspect_mg0

SCHEMA="gg-c07-m121-o145-25-source-semantic-replay-v1"
IDS=tuple(
    "AAA-200-%s-%03d"%(
        "M" if n<=130 else "N" if n<=140 else "O",n)
    for n in range(121,146))
PHASES={"P3":3,"P4":4,"P5":5,"P6":6,"P7":7,"P8":8}
CLAUSES={rid:MQ_CLAUSES[n] for n,rid in enumerate(IDS,121)}
REQUIRED_PHASE={rid:("P4" if n<=140 else "P5")
                for n,rid in enumerate(IDS,121)}
# Rule-specific intent, derived from unchanged source clauses, not extra rules.
TOPICS={
121:"material_identity",122:"physically_grounded_roughness_reflectance",
123:"supported_normal_roughness_maps",124:"non_artificial_basecolors",
125:"credible_surface_variation",126:"different_wood_stone_metal_glass_plaster",
127:"appropriately_weathered_texture",128:"texture_resolution_compression_cost",
129:"destination_engine_shader_compatibility",130:"multilight_material_coherence",
131:"neutral_control_lighting",132:"neutral_vs_cinematic_lighting_separation",
133:"lighting_reveals_geometry_errors",134:"material_direct_lighting_behavior",
135:"material_shadow_behavior",136:"reflective_metal_glass_inspection",
137:"player_camera_visual_qa",138:"four_independent_qa_view_angles",
139:"render_not_hiding_defects",140:"presentation_vs_technical_quality",
141:"documented_platform_performance_budget",142:"measured_mesh_triangle_count",
143:"unneeded_hidden_geometry_removed",144:"distance_appropriate_lod",
145:"visual_lod_transition_quality"}
class Batch25Blocked(ValueError): pass
def need(cond,why):
    if not cond: raise Batch25Blocked(why)
def sha(raw): return hashlib.sha256(raw).hexdigest()

def canonical(inventory):
    need(type(inventory) is dict and
         inventory.get("schema")=="gg-effective-family-inventory-v1" and
         inventory.get("rule_count")==763 and
         inventory.get("source_digests",{}).get("aaa_catalog")==CATALOG_SHA and
         len(CLAUSES)==len(REQUIRED_PHASE)==len(IDS)==len(TOPICS)==25 and
         set(CLAUSES)==set(REQUIRED_PHASE)==set(IDS) and
         set(TOPICS)==set(range(121,146)) and
         len(set(TOPICS.values()))==25,
         "C07_M121_O145_ALL_25_ORIGINAL_CATALOG_RULES_REQUIRED")
    for n,rid in enumerate(IDS,121):
        orig=CLAUSES[rid]; phase=REQUIRED_PHASE[rid]
        r146=R146_TEXT.get(str(n))
        row=inventory.get("rules",{}).get(rid,{})
        need(r146==[orig,phase] and
             row.get("family")=="AAA-200" and
             row.get("catalog_number")==n and
             row.get("catalog_section")==rid.split("-")[2] and
             row.get("catalog_phase")==phase and
             row.get("asset_type")=="all" and
             row.get("source_sha256")==CATALOG_SHA and
             row.get("requirement")==orig and
             row.get("requirement_sha256")==sha(orig.encode("utf-8")) and
             type(MQ_PREDICATES.get(n)) in (tuple,list) and
             len(MQ_PREDICATES[n])>=3,
             "C07_M121_O145_ORIGINAL_SOURCE_REQUIREMENT_CHANGED:"+rid)

def inspect(context):
    need(type(context) is dict and
         set(context)=={"inventory","plan","controller","asset","step",
                        "work","source_loader"} and
         callable(context["source_loader"]),
         "C07_M121_O145_REAL_SOURCE_CONTEXT_REQUIRED")
    inv=context["inventory"];plan=context["plan"];work=context["work"]
    controller=context["controller"];asset=context["asset"];step=context["step"]
    canonical(inv)
    need(type(work) is dict and
         type(plan) is dict and work.get("phase") in PHASES and
         plan.get("phase")==work["phase"] and
         plan.get("master_sha256")==work.get("master_sha256")==
             inv.get("canonical_master_sha256") and
         type(work.get("attempt_id")) is str and
         re.fullmatch("[a-f0-9]{64}",work["attempt_id"]) and
         type(work.get("operation_sha256")) is str and
         re.fullmatch("[a-f0-9]{64}",work["operation_sha256"]),
         "C07_M121_O145_ORIGINAL_ATTEMPT_AND_PHASE_REQUIRED")
    master=controller.master.read_bytes()
    need(type(master) is bytes and sha(master)==work["master_sha256"],
         "C07_M121_O145_ORIGINAL_MASTER_BYTES_CHANGED")
    args=(inv,plan,controller,asset,step,work)
    kw={"source_loader":context["source_loader"]}
    mq=inspect_mq(*args,**kw)
    r146=inspect_r146(*args,**kw)
    audit=controller.audit_path(asset).read_bytes()
    need(type(audit) is bytes,
         "C07_M121_O145_ORIGINAL_AUDIT_BYTES_REQUIRED")
    mg0=inspect_mg0(master,audit,asset,work["master_sha256"],
                    list(IDS),work["attempt_id"])
    need(mq.get("schema")==MQ_SCHEMA and r146.get("schema")==R146_SCHEMA and
         mq.get("source_rules_examined")==50 and
         r146.get("source_rule_count")==40 and
         mq.get("native_predicates_evaluated",0)>=150 and
         r146.get("native_named_domain_checks")==80 and
         len(mq.get("rules",{}))==50 and len(r146.get("rules",{}))==40 and
         mg0.get("rule_count")==25 and
         set(mg0.get("rules",{}))==set(IDS) and
         mq.get("original_audit_sha256")==
             r146.get("original_audit_sha256")==
             mg0.get("audit_sha256")==sha(audit) and
         mq.get("original_audit_tail")==r146.get("original_audit_tail")==
             mg0.get("audit_tail_sha256") and
         mq.get("attempt_id")==r146.get("attempt_id")==
             mg0.get("attempt_id")==work["attempt_id"] and
         mq.get("operation_sha256")==r146.get("operation_sha256")==
             work["operation_sha256"] and
         r146.get("master_sha256")==work["master_sha256"] and
         mq.get("full_rule_passes")==r146.get("full_rule_passes")==0 and
         mq.get("individual_mg0_passes")==
             r146.get("individual_mg0_passes")==
             mg0.get("individual_mg0_passes")==0 and
         mq.get("advancement_authorized") is False and
         r146.get("advancement_authorized") is False and
         mg0.get("advancement_authorized") is False,
         "C07_M121_O145_THREE_ORIGINAL_SOURCE_ENGINES_DISAGREE")
    rows={}
    checked=observed=negative=0
    for n,rid in enumerate(IDS,121):
        left=mq["rules"].get(rid)
        right=r146["rules"].get(rid)
        original=inv["rules"][rid]
        need(type(left) is dict and type(right) is dict and
             left.get("rule_id")==right.get("rule_id")==rid and
             left.get("canonical_requirement")==CLAUSES[rid] and
             left.get("canonical_source_sha256")==
                 right.get("source_sha256")==original["source_sha256"] and
             left.get("requirement_sha256")==
                 right.get("requirement_sha256")==original["requirement_sha256"] and
             left.get("full_rule_semantics")=="UNKNOWN" and
             left.get("individual_mg0")=="UNKNOWN" and
             left.get("owner_approval")=="UNKNOWN" and
             left.get("advancement_authorized") is False and
             right.get("full_rule_semantics") in ("UNKNOWN","NOT_DUE") and
             right.get("individual_mg0") in ("UNKNOWN","NOT_DUE") and
             right.get("owner_acceptance")=="UNKNOWN" and
             right.get("advancement_authorized") is False and
             right.get("earliest_phase")==REQUIRED_PHASE[rid],
             "C07_M121_O145_FALSIFIED_OR_DIFFERENT_RULE:"+rid)
        machine=left.get("original_native_predicates")
        observed_right=right.get("machine_observations")
        need(type(machine) is dict and len(machine)==len(MQ_PREDICATES[n]) and
             set(machine)==set(MQ_PREDICATES[n]) and
             all(type(x) is bool for x in machine.values()) and
             type(observed_right) is dict,
             "C07_M121_O145_SOURCE_SPECIFIC_PREDICATES_REQUIRED:"+rid)
        due=PHASES[work["phase"]]>=PHASES[REQUIRED_PHASE[rid]]
        need(right.get("applicability")==("DUE" if due else "FUTURE_PHASE") and
             (len(observed_right)==2 and
              all(type(x) is bool for x in observed_right.values()) if due
              else observed_right=={}),
             "C07_M121_O145_PHASE_SCOPED_EVIDENCE_MISMATCH:"+rid)
        # On a future-phase rule, even valid generic GLB machine facts cannot
        # be credited as that rule's required P4/P5 completed inspection.
        details=({
            **{"native:"+k:v for k,v in machine.items()},
            **{"independent:"+k:v for k,v in observed_right.items()}
          } if due else {})
        obs=mg0["rules"][rid]
        need(type(obs) is dict and
             obs.get("verdict") in ("UNKNOWN","FAIL") and
             type(obs.get("uncorrected_failure_count")) is int and
             obs["uncorrected_failure_count"]>=0 and
             type(obs.get("observation_sha256")) is str and
             re.fullmatch("[a-f0-9]{64}",obs["observation_sha256"]),
             "C07_M121_O145_AUTHENTIC_NEGATIVE_MG0_REQUIRED:"+rid)
        fail=obs["verdict"]=="FAIL" or obs["uncorrected_failure_count"]>0
        checked+=len(details);observed+=sum(details.values());negative+=int(fail)
        rows[rid]={
            "rule_id":rid,"original_clause":CLAUSES[rid],
            "source_sha256":original["source_sha256"],
            "requirement_sha256":original["requirement_sha256"],
            "semantic_subject":TOPICS[n],
            "required_phase":REQUIRED_PHASE[rid],
            "applicability":"DUE" if due else "FUTURE_PHASE",
            "replayed_machine_checks":details,
            "replayed_positive_subchecks":sum(details.values()),
            "missing_subchecks":sorted(k for k,v in details.items() if not v),
            "original_negative_verdict":obs["verdict"],
            "uncorrected_mg0_failures":obs["uncorrected_failure_count"],
            "mg0_observation_sha256":obs["observation_sha256"],
            "semantic_verdict":"FAIL" if fail else (
                "UNKNOWN" if due else "NOT_DUE"),
            "full_original_semantics_pass":False,
            "independent_mg0_pass":False,
            "advancement_authorized":False,
        }
    need(len(rows)==25 and set(rows)==set(IDS) and
         all(len(r["replayed_machine_checks"])>=5
             for r in rows.values() if r["applicability"]=="DUE") and
         all(not r["replayed_machine_checks"]
             for r in rows.values() if r["applicability"]=="FUTURE_PHASE"),
         "C07_M121_O145_TWENTY_FIVE_EXACT_ORIGINAL_RULES_REQUIRED")
    return {
      "schema":SCHEMA,"rule_count":25,"original_clause_count":25,
      "current_phase":work["phase"],
      "due_rules":sum(r["applicability"]=="DUE" for r in rows.values()),
      "future_phase_rules":sum(r["applicability"]=="FUTURE_PHASE" for r in rows.values()),
      "original_named_semantic_subchecks":checked,
      "source_observations_positive":observed,
      "independent_negative_failures":negative,
      "original_audit_sha256":sha(audit),
      "original_audit_tail":mg0["audit_tail_sha256"],
      "master_sha256":work["master_sha256"],
      "attempt_id":work["attempt_id"],
      "operation_sha256":work["operation_sha256"],
      "full_rule_semantic_passes":0,"individual_mg0_passes":0,
      "advancement_authorized":False,"rules":rows
    }

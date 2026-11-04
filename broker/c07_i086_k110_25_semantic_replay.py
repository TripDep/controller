"""C07 fifth 25-rule macro I086-K110: canonical P2 organic, vegetation, terrain.

Cross-read two independently written original asset-byte semantic observers
and the authentic negative MG0 audit for exactly one active operation.
Machine subcriteria are neither full semantic rule PASS nor MG0 approval.
Different asset classes are N_A, never counted as positive.
"""
import hashlib
import re

from c07_gk50_canonical import CLAUSES, CATALOG_SHA
from c07_gk50_predicates import SPEC
from c07_g061_k110_fifty_native import SCHEMA as GK_SCHEMA, inspect as inspect_gk
from c07_p2_fifty_asset_type_domain import (
    SCHEMA as P2_SCHEMA, TEXT as P2_TEXT, inspect as inspect_p2)
from c07_mg0_individual import inspect_batch as inspect_mg0

SCHEMA="gg-c07-i086-k110-25-independent-source-scopes-v1"
IDS=tuple("AAA-200-%s-%03d"%(
    "I" if n<=90 else "J" if n<=100 else "K", n)
    for n in range(86,111))
GROUPS={"organic":5,"vegetation":10,"terrain":10}
TOPICS={
86:"original_rock_erosion_material",87:"original_rock_repetition",
88:"terrain_rock_ground_contact",89:"rock_visual_fidelity_vs_mesh_budget",
90:"original_rock_close_and_wide_qa",
91:"native_species_climate_reference",92:"measured_plant_silhouette_height",
93:"original_plant_branch_hierarchy",94:"botanical_growth_structure",
95:"foliage_alpha_card_method",96:"leaf_alpha_channel_original_bytes",
97:"botanical_canopy_nonrepetition",98:"botanical_plant_variants",
99:"vegetation_real_lod_evidence",100:"fivem_wind_material_runtime_receipt",
101:"original_terrain_survey_world_points",102:"noninvented_elevation_levels",
103:"water_constructed_natural_surface_separation",
104:"source_contours_no_arbitrary_relief",
105:"original_terrain_paths_aerial",106:"terrain_stairs_bridge_landings",
107:"shoreline_reference_and_water_height",108:"water_terrain_rock_contact",
109:"bridge_walkway_world_elevations",
110:"water_native_visual_and_runtime"}
class CohortBlocked(ValueError):pass
def need(ok,reason):
    if not ok:raise CohortBlocked(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def canonical(inventory):
    need(type(inventory) is dict and
         inventory.get("schema")=="gg-effective-family-inventory-v1" and
         inventory.get("rule_count")==763 and
         inventory.get("source_digests",{}).get("aaa_catalog")==CATALOG_SHA and
         len(IDS)==len(set(IDS))==len(TOPICS)==25 and
         set(TOPICS)==set(range(86,111)) and
         set(GROUPS)=={"organic","vegetation","terrain"} and
         sum(GROUPS.values())==25 and len(set(TOPICS.values()))==25,
         "C07_I086_K110_EXACT_25_ORIGINAL_RULES_REQUIRED")
    for n,rid in enumerate(IDS,86):
        section,clause,phase,kind=CLAUSES[n]
        item=inventory.get("rules",{}).get(rid,{})
        need(rid=="AAA-200-"+section+"-%03d"%n and
             P2_TEXT.get(str(n))==[clause,kind] and
             phase=="P2" and kind in GROUPS and
             item.get("family")=="AAA-200" and
             item.get("catalog_number")==n and
             item.get("catalog_section")==section and
             item.get("catalog_phase")==phase and
             item.get("asset_type")==kind and
             item.get("source_sha256")==CATALOG_SHA and
             item.get("requirement")==clause and
             item.get("requirement_sha256")==sha(clause.encode("utf-8")) and
             type(SPEC.get(n)) in (list,tuple) and len(SPEC[n])>=3 and
             len(set(SPEC[n]))==len(SPEC[n]),
             "C07_I086_K110_CANONICAL_CLAUSE_CHANGED:"+rid)

def inspect(context):
    need(type(context) is dict and set(context)=={
             "inventory","plan","controller","asset","step","work",
             "source_loader"} and callable(context["source_loader"]),
         "C07_I086_K110_CURRENT_ORIGINAL_CONTEXT_REQUIRED")
    inv=context["inventory"];plan=context["plan"];work=context["work"]
    c=context["controller"];asset=context["asset"];step=context["step"]
    canonical(inv)
    need(type(plan) is dict and type(work) is dict and
         plan.get("phase")==work.get("phase") and
         work.get("phase") in ("P2","P3","P4","P5","P6","P7","P8") and
         plan.get("asset_type")==work.get("asset_type") and
         work.get("asset_type") in ("architecture","organic","vegetation","terrain") and
         plan.get("master_sha256")==work.get("master_sha256")==
             inv.get("canonical_master_sha256") and
         type(work.get("attempt_id")) is str and
         re.fullmatch("[a-f0-9]{64}",work["attempt_id"]) and
         type(work.get("operation_sha256")) is str and
         re.fullmatch("[a-f0-9]{64}",work["operation_sha256"]),
         "C07_I086_K110_CURRENT_PLAN_PHASE_OR_ATTEMPT_REQUIRED")
    master=c.master.read_bytes()
    need(type(master) is bytes and sha(master)==work["master_sha256"],
         "C07_I086_K110_REAL_ORIGINAL_MASTER_CHANGED")
    args=(inv,plan,c,asset,step,work)
    opts={"source_loader":context["source_loader"]}
    gk=inspect_gk(*args,**opts)
    p2=inspect_p2(*args,**opts)
    audit=c.audit_path(asset).read_bytes()
    need(type(audit) is bytes,"C07_I086_K110_REAL_AUDIT_REQUIRED")
    mg=inspect_mg0(master,audit,asset,work["master_sha256"],
                   list(IDS),work["attempt_id"])
    need(gk.get("schema")==GK_SCHEMA and p2.get("schema")==P2_SCHEMA and
         gk.get("source_rules_examined")==50 and
         p2.get("canonical_source_rule_count")==50 and
         gk.get("native_conditions_evaluated",0)>=150 and
         p2.get("named_domain_probes")==100 and
         mg.get("rule_count")==25 and
         set(mg.get("rules",{}))==set(IDS) and
         mg.get("counts",{}).get("PASS")==0 and
         gk.get("original_audit_sha256")==
             p2.get("original_audit_sha256")==
             mg.get("audit_sha256")==sha(audit) and
         gk.get("original_audit_tail")==
             p2.get("original_audit_tail")==mg.get("audit_tail_sha256") and
         gk.get("attempt_id")==p2.get("attempt_id")==
             mg.get("attempt_id")==work["attempt_id"] and
         gk.get("operation_sha256")==p2.get("operation_sha256")==
             work["operation_sha256"] and
         p2.get("master_sha256")==work["master_sha256"] and
         gk.get("full_rule_passes")==p2.get("full_semantic_passes")==0 and
         gk.get("individual_mg0_passes")==
             p2.get("individual_mg0_passes")==
             mg.get("individual_mg0_passes")==0 and
         all(x.get("advancement_authorized") is False for x in (gk,p2,mg)),
         "C07_I086_K110_ORIGINAL_READBACK_ENGINES_DISAGREE")
    results={};observed=checked=negative=0
    for n,rid in enumerate(IDS,86):
        kind=CLAUSES[n][3]
        orig=inv["rules"][rid]
        left=gk.get("rules",{}).get(rid)
        right=p2.get("rules",{}).get(rid)
        due=work["asset_type"]==kind
        need(type(left) is dict and type(right) is dict and
             left.get("rule_id")==right.get("rule_id")==rid and
             left.get("source_sha256")==
                 right.get("source_sha256")==orig["source_sha256"] and
             left.get("requirement_sha256")==
                 right.get("requirement_sha256")==orig["requirement_sha256"] and
             left.get("canonical_requirement")==orig["requirement"] and
             left.get("applicability")==right.get("applicability")==(
                 "DUE" if due else "N_A_ASSET_TYPE") and
             left.get("full_rule_semantics")=="UNKNOWN" and
             left.get("individual_mg0")=="UNKNOWN" and
             left.get("owner_approval")=="UNKNOWN" and
             left.get("advancement_authorized") is False and
             right.get("full_rule_semantics") in ("UNKNOWN","NOT_DUE") and
             right.get("individual_mg0") in ("UNKNOWN","NOT_DUE") and
             right.get("owner_approval")=="UNKNOWN" and
             right.get("advancement_authorized") is False and
             right.get("source_asset_type")==kind and
             right.get("current_asset_type")==work["asset_type"],
             "C07_I086_K110_DIFFERENT_ORIGINAL_RULE_OR_TYPE:"+rid)
        native=left.get("native_byte_checks")
        independent=right.get("original_native_domain_predicates")
        need(type(native) is dict and
             set(native)==set(SPEC[n]) and
             len(native)==len(SPEC[n]) and
             all(type(x) is bool for x in native.values()) and
             type(independent) is dict and
             (len(independent)==2 and
              all(type(x) is bool for x in independent.values())
              if due else independent=={}),
             "C07_I086_K110_ORIGINAL_RULE_EVIDENCE_REQUIRED:"+rid)
        readings=({
            **{"native:"+key:val for key,val in native.items()},
            **{"independent:"+key:val for key,val in independent.items()}
        } if due else {})
        finding=mg["rules"][rid]
        need(type(finding) is dict and
             finding.get("verdict") in ("FAIL","UNKNOWN") and
             type(finding.get("uncorrected_failure_count")) is int and
             finding["uncorrected_failure_count"]>=0 and
             type(finding.get("observation_sha256")) is str and
             re.fullmatch("[a-f0-9]{64}",finding["observation_sha256"]),
             "C07_I086_K110_REAL_MG0_NEGATIVE_READBACK_REQUIRED:"+rid)
        fail=finding["verdict"]=="FAIL" or finding["uncorrected_failure_count"]>0
        negative+=int(fail);checked+=len(readings);observed+=sum(readings.values())
        results[rid]={
            "rule_id":rid,"original_requirement":orig["requirement"],
            "source_sha256":orig["source_sha256"],
            "requirement_sha256":orig["requirement_sha256"],
            "semantic_subject":TOPICS[n],"required_phase":"P2",
            "required_asset_type":kind,
            "applicability":"DUE" if due else "N_A_ASSET_TYPE",
            "machine_subcriteria":readings,
            "machine_subcriteria_true":sum(readings.values()),
            "missing_source_subcriteria":sorted(k for k,v in readings.items() if not v),
            "original_negative_mg0_verdict":finding["verdict"],
            "uncorrected_mg0_failures":finding["uncorrected_failure_count"],
            "mg0_original_observation_sha256":finding["observation_sha256"],
            "source_semantics_verdict":"FAIL" if fail else
               "UNKNOWN" if due else "NOT_DUE",
            "original_full_clause_certified":False,
            "individual_mg0_certified":False,
            "advancement_authorized":False,
        }
    need(len(results)==25 and set(results)==set(IDS) and
         all(len(v["machine_subcriteria"])>=5 for v in results.values()
             if v["applicability"]=="DUE") and
         all(v["machine_subcriteria"]=={} for v in results.values()
             if v["applicability"]=="N_A_ASSET_TYPE"),
         "C07_I086_K110_COMPLETE_25_CURRENT_SOURCE_SCOPES_REQUIRED")
    return {
        "schema":SCHEMA,"rule_count":25,"source_original_clauses":25,
        "current_asset_type":work["asset_type"],
        "current_phase":work["phase"],
        "due_rules":sum(v["applicability"]=="DUE" for v in results.values()),
        "not_applicable_rules":sum(v["applicability"]!="DUE" for v in results.values()),
        "machine_subcriteria_checked":checked,
        "machine_positive_subcriteria":observed,
        "independent_negative_mg0_failures":negative,
        "original_audit_sha256":sha(audit),
        "original_audit_tail":mg["audit_tail_sha256"],
        "master_sha256":work["master_sha256"],
        "attempt_id":work["attempt_id"],
        "operation_sha256":work["operation_sha256"],
        "full_rule_semantic_passes":0,"independent_mg0_passes":0,
        "advancement_authorized":False,"rules":results
    }

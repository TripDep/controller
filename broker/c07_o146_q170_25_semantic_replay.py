"""C07 O146..Q170 — 25 exact original material optimization, collision and FiveM semantic checks.

Real-source, non-certifying macro using already independently authored
M121-Q170 original-byte GLB/native evidence, R146 P3-P5 technical QA,
R147 P6-P8 collision/native-FiveM evidence (only when phase is due), and
MG0 original hash-chained negative readback.

An observed machine subpredicate is NOT a final semantic PASS, FiveM-in-game
evidence, owner approval or MG0 certification. Missing and FUTURE_PHASE
requirements never advance a production asset.
"""
import hashlib
import re
from c07_m121_q170_fifty_native import (
    SCHEMA as MQ_SCHEMA, CLAUSES as MQ_CLAUSES,
    CATALOG_SHA, RULE_PREDICATES as MQ_PREDICATES,
    inspect as inspect_mq)
from c07_p345_forty_native_evidence import (
    SCHEMA as P345_SCHEMA, TEXT as P345_TEXT, inspect as inspect_p345)
from c07_p678_forty_native_domain import (
    SCHEMA as P678_SCHEMA, TEXT as P678_TEXT, inspect as inspect_p678)
from c07_mg0_individual import inspect_batch as inspect_mg0

SCHEMA="gg-c07-o146-q170-exact25-source-semantic-readback-v1"
IDS=tuple("AAA-200-%s-%03d"%(
    "O" if n<=150 else "P" if n<=160 else "Q",n)
    for n in range(146,171))
PHASE_INDEX={"P5":5,"P6":6,"P7":7,"P8":8}
CLAUSES={rid:MQ_CLAUSES[n] for n,rid in enumerate(IDS,146)}
REQUIRED_PHASE={rid:"P5" if n<=150 else "P6" if n<=160 else "P7"
                for n,rid in enumerate(IDS,146)}
TOPICS={
 146:"material_instance_optimization",
 147:"reuse_source_textures_without_loss",
 148:"measured_texture_memory_budget",
 149:"foliage_and_transparency_cost",
 150:"runtime_performance_not_fake_benchmarks",
 151:"collision_surfaces_declared",
 152:"separate_visual_and_collision_geometry",
 153:"collision_complexity_measured",
 154:"doors_stairs_corridors_and_railings_collision",
 155:"solid_surface_player_walktest",
 156:"absence_of_invisible_collision",
 157:"walkable_player_area_verification",
 158:"terrain_building_contact_collision",
 159:"vehicle_passage_clearance_verification",
 160:"live_game_collision_navigation",
 161:"gta_fivem_resource_membership",
 162:"actual_ydr_drawable_source",
 163:"actual_ytd_texture_dictionary_source",
 164:"actual_ytyp_archetype_source",
 165:"actual_ymap_placement_source",
 166:"actual_ybn_collision_source",
 167:"source_sollumz_export_profile",
 168:"rage_shader_and_vertex_attributes",
 169:"codewalker_lod_streaming_placement",
 170:"actual_fivem_runtime_playback"
}
class Semantic25Blocked(ValueError):pass
def need(ok,why):
    if not ok:raise Semantic25Blocked(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def canonical(inventory):
    """Validate all original 25 canonical clauses and per-rule evidence IDs."""
    need(type(inventory) is dict and
         inventory.get("schema")=="gg-effective-family-inventory-v1" and
         inventory.get("rule_count")==763 and
         inventory.get("source_digests",{}).get("aaa_catalog")==CATALOG_SHA and
         len(IDS)==len(set(IDS))==25 and
         len(CLAUSES)==len(REQUIRED_PHASE)==len(TOPICS)==25 and
         set(CLAUSES)==set(REQUIRED_PHASE)==set(IDS) and
         set(TOPICS)==set(range(146,171)) and
         len(set(TOPICS.values()))==25,
         "C07_O146_Q170_EXACT_25_CANONICAL_CLAUSES_REQUIRED")
    for n,rid in enumerate(IDS,146):
        orig=CLAUSES[rid]
        phase=REQUIRED_PHASE[rid]
        reader=(P345_TEXT if n<=150 else P678_TEXT)
        row=inventory.get("rules",{}).get(rid,{})
        need(reader.get(str(n))==[orig,phase] and
             row.get("family")=="AAA-200" and
             row.get("catalog_number")==n and
             row.get("catalog_section")==rid.split("-")[2] and
             row.get("catalog_phase")==phase and
             row.get("asset_type")=="all" and
             row.get("source_sha256")==CATALOG_SHA and
             row.get("requirement")==orig and
             row.get("requirement_sha256")==sha(orig.encode("utf-8")) and
             type(MQ_PREDICATES.get(n)) in (tuple,list) and
             len(MQ_PREDICATES[n])>=3 and
             len(set(MQ_PREDICATES[n]))==len(MQ_PREDICATES[n]),
             "C07_O146_Q170_SOURCE_OR_RULE_DRIFT:"+rid)

def inspect(context):
    need(type(context) is dict and set(context)=={
        "inventory","plan","controller","asset","step","work","source_loader"
    } and callable(context["source_loader"]),
         "C07_O146_Q170_REAL_SOURCE_CONTEXT_REQUIRED")
    inv=context["inventory"];plan=context["plan"];work=context["work"]
    controller=context["controller"];asset=context["asset"];step=context["step"]
    canonical(inv)
    need(type(plan) is dict and type(work) is dict and
         plan.get("phase")==work.get("phase") and
         work.get("phase") in PHASE_INDEX and
         plan.get("master_sha256")==work.get("master_sha256")==
             inv.get("canonical_master_sha256") and
         type(work.get("attempt_id")) is str and
         re.fullmatch("[a-f0-9]{64}",work["attempt_id"]) and
         type(work.get("operation_sha256")) is str and
         re.fullmatch("[a-f0-9]{64}",work["operation_sha256"]),
         "C07_O146_Q170_ORIGINAL_PLAN_PHASE_ATTEMPT_REQUIRED")
    master=controller.master.read_bytes()
    need(type(master) is bytes and sha(master)==work["master_sha256"],
         "C07_O146_Q170_MASTER_ORIGINAL_BYTES_CHANGED")
    args=(inv,plan,controller,asset,step,work)
    kw={"source_loader":context["source_loader"]}
    mq=inspect_mq(*args,**kw)
    p345=inspect_p345(*args,**kw)
    p678=inspect_p678(*args,**kw) if PHASE_INDEX[work["phase"]]>=6 else None
    audit=controller.audit_path(asset).read_bytes()
    need(type(audit) is bytes,
         "C07_O146_Q170_ORIGINAL_AUDIT_BYTES_REQUIRED")
    mg0=inspect_mg0(master,audit,asset,work["master_sha256"],
                    list(IDS),work["attempt_id"])
    engine_reports=[mq,p345]+([p678] if p678 is not None else [])
    need(mq.get("schema")==MQ_SCHEMA and
         p345.get("schema")==P345_SCHEMA and
         mq.get("source_rules_examined")==50 and
         p345.get("source_rule_count")==40 and
         mq.get("native_predicates_evaluated",0)>=150 and
         p345.get("native_named_domain_checks")==80 and
         len(mq.get("rules",{}))==50 and
         len(p345.get("rules",{}))==40 and
         (p678 is None or (p678.get("schema")==P678_SCHEMA and
          p678.get("source_rule_count")==40 and
          p678.get("named_machine_criteria")==80 and
          len(p678.get("rules",{}))==40)) and
         mg0.get("rule_count")==25 and
         set(mg0.get("rules",{}))==set(IDS) and
         mg0.get("counts",{}).get("PASS")==0 and
         all(e.get("original_audit_sha256")==
             mg0.get("audit_sha256")==sha(audit)
             for e in engine_reports) and
         all(e.get("original_audit_tail")==
             mg0.get("audit_tail_sha256")
             for e in engine_reports) and
         all(e.get("attempt_id")==mg0.get("attempt_id")==
             work["attempt_id"] for e in engine_reports) and
         all(e.get("operation_sha256")==work["operation_sha256"]
             for e in engine_reports) and
         p345.get("master_sha256")==work["master_sha256"] and
         (p678 is None or p678.get("master_sha256")==work["master_sha256"]) and
         mq.get("full_rule_passes")==p345.get("full_rule_passes")==0 and
         (p678 is None or p678.get("full_semantic_passes")==0) and
         mq.get("individual_mg0_passes")==
             p345.get("individual_mg0_passes")==
             mg0.get("individual_mg0_passes")==0 and
         (p678 is None or p678.get("individual_mg0_passes")==0) and
         all(e.get("advancement_authorized") is False
             for e in engine_reports) and
         mg0.get("advancement_authorized") is False,
         "C07_O146_Q170_ORIGINAL_SOURCE_REPLAYS_DISAGREE")
    rows={}
    observed=checked=failures=0
    for n,rid in enumerate(IDS,146):
        native=mq["rules"].get(rid)
        reader=(p345 if n<=150 else p678)
        if reader is None:
            independent=None
        else:
            independent=reader["rules"].get(rid)
        row=inv["rules"][rid]
        need(type(native) is dict and
             native.get("rule_id")==rid and
             native.get("canonical_requirement")==CLAUSES[rid] and
             native.get("canonical_source_sha256")==row["source_sha256"] and
             native.get("requirement_sha256")==row["requirement_sha256"] and
             native.get("full_rule_semantics")=="UNKNOWN" and
             native.get("individual_mg0")=="UNKNOWN" and
             native.get("owner_approval")=="UNKNOWN" and
             native.get("advancement_authorized") is False,
             "C07_O146_Q170_MQ_NATIVE_ORIGINAL_RULE_CHANGED:"+rid)
        first=native.get("original_native_predicates")
        need(type(first) is dict and
             len(first)==len(MQ_PREDICATES[n]) and
             set(first)==set(MQ_PREDICATES[n]) and
             all(type(x) is bool for x in first.values()),
             "C07_O146_Q170_EXACT_SOURCE_NATIVE_PREDICATES_REQUIRED:"+rid)
        due=PHASE_INDEX[work["phase"]]>=PHASE_INDEX[REQUIRED_PHASE[rid]]
        if independent is not None:
            need(type(independent) is dict and
                 independent.get("rule_id")==rid and
                 independent.get("source_sha256")==row["source_sha256"] and
                 independent.get("requirement_sha256")==row["requirement_sha256"] and
                 independent.get("earliest_phase")==REQUIRED_PHASE[rid] and
                 independent.get("applicability")==(
                     "DUE" if due else "FUTURE_PHASE") and
                 independent.get("full_rule_semantics") in ("UNKNOWN","NOT_DUE") and
                 independent.get("individual_mg0") in ("UNKNOWN","NOT_DUE") and
                 independent.get("owner_acceptance")=="UNKNOWN" and
                 independent.get("advancement_authorized") is False,
                 "C07_O146_Q170_INDEPENDENT_SOURCE_REPLAY_CHANGED:"+rid)
        second=(independent.get("machine_observations") if n<=150 else
                independent.get("native_original_machine_evidence")) if independent else {}
        need(type(second) is dict and (
             (len(second)==2 and all(type(x) is bool for x in second.values()))
             if due else second=={}),
             "C07_O146_Q170_PHASE_SCOPED_MACHINE_EVIDENCE_INVALID:"+rid)
        # Never count P6/P7 native facts when the work is merely in P5.
        # Prefixes distinguish separately authored byte-backed engines.
        details=({
          **{"native:"+k:v for k,v in first.items()},
          **{"independent:"+k:v for k,v in second.items()}
        } if due else {})
        obs=mg0["rules"][rid]
        need(type(obs) is dict and
             obs.get("verdict") in ("FAIL","UNKNOWN") and
             type(obs.get("uncorrected_failure_count")) is int and
             obs["uncorrected_failure_count"]>=0 and
             type(obs.get("observation_sha256")) is str and
             re.fullmatch("[a-f0-9]{64}",obs["observation_sha256"]),
             "C07_O146_Q170_MG0_NEGATIVE_READBACK_INVALID:"+rid)
        fail=obs["verdict"]=="FAIL" or obs["uncorrected_failure_count"]>0
        checked+=len(details)
        observed+=sum(details.values())
        failures+=int(fail)
        rows[rid]={
           "rule_id":rid,"canonical_clause":CLAUSES[rid],
           "semantic_subject":TOPICS[n],
           "source_sha256":row["source_sha256"],
           "requirement_sha256":row["requirement_sha256"],
           "required_phase":REQUIRED_PHASE[rid],
           "applicability":"DUE" if due else "FUTURE_PHASE",
           "original_machine_observations":details,
           "positive_subcriteria":sum(details.values()),
           "missing_subcriteria":sorted(k for k,v in details.items() if not v),
           "original_mg0_negative_verdict":obs["verdict"],
           "uncorrected_mg0_failures":obs["uncorrected_failure_count"],
           "original_mg0_observation_sha256":obs["observation_sha256"],
           "source_semantic_verdict":"FAIL" if fail else (
                "UNKNOWN" if due else "NOT_DUE"),
           "original_full_semantics_certified":False,
           "independent_mg0_certified":False,
           "advancement_authorized":False,
        }
    need(len(rows)==25 and set(rows)==set(IDS) and
         all(len(r["original_machine_observations"])>=5
             for r in rows.values() if r["applicability"]=="DUE") and
         all(not r["original_machine_observations"]
             for r in rows.values() if r["applicability"]=="FUTURE_PHASE"),
         "C07_O146_Q170_TWENTY_FIVE_ORIGINAL_SCOPES_INCOMPLETE")
    return {
      "schema":SCHEMA,"rule_count":25,
      "exact_source_clauses":25,
      "current_phase":work["phase"],
      "due_rules":sum(r["applicability"]=="DUE" for r in rows.values()),
      "future_phase_rules":sum(r["applicability"]=="FUTURE_PHASE" for r in rows.values()),
      "original_named_machine_subcriteria":checked,
      "observed_true_machine_subcriteria":observed,
      "original_negative_mg0_failures":failures,
      "original_audit_sha256":sha(audit),
      "original_audit_tail":mg0["audit_tail_sha256"],
      "master_sha256":work["master_sha256"],
      "attempt_id":work["attempt_id"],
      "operation_sha256":work["operation_sha256"],
      "full_rule_semantic_passes":0,
      "individual_mg0_passes":0,
      "advancement_authorized":False,
      "rules":rows,
    }

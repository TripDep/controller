"""C07 sixth 25-rule original P2 source-scoped semantic readback.

G061-G070 and H071-H080 architecture; I081-I085 natural stone.
Both independently existing source-byte readers must replay the same
Controller work, original MASTER, audit and 25 separate negative MG0 findings.
All machine subcriteria are explicitly non-certifying; no owner review, full
semantic PASS or FiveM runtime certification is inferred.
"""
import hashlib
import re
from c07_gk50_canonical import CLAUSES,CATALOG_SHA
from c07_gk50_predicates import SPEC
from c07_g061_k110_fifty_native import SCHEMA as GK_SCHEMA,inspect as inspect_gk
from c07_p2_fifty_asset_type_domain import SCHEMA as P2_SCHEMA,TEXT as P2_TEXT,inspect as inspect_p2
from c07_mg0_individual import inspect_batch as inspect_mg0

SCHEMA="gg-c07-g061-i085-original25-dual-semantic-v1"
IDS=tuple("AAA-200-%s-%03d"%("G" if n<=70 else "H" if n<=80 else "I",n)
          for n in range(61,86))
TOPICS={
61:"geometric_reference",62:"main_silhouette",63:"scale_aware_bevels",
64:"edge_radius_intent",65:"normals_and_winding",
66:"duplicate_surfaces",67:"component_intersections",
68:"pivots_and_transforms",69:"modular_reuse",
70:"editable_original_source",71:"construction_logic",
72:"beams_columns_supports",73:"structural_joins",
74:"approved_symmetry",75:"intentional_asymmetry",
76:"roof_pitch_and_curvature",77:"roof_wall_column_joins",
78:"unrealistic_intersecting_volumes",79:"doors_windows_railings_dimensions",
80:"architecture_scene_context",81:"original_natural_rock_reference",
82:"rock_major_forms",83:"organic_sculpting_method",
84:"natural_distribution",85:"organic_surface_silhouette_variation"
}
TYPES={"architecture":20,"organic":5}
class Original25Blocked(ValueError): pass
def need(ok,label):
    if not ok: raise Original25Blocked(label)
def sha(raw): return hashlib.sha256(raw).hexdigest()

def canonical(inventory):
    need(type(inventory) is dict and
         inventory.get("schema")=="gg-effective-family-inventory-v1" and
         inventory.get("rule_count")==763 and
         inventory.get("source_digests",{}).get("aaa_catalog")==CATALOG_SHA and
         len(IDS)==len(set(IDS))==len(TOPICS)==25 and
         len(set(TOPICS.values()))==25 and
         set(TOPICS)==set(range(61,86)),
         "C07_G061_I085_EXACT_25_SOURCE_RULES_REQUIRED")
    for n,rid in enumerate(IDS,61):
        sec,literal,phase,kind=CLAUSES[n]
        row=inventory.get("rules",{}).get(rid,{})
        need(rid=="AAA-200-"+sec+"-%03d"%n and
             phase=="P2" and kind in TYPES and
             P2_TEXT.get(str(n))==[literal,kind] and
             row.get("family")=="AAA-200" and
             row.get("catalog_number")==n and
             row.get("catalog_section")==sec and
             row.get("catalog_phase")=="P2" and
             row.get("asset_type")==kind and
             row.get("source_sha256")==CATALOG_SHA and
             row.get("requirement")==literal and
             row.get("requirement_sha256")==sha(literal.encode("utf-8")) and
             isinstance(SPEC.get(n),(tuple,list)) and
             len(SPEC[n])>=3 and len(set(SPEC[n]))==len(SPEC[n]),
             "C07_G061_I085_ORIGINAL_CLAUSE_CHANGED:"+rid)

def inspect(context):
    need(type(context) is dict and set(context)=={
         "inventory","plan","controller","asset","step","work","source_loader"}
         and callable(context["source_loader"]),
         "C07_G061_I085_CURRENT_CONTROLLER_CONTEXT_REQUIRED")
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
         "C07_G061_I085_CURRENT_ATTEMPT_AND_PHASE_REQUIRED")
    master=c.master.read_bytes()
    need(type(master) is bytes and sha(master)==work["master_sha256"],
         "C07_G061_I085_ORIGINAL_MASTER_CHANGED")
    args=(inv,plan,c,asset,step,work)
    kw={"source_loader":context["source_loader"]}
    gk=inspect_gk(*args,**kw)
    p2=inspect_p2(*args,**kw)
    audit=c.audit_path(asset).read_bytes()
    need(type(audit) is bytes,"C07_G061_I085_REAL_AUDIT_REQUIRED")
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
             p2.get("original_audit_sha256")==mg.get("audit_sha256")==sha(audit) and
         gk.get("original_audit_tail")==p2.get("original_audit_tail")==
             mg.get("audit_tail_sha256") and
         gk.get("attempt_id")==p2.get("attempt_id")==
             mg.get("attempt_id")==work["attempt_id"] and
         gk.get("operation_sha256")==p2.get("operation_sha256")==
             work["operation_sha256"] and
         p2.get("master_sha256")==work["master_sha256"] and
         gk.get("full_rule_passes")==p2.get("full_semantic_passes")==0 and
         gk.get("individual_mg0_passes")==p2.get("individual_mg0_passes")==
             mg.get("individual_mg0_passes")==0 and
         all(z.get("advancement_authorized") is False for z in (gk,p2,mg)),
         "C07_G061_I085_THREE_REPLAYED_EVIDENCE_READERS_DIVERGED")
    rows={};seen=checked=failures=0
    for n,rid in enumerate(IDS,61):
        source=inv["rules"][rid]
        a=gk.get("rules",{}).get(rid)
        b=p2.get("rules",{}).get(rid)
        relevant=work["asset_type"]==source["asset_type"]
        need(type(a) is dict and type(b) is dict and
             a.get("rule_id")==b.get("rule_id")==rid and
             a.get("requirement_sha256")==b.get("requirement_sha256")==
                 source["requirement_sha256"] and
             a.get("source_sha256")==b.get("source_sha256")==
                 source["source_sha256"] and
             a.get("canonical_requirement")==source["requirement"] and
             a.get("applicability")==b.get("applicability")==(
                 "DUE" if relevant else "N_A_ASSET_TYPE") and
             a.get("full_rule_semantics")=="UNKNOWN" and
             a.get("individual_mg0")=="UNKNOWN" and
             a.get("owner_approval")=="UNKNOWN" and
             a.get("advancement_authorized") is False and
             b.get("full_rule_semantics") in ("UNKNOWN","NOT_DUE") and
             b.get("individual_mg0") in ("UNKNOWN","NOT_DUE") and
             b.get("owner_approval")=="UNKNOWN" and
             b.get("advancement_authorized") is False and
             b.get("source_asset_type")==source["asset_type"] and
             b.get("current_asset_type")==work["asset_type"],
             "C07_G061_I085_WRONG_ORIGINAL_RULE_OR_ASSET:"+rid)
        native=a.get("native_byte_checks")
        independent=b.get("original_native_domain_predicates")
        need(type(native) is dict and set(native)==set(SPEC[n]) and
             all(type(x) is bool for x in native.values()) and
             type(independent) is dict and
             ((len(independent)==2 and
               all(type(x) is bool for x in independent.values()))
              if relevant else independent=={}),
             "C07_G061_I085_INDIVIDUAL_SOURCE_PREDICATES_INVALID:"+rid)
        evidence=({
            **{"native:"+k:v for k,v in native.items()},
            **{"independent:"+k:v for k,v in independent.items()}
        } if relevant else {})
        finding=mg["rules"][rid]
        need(type(finding) is dict and
             finding.get("verdict") in ("FAIL","UNKNOWN") and
             type(finding.get("uncorrected_failure_count")) is int and
             finding["uncorrected_failure_count"]>=0 and
             type(finding.get("observation_sha256")) is str and
             re.fullmatch("[a-f0-9]{64}",finding["observation_sha256"]),
             "C07_G061_I085_ORIGINAL_MG0_NEGATIVE_FINDING_INVALID:"+rid)
        bad=finding["verdict"]=="FAIL" or finding["uncorrected_failure_count"]>0
        seen+=sum(evidence.values());checked+=len(evidence);failures+=int(bad)
        rows[rid]={
            "rule_id":rid,"original_clause":source["requirement"],
            "source_sha256":source["source_sha256"],
            "requirement_sha256":source["requirement_sha256"],
            "specific_semantic_concern":TOPICS[n],
            "required_phase":"P2",
            "required_asset_type":source["asset_type"],
            "applicability":"DUE" if relevant else "N_A_ASSET_TYPE",
            "original_machine_predicates":evidence,
            "original_positive_subconditions":sum(evidence.values()),
            "unproven_source_subconditions":sorted(k for k,v in evidence.items() if not v),
            "independent_negative_verdict":finding["verdict"],
            "uncorrected_mg0_failures":finding["uncorrected_failure_count"],
            "mg0_observation_sha256":finding["observation_sha256"],
            "original_semantic_verdict":"FAIL" if bad else
                ("UNKNOWN" if relevant else "NOT_DUE"),
            "full_original_semantics_certified":False,
            "independent_mg0_certified":False,
            "advancement_authorized":False,
        }
    need(len(rows)==25 and set(rows)==set(IDS) and
         all(len(z["original_machine_predicates"])>=5 for z in rows.values()
             if z["applicability"]=="DUE") and
         all(z["original_machine_predicates"]=={} for z in rows.values()
             if z["applicability"]!="DUE"),
         "C07_G061_I085_COMPLETE_25_INDIVIDUAL_SOURCE_SCOPES_REQUIRED")
    return {
        "schema":SCHEMA,"rule_count":25,"original_source_clauses":25,
        "current_phase":work["phase"],"current_asset_type":work["asset_type"],
        "due_rules":sum(z["applicability"]=="DUE" for z in rows.values()),
        "nonapplicable_rules":sum(z["applicability"]!="DUE" for z in rows.values()),
        "machine_subconditions_checked":checked,
        "machine_subconditions_observed":seen,
        "original_mg0_negative_failures":failures,
        "original_audit_sha256":sha(audit),
        "original_audit_tail":mg["audit_tail_sha256"],
        "master_sha256":work["master_sha256"],
        "attempt_id":work["attempt_id"],
        "operation_sha256":work["operation_sha256"],
        "full_rule_semantic_passes":0,"independent_mg0_passes":0,
        "advancement_authorized":False,"rules":rows
    }

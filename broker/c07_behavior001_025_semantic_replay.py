"""C07 tenth group, BEHAVIOR-001..025: canonical-source-bound behavior evidence.

Only original Controller audit and existing native machine observations are
considered. An observed behavior failure may be FAIL; lack of an observed
failure never establishes compliance. No synthetic fixture, MG0 or owner PASS.
"""
import hashlib
import re
from c07_behavior_001_050_canonical import CLAUSES, SOURCE_SHA
from c07_behavior_001_050_spec import SPEC
from c07_behavior_001_050_native import SCHEMA as NATIVE_SCHEMA, inspect as native50
from c07_mg0_individual import inspect_batch as mg0_batch
from real_work_intake import audit_check

SCHEMA="gg-c07-behavior001-025-original-observation-v1"
IDS=tuple("BEHAVIOR-%03d"%n for n in range(1,26))
FAIL_EVENTS={"QUALITY_FINDING","USER_REVIEW","VERIFIED_STATE_REVOKED",
             "DELIVERY_GATE_CHECK","STEP_CLOSE"}
HEX=re.compile("[0-9a-f]{64}\\Z")
class Blocked(ValueError):pass
def need(ok,msg):
    if not ok:raise Blocked(msg)
def sha(data):return hashlib.sha256(data).hexdigest()

def verify_canonical(inv):
    need(type(inv) is dict and inv.get("schema")=="gg-effective-family-inventory-v1"
         and inv.get("rule_count")==763
         and inv.get("source_digests",{}).get("error_registry")==SOURCE_SHA
         and len(IDS)==len(set(IDS))==25,
         "C07_BEH25_CANONICAL_SOURCE_REQUIRED")
    for n,rid in enumerate(IDS,1):
        sentence=CLAUSES[n];rule=inv.get("rules",{}).get(rid,{})
        need(sentence.startswith("Errore: ") and " → " in sentence
             and len(SPEC[n])==len(set(SPEC[n]))==3
             and rule.get("family")=="BEHAVIOR_110"
             and rule.get("source")=="error_registry"
             and rule.get("source_sha256")==SOURCE_SHA
             and rule.get("requirement")==sentence
             and rule.get("requirement_sha256")==sha(sentence.encode("utf-8"))
             and rule.get("required_mg0") is True,
             "C07_BEH25_ORIGINAL_REQUIREMENT_CHANGED:"+rid)
    return IDS

def inspect(ctx):
    need(type(ctx) is dict and set(ctx)=={
        "inventory","plan","controller","asset","step","work","source_loader"}
        and callable(ctx["source_loader"]),
        "C07_BEH25_ORIGINAL_CONTEXT_REQUIRED")
    inv=ctx["inventory"];plan=ctx["plan"];work=ctx["work"]
    verify_canonical(inv)
    need(type(plan) is dict and type(work) is dict
         and plan.get("phase")==work.get("phase")
         and plan.get("master_sha256")==work.get("master_sha256")
             ==inv.get("canonical_master_sha256")
         and all(type(work.get(k)) is str and HEX.fullmatch(work[k])
                 for k in ("attempt_id","operation_sha256")),
         "C07_BEH25_EXACT_ACTIVE_ATTEMPT_REQUIRED")
    ctrl=ctx["controller"];asset=ctx["asset"]
    master=ctrl.master.read_bytes()
    raw=ctrl.audit_path(asset).read_bytes()
    need(type(master) is bytes and type(raw) is bytes
         and sha(master)==work["master_sha256"],
         "C07_BEH25_CANONICAL_MASTER_AUDIT_REQUIRED")
    rows,tail=audit_check(raw,asset)
    native=native50(inv,plan,ctrl,asset,ctx["step"],work,
                    source_loader=ctx["source_loader"])
    mg=mg0_batch(master,raw,asset,work["master_sha256"],
                list(IDS),work["attempt_id"])
    need(native.get("schema")==NATIVE_SCHEMA
         and native.get("source_rules_examined")==50
         and native.get("native_conditions_evaluated")==150
         and native.get("original_audit_sha256")==mg.get("audit_sha256")==sha(raw)
         and native.get("original_audit_tail")==mg.get("audit_tail_sha256")==tail
         and native.get("attempt_id")==mg.get("attempt_id")==work["attempt_id"]
         and native.get("operation_sha256")==work["operation_sha256"]
         and native.get("full_rule_passes")==native.get("individual_mg0_passes")==0
         and native.get("advancement_authorized") is False
         and mg.get("rule_count")==25 and set(mg.get("rules",{}))==set(IDS)
         and mg.get("counts",{}).get("PASS")==0
         and mg.get("individual_mg0_passes")==0
         and mg.get("advancement_authorized") is False,
         "C07_BEH25_ORIGINAL_NATIVE_AND_MG0_DIVERGED")
    results={};checked=observed=failures=0
    for n,rid in enumerate(IDS,1):
        r=native["rules"].get(rid,{})
        checks=r.get("original_machine_checks")
        names=SPEC[n]
        need(r.get("rule_id")==rid
             and r.get("canonical_clause")==CLAUSES[n]
             and r.get("source_sha256")==SOURCE_SHA
             and r.get("requirement_sha256")==inv["rules"][rid]["requirement_sha256"]
             and r.get("full_prevention_semantics")=="UNKNOWN"
             and r.get("individual_mg0")=="UNKNOWN"
             and r.get("owner_approval")=="UNKNOWN"
             and r.get("advancement_authorized") is False
             and type(checks) is dict and list(checks)==list(names)
             and all(type(v) is bool for v in checks.values())
             and checks[names[2]] is False,
             "C07_BEH25_MACHINE_OR_ORIGINAL_CLAUSE_DRIFT:"+rid)
        witness=[e for e in rows if e.get("rule_id")==rid
                 and e.get("event") in FAIL_EVENTS
                 and e.get("result") in ("FAIL","BLOCKED")
                 and e.get("attempt_id")==work["attempt_id"]
                 and e.get("step")==ctx["step"]]
        individual=mg["rules"].get(rid,{})
        need(individual.get("verdict") in ("UNKNOWN","FAIL")
             and type(individual.get("uncorrected_failure_count")) is int
             and individual["uncorrected_failure_count"]>=0
             and type(individual.get("observation_sha256")) is str
             and HEX.fullmatch(individual["observation_sha256"]),
             "C07_BEH25_INDIVIDUAL_MG0_NEGATIVE_REQUIRED:"+rid)
        bad=bool(witness) or individual["verdict"]=="FAIL" or (
            individual["uncorrected_failure_count"]>0)
        failures+=int(bad);checked+=2
        observed+=int(checks[names[0]])+int(checks[names[1]])
        results[rid]={
            "rule_id":rid,"original_error_prevention":CLAUSES[n],
            "requirement_sha256":inv["rules"][rid]["requirement_sha256"],
            "original_machine_observations":{key:checks[key] for key in names[:2]},
            "unproven_full_clause":names[2],
            "authenticated_failure_record_hashes":[w["record_hash"] for w in witness],
            "mg0_negative_verdict":individual["verdict"],
            "mg0_observation_sha256":individual["observation_sha256"],
            "semantic_verdict":"FAIL" if bad else "UNKNOWN",
            "full_prevention_certified":False,"individual_mg0_certified":False,
            "advancement_authorized":False}
    need(set(results)==set(IDS) and checked==50,
         "C07_BEH25_ALL_RULES_50_NATIVE_FACTS_REQUIRED")
    return {"schema":SCHEMA,"rule_count":25,"canonical_clauses":25,
        "native_facts_checked":checked,"native_facts_observed":observed,
        "mg0_negative_checks":25,"negative_rule_count":failures,
        "original_audit_sha256":sha(raw),"original_audit_tail":tail,
        "attempt_id":work["attempt_id"],"operation_sha256":work["operation_sha256"],
        "full_rule_semantic_passes":0,"individual_mg0_passes":0,
        "advancement_authorized":False,"rules":results}

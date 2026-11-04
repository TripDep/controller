"""C07 ninth 25 original native semantic scopes; not independent FULL/MG0 PASS."""
import re
from c07_aaa25_gap_canonical import canonical, IDS, NUMBERS
from c07_aaa25_gap_sources import source_readback
from c07_bf50_predicates import SPEC

SCHEMA="gg-c07-aaa-remaining25-source-native-v1"
def need(ok,why):
    if not ok:raise ValueError(why)
def check_native(d,expected,rid):
    need(type(d) is dict and len(d)==expected and
         all(type(v) is bool for v in d.values()),
         "C07_25_EXACT_NATIVE_CRITERIA:"+rid)
    return d

def inspect(context):
    original=canonical(context["inventory"])
    sources,negative,audit_sha=source_readback(context)
    ac,bf,p1,p345,process=sources
    results={};evaluated=observed=failures=0
    for n,rid in zip(NUMBERS,original):
        inv=context["inventory"]["rules"][rid];checks={}
        if n<=30:
            a=ac["rules"].get(rid,{});b=bf["rules"].get(rid,{})
            native=check_native(a.get("native_original_file_criteria"),3,rid)
            dup=check_native(b.get("original_native_predicates"),4,rid)
            need(set(dup)==set(SPEC[n]) and
                 list(native.values())==list(dup.values())[:3] and
                 dup[SPEC[n][-1]] is False and
                 a.get("full_rule_pass") is False and
                 a.get("individual_mg0")=="UNKNOWN" and
                 a.get("owner_approval")=="UNKNOWN" and
                 b.get("full_rule_semantics")=="UNKNOWN",
                 "C07_25_C_REFERENCES_NOT_DUPLICATED:"+rid)
            checks={"reference:"+k:v for k,v in native.items()}
        elif n<=35:
            a=bf["rules"].get(rid,{});b=p1["rules"].get(rid,{})
            native=check_native(a.get("original_native_predicates"),4,rid)
            domain=check_native(b.get("original_native_measured_criteria"),3,rid)
            need(set(native)==set(SPEC[n]) and
                 a.get("full_rule_semantics")=="UNKNOWN" and
                 b.get("full_rule_semantics")=="UNKNOWN" and
                 a.get("applicability")=="DUE",
                 "C07_25_D_P1_ORIGINAL_SCOPE:"+rid)
            checks={**{"planning:"+k:v for k,v in native.items()},
                    **{"design:"+k:v for k,v in domain.items()}}
        elif n<=120:
            a=p345["rules"].get(rid,{})
            native=check_native(a.get("machine_observations"),2,rid)
            need(a.get("earliest_phase")=="P3" and
                 a.get("applicability")=="DUE" and
                 a.get("full_rule_semantics")=="UNKNOWN" and
                 a.get("individual_mg0")=="UNKNOWN" and
                 a.get("owner_acceptance")=="UNKNOWN",
                 "C07_25_L_P3_ORIGINAL_TOPOLOGY_SCOPE:"+rid)
            checks={"topology_uv:"+k:v for k,v in native.items()}
        else:
            a=process["rules"].get(rid,{})
            native=check_native(a.get("original_machine_criteria"),4,rid)
            need(a.get("full_rule_pass") is False and
                 a.get("independent_mg0")=="UNKNOWN",
                 "C07_25_R_ORIGINAL_PROCESS_SCOPE:"+rid)
            checks={"process:"+k:v for k,v in native.items()}
        native_source=(ac if n<=30 else bf if n<=35 else
                       p345 if n<=120 else process)["rules"][rid]
        need(native_source.get("rule_id")==rid and
             native_source.get("source_sha256")==inv["source_sha256"] and
             native_source.get("requirement_sha256")==inv["requirement_sha256"] and
             native_source.get("advancement_authorized") is False,
             "C07_25_CANONICAL_SOURCE_IDENTITY_DRIFT:"+rid)
        mg0=negative["rules"].get(rid,{})
        need(mg0.get("verdict") in ("UNKNOWN","FAIL") and
             type(mg0.get("uncorrected_failure_count")) is int and
             mg0["uncorrected_failure_count"]>=0 and
             type(mg0.get("observation_sha256")) is str and
             re.fullmatch("[0-9a-f]{64}",mg0["observation_sha256"]),
             "C07_25_MG0_ORIGINAL_NEGATIVE_MISSING:"+rid)
        failed=mg0["verdict"]=="FAIL" or mg0["uncorrected_failure_count"]>0
        evaluated+=len(checks);observed+=sum(checks.values());failures+=int(failed)
        results[rid]={
            "rule_id":rid,"canonical_clause":inv["requirement"],
            "requirement_sha256":inv["requirement_sha256"],
            "source_sha256":inv["source_sha256"],
            "original_native_checks":checks,
            "missing_native_checks":sorted(k for k,v in checks.items() if not v),
            "individual_mg0_verdict":mg0["verdict"],
            "individual_mg0_observation_sha256":mg0["observation_sha256"],
            "semantic_verdict":"FAIL" if failed else "UNKNOWN",
            "full_rule_semantics_certified":False,
            "independent_mg0_certified":False,
            "advancement_authorized":False}
    need(len(results)==25 and set(results)==set(IDS) and evaluated==90,
         "C07_25_90_INDIVIDUAL_NATIVE_SOURCE_CRITERIA_REQUIRED")
    return {"schema":SCHEMA,"rule_count":25,"canonical_clauses":25,
        "machine_subchecks_checked":evaluated,"machine_subchecks_observed":observed,
        "independent_mg0_negative_checks":25,"mg0_failures":failures,
        "original_audit_sha256":audit_sha,
        "original_audit_tail":negative["audit_tail_sha256"],
        "attempt_id":context["work"]["attempt_id"],
        "operation_sha256":context["work"]["operation_sha256"],
        "full_rule_semantic_passes":0,"individual_mg0_passes":0,
        "advancement_authorized":False,"rules":results}

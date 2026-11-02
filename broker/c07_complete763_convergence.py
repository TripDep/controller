"""C07 full canonical 763-ID convergence across the existing source engines.

This does NOT certify the 763 requirements. It proves that all 200 AAA,
110 BEHAVIOR, 153 other project controls and 300 master questions have
nonduplicated, source-bound operational observations at current attempt.
A green workflow/merely existing file is never MG0 or owner acceptance.
"""
from c07_positive_native_process import sha, _original_attempt
from c07_questions_300 import extract_bank

SCHEMA="gg-c07-763-original-source-convergence-v1"
RECENT_COUNTS=(200,100,50,50,50,50,10)
SOURCE_ENGINE_COUNTS=(200,100)
class ConvergenceBlocked(ValueError):
    pass
def need(ok,why):
    if not ok: raise ConvergenceBlocked(why)

def inspect(inventory,plan,controller,asset,step,work,*,cohort200,batch100,beh50,bf50,
            gk50,mq50,ten_process,q200_actual,q100_final):
    need(type(inventory) is dict and
         inventory.get("schema")=="gg-effective-family-inventory-v1"
         and inventory.get("rule_count")==763 and
         type(inventory.get("rules")) is dict and
         len(inventory["rules"])==763 and
         type(inventory.get("families")) is dict and
         len(inventory["families"])==20,
         "C07_763_ORIGINAL_CANONICAL_INVENTORY_REQUIRED")
    source=controller.master.read_bytes()
    master=sha(source)
    need(master==inventory.get("canonical_master_sha256")
         ==inventory.get("source_digests",{}).get("master")
         ==work.get("master_sha256"),
         "C07_763_ORIGINAL_MASTER_BYTES_CHANGED")
    family_counts={
       "AAA-200":200,"BEHAVIOR_110":110,"QUESTIONS_300":300
    }
    for name,count in family_counts.items():
        need(len(inventory["families"].get(name,()))==count,
             "C07_763_ORIGINAL_FAMILY_COUNT_CHANGED:"+name)
    need(sum(len(v) for v in inventory["families"].values())==763 and
         len({rid for seq in inventory["families"].values() for rid in seq})==763 and
         set(inventory["rules"])=={
             rid for seq in inventory["families"].values() for rid in seq},
         "C07_763_CANONICAL_MEMBERSHIP_DUPLICATED_OR_MISSING")
    bank=extract_bank(source)
    need(len(bank)==300 and
         set(bank)==set(inventory["families"]["QUESTIONS_300"]),
         "C07_763_MASTER_300_QUESTION_BANK_CHANGED")
    recent=[
       ("GOVERNANCE_153_Q254_300",cohort200,200),
       ("AAA40_BEHAVIOR60",batch100,100),
       ("BEHAVIOR001_050",beh50,50),
       ("AAA_B011_F060",bf50,50),
       ("AAA_G061_K110",gk50,50),
       ("AAA_M121_Q170",mq50,50),
       ("AAA_R171_R180",ten_process,10),
    ]
    audit_rows,latest_tail,latest_state,latest_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(latest_state.get('last_audit_hash')==latest_tail and
         (latest_state.get('active_step') or {}).get('step')==step,
         'C07_763_FINAL_ORIGINAL_AUDIT_STATE_DRIFT')
    audit_origins={row.get('record_hash') for row in audit_rows}
    seen={}
    for engine,result,count in recent:
        need(type(result) is dict and
             type(result.get("rules")) is dict and
             len(result["rules"])==count and
             result.get("source_rules_examined")==count and
             result.get("individual_mg0_passes")==0 and
             result.get("advancement_authorized") is False,
             "C07_763_SOURCE_ENGINE_INCOMPLETE_OR_FAKE_MG0:"+engine)
        # Each engine must name its individual actual audited original work.
        need(result.get("attempt_id")==work.get("attempt_id")
             and result.get("operation_sha256")==work.get("operation_sha256"),
             "C07_763_REPLAYED_DIFFERENT_ATTEMPT:"+engine)
        need(result.get('original_audit_tail') in audit_origins and
             type(result.get('original_audit_sha256')) is str,
             'C07_763_SOURCE_ENGINE_AUDIT_NOT_IN_CURRENT_CHAIN:'+engine)
        for rid,row in result["rules"].items():
            need(rid not in seen,
                 "C07_763_DUPLICATED_RULE_ID:"+rid+":"+engine)
            need(rid in inventory["rules"] and
                 type(row) is dict and row.get("rule_id")==rid and
                 row.get("requirement_sha256")==
                    inventory["rules"][rid]["requirement_sha256"] and
                 row.get("advancement_authorized") is False,
                 "C07_763_ORIGINAL_PER_RULE_SHA_OR_SCOPE_CHANGED:"+rid)
            sources=(
                row.get("source_sha256"),
                row.get("original_source_sha256"),
                row.get("canonical_source_sha256"),
            )
            need(inventory["rules"][rid]["source_sha256"] in sources,
                 "C07_763_ORIGINAL_RULE_SOURCE_DIGEST_CHANGED:"+rid)
            need(row.get("individual_mg0",row.get("independent_mg0"))
                 in ("UNKNOWN","NOT_DUE"),
                 "C07_763_UNAUTHORIZED_INDIVIDUAL_MG0_PASS:"+rid)
            seen[rid]=engine
    need(latest_tail in audit_origins,
         'C07_763_FINAL_AUDIT_CHAIN_EMPTY')
    need(len(seen)==510,
         "C07_763_PRIOR_SIX_COHORT_510_NOT_DISTINCT")
    for engine,result,first,last in (
        ("Q001_Q200",q200_actual,1,200),
        ("Q201_Q300",q100_final,201,300),
    ):
        count=last-first+1
        need(type(result) is dict and
             type(result.get("rules")) is dict and
             len(result["rules"])==count and
             result.get("source_question_count")==count and
             result.get("individual_mg0_passes")==0 and
             result.get("advancement_authorized") is False and
             result.get("attempt_id")==work.get("attempt_id") and
             result.get("operation_sha256")==work.get("operation_sha256") and
             result.get("original_audit_tail") in audit_origins,
             "C07_763_ORIGINAL_QUESTION_SOURCE_ENGINE_UNTRUSTED:"+engine)
        need(set(result["rules"])==
             {"Q-%03d"%n for n in range(first,last+1)},
             "C07_763_QUESTION_ENGINE_MISSING_ID:"+engine)
        for rid,row in result["rules"].items():
            need(row.get("rule_id")==rid and
                 row.get("requirement_sha256")==inventory["rules"][rid]["requirement_sha256"] and
                 row.get("source_sha256")==master and
                 row.get("original_question",row.get("canonical_question"))==bank[rid] and
                 row.get("individual_mg0")=="UNKNOWN" and
                 row.get("advancement_authorized") is False and
                 row.get("semantic_verdict") in ("UNKNOWN","FAIL"),
                 "C07_763_QUESTION_CANONICAL_OR_MG0_DRIFT:"+rid)
            if rid in seen:
                # Q254..Q300 is already observed by the governance+questions
                # cohort. Agree on both original source hashes: do NOT count
                # these forty-seven as new, additional rules.
                need(seen[rid]=="GOVERNANCE_153_Q254_300"
                     and int(rid[2:])>=254,
                     "C07_763_DUPLICATE_QUESTION_NOT_ALLOWED:"+rid)
            else:
                need(int(rid[2:])<=253,
                     "C07_763_MISSING_QUESTION_OUTSIDE_REQUIRED_253:"+rid)
                seen[rid]=engine
    missing=set(inventory["rules"])-set(seen)
    extra=set(seen)-set(inventory["rules"])
    need(not missing and not extra and len(seen)==763,
         "C07_763_CANONICAL_SOURCE_NOT_FULLY_COVERED")
    # Traceability status: every source has one primary counting owner,
    # independent semantic and user/MG0 certification remain UNPROVEN.
    by_engine={}
    for owner in seen.values():by_engine[owner]=by_engine.get(owner,0)+1
    need(sum(by_engine.values())==763 and
         by_engine.get("Q001_Q200")==200 and
         by_engine.get("Q201_Q300")==53 and
         by_engine.get("GOVERNANCE_153_Q254_300")==200,
         "C07_763_NEW_253_QUESTION_COUNT_CHANGED")
    return {
       "schema":SCHEMA,"source_rules_covered":763,
       "prior_six_batches_distinct":510,
       "existing_original_question_rules_reconciled":253,
       "overall_families":20,"all_question_ids_verified":300,
       "original_master_sha256":master,
       "original_audit_sha256":latest_sha,
       "original_audit_tail":latest_tail,
       "attempt_id":work["attempt_id"],
       "operation_sha256":work["operation_sha256"],
       "coverage_complete":True,"independent_mg0_passes":0,
       "full_rule_semantic_passes":0,
       "advancement_authorized":False,
       "per_engine_primary_ownership":by_engine,
       "all_rule_ids":sorted(seen),
       "next_required_gate":"REAL_INDEPENDENT_MG0_PER_RULE",
    }

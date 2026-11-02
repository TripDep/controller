"""C07: validate original pre-operation evidence contracts before enrollment.

These fields already feed the R139/R140/R142-R148 domain readers. Previously
ControlledJudgment rejected every one as an extra plan key, so the real
source-specific predicates could never receive their pre-committed inputs in a
live operation. This validates the existing contracts; it does NOT create a
rule PASS, MG0 PASS, owner approval, or a new source of authority.
"""
import math
import re

HEX64 = re.compile(r"[a-f0-9]{64}\Z")
ROLE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
OPTIONAL_EVIDENCE_CONTEXT = frozenset((
    "pre_d_control", "reference_evidence_contract", "output_expectation",
    "p1_evidence_contract", "p2_evidence_contract",
    "p345_evidence_contract", "p678_evidence_contract",
    "question_200_original_witnesses", "acceptance_criteria",
    "mandatory_issue_ids", "timebox_seconds", "visual_hierarchy_contract",
))
# Late source evidence is accepted without changing the legacy 12-field
# contract enumeration. It remains original-byte observation, not approval.
LATE_EVIDENCE_CONTEXT = frozenset((
    "question_100_original_witnesses",
    "last_67_source_evidence_contract",
))
ALL_EVIDENCE_CONTEXT = OPTIONAL_EVIDENCE_CONTEXT | LATE_EVIDENCE_CONTEXT
PINNED_CONTRACTS = frozenset((
    "p1_evidence_contract", "p2_evidence_contract",
    "p345_evidence_contract", "p678_evidence_contract",
))

class EvidenceContractBlocked(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise EvidenceContractBlocked(reason)

def sha_map(value, *, permitted=None):
    need(type(value) is dict and bool(value) and len(value) <= 128,
         "C07_PRE_D_ORIGINAL_ARTIFACT_PINS_REQUIRED")
    need(all(type(k) is str and ROLE.fullmatch(k) and
             (permitted is None or k in permitted) and
             type(v) is str and HEX64.fullmatch(v)
             for k, v in value.items()),
         "C07_PRE_D_ORIGINAL_ARTIFACT_PIN_SCHEMA")
    return True

def strings(value):
    return (type(value) is list and bool(value) and
            len(value) <= 763 and
            all(type(s) is str and s.strip() == s and
                0 < len(s) <= 300 for s in value) and
            len(set(value)) == len(value))

def validate(plan, inventory):
    """Validate only explicit pre-enrolled contracts; never infer evidence.

    The Controller separately authenticates D authorization, enrolled STATUS,
    original audit chain, exact work attempt and registered output bytes.
    """
    need(type(plan) is dict and type(inventory) is dict and
         type(inventory.get("rules")) is dict,
         "C07_PRE_D_PLAN_OR_INVENTORY_MISSING")
    extras = set(plan) & ALL_EVIDENCE_CONTEXT
    for key in sorted(extras & PINNED_CONTRACTS):
        value = plan[key]
        need(type(value) is dict and set(value) == {"original_artifact_sha256"},
             "C07_PRE_D_CONTRACT_SCHEMA:" + key)
        sha_map(value["original_artifact_sha256"])
    if "reference_evidence_contract" in extras:
        from c07_a10_c10_original_evidence import CONTRACT_SCHEMA, SOURCE_ROLES
        value = plan["reference_evidence_contract"]
        need(type(value) is dict and
             set(value) == {"schema", "artifact_sha256"} and
             value["schema"] == CONTRACT_SCHEMA,
             "C07_PRE_D_REFERENCE_CONTRACT_SCHEMA")
        sha_map(value["artifact_sha256"], permitted=set(SOURCE_ROLES))
    if "output_expectation" in extras:
        from c07_native_output_oracle import _contract
        need(_contract(plan["output_expectation"]) is not None,
             "C07_PRE_D_GEOMETRY_EXPECTATION_INVALID")
        need(plan.get("operation", {}).get("category") in
             ("GENERATION", "MUTATION", "EXPORT"),
             "C07_PRE_D_GEOMETRY_NOT_AN_OUTPUT_OPERATION")
    if "pre_d_control" in extras:
        value = plan["pre_d_control"]
        need(type(value) is dict and
             all(type(value.get(k)) is str and value[k].strip()
                 for k in ("piece_id", "objective", "phase")) and
             value["phase"] in ("G0", "G1", "A", "B", "C", "D0") and
             strings(value.get("rule_ids")) and
             set(value["rule_ids"]) <= set(inventory["rules"]),
             "C07_PRE_D_MOTHER_CONTROL_INVALID")
        for key in ("criteria", "assertions", "assumptions", "defect_ids",
                    "predecessors"):
            if key in value:
                need(strings(value[key]), "C07_PRE_D_CONTROL_LIST:" + key)
    if "question_200_original_witnesses" in extras:
        from c07_q200_original_witnesses import (
            CONTRACT, IDS, domain_for, file_type_for,
        )
        value = plan["question_200_original_witnesses"]
        need(type(value) is dict and set(value) == {"schema", "rules"} and
             value["schema"] == CONTRACT and
             type(value["rules"]) is dict and
             bool(value["rules"]) and
             set(value["rules"]) <= set(IDS),
             "C07_PRE_D_Q200_CANONICAL_WITNESSES_ONLY")
        # A partially evidenced batch remains UNKNOWN for absent IDs; do
        # not invent 200 signed witnesses or force a false prerequisite.
        for n, rid in enumerate(IDS, 1):
            if rid not in value["rules"]:
                continue
            row = value["rules"][rid]
            need(type(row) is dict and set(row) == {
                 "question_sha256", "source_role", "source_sha256",
                 "measured_fingerprint", "claim_status"} and
                 row["question_sha256"] ==
                 inventory["rules"][rid]["requirement_sha256"] and
                 row["source_role"] == file_type_for(domain_for(n)) and
                 all(type(row[k]) is str and HEX64.fullmatch(row[k])
                     for k in ("source_sha256", "measured_fingerprint")) and
                 row["claim_status"] == "OBSERVATION_ONLY",
                 "C07_PRE_D_Q200_SOURCE_SPECIFIC:" + rid)
    if "question_100_original_witnesses" in extras:
        from c07_q100_closing_original_witnesses import (
            CONTRACT as Q100_CONTRACT, IDS as Q100_IDS,
            ROLES as Q100_ROLES, topic as q100_topic,
        )
        val = plan["question_100_original_witnesses"]
        need(type(val) is dict and set(val)=={"schema","rules"} and
             val["schema"]==Q100_CONTRACT and type(val["rules"]) is dict and
             set(val["rules"])<=set(Q100_IDS),
             "C07_PRE_D_Q100_CANONICAL_WITNESSES_ONLY")
        for rid, slot in val["rules"].items():
            row=inventory["rules"].get(rid,{})
            number=int(rid[2:])
            need(type(slot) is dict and set(slot)=={
                 "question_sha256","source_role","source_sha256",
                 "measured_fingerprint","claim_status"} and
                 row.get("family")=="QUESTIONS_300" and
                 slot["question_sha256"]==row.get("requirement_sha256") and
                 slot["source_role"]==Q100_ROLES[q100_topic(number)] and
                 all(type(slot[k]) is str and HEX64.fullmatch(slot[k])
                     for k in ("source_sha256","measured_fingerprint")) and
                 slot["claim_status"]=="OBSERVATION_ONLY",
                 "C07_PRE_D_Q100_SOURCE_SPECIFIC:"+rid)
    if "last_67_source_evidence_contract" in extras:
        from c07_last67_original_family_witnesses import (
            CONTRACT as LAST67_CONTRACT, EXPECTED_FAMILIES,
        )
        val=plan["last_67_source_evidence_contract"]
        need(type(val) is dict and set(val)=={"schema","rules"} and
             val["schema"]==LAST67_CONTRACT and type(val["rules"]) is dict and
             len(val["rules"])<=67,
             "C07_PRE_D_LAST67_CONTRACT_SCHEMA")
        for rid, slot in val["rules"].items():
            row=inventory["rules"].get(rid,{})
            family=row.get("family")
            need(type(slot) is dict and
                 set(slot)=={"requirement_sha256","source_sha256",
                             "witness_role","witness_sha256",
                             "observed_origin","claim_status"} and
                 family in EXPECTED_FAMILIES and
                 slot["requirement_sha256"]==row.get("requirement_sha256") and
                 slot["source_sha256"]==row.get("source_sha256") and
                 slot["witness_role"]=="C07_FAMILY_"+family and
                 type(slot["witness_sha256"]) is str and
                 HEX64.fullmatch(slot["witness_sha256"]) and
                 slot["observed_origin"]=="ORIGINAL_REGISTERED_BYTES" and
                 slot["claim_status"]=="OBSERVATION_ONLY",
                 "C07_PRE_D_LAST67_SOURCE_SPECIFIC:"+str(rid))
    if "acceptance_criteria" in extras:
        value = plan["acceptance_criteria"]
        need(type(value) is list and 0 < len(value) <= 100 and
             all(type(v) is dict and
                 {"criterion_id", "expected", "oracle"} <= set(v) and
                 type(v["criterion_id"]) is str and
                 v["criterion_id"].strip() == v["criterion_id"] and
                 bool(v["criterion_id"]) and
                 type(v["oracle"]) is str and
                 bool(v["oracle"].strip()) and
                 (type(v["expected"]) is str or
                  (type(v["expected"]) in (int, float) and
                   math.isfinite(v["expected"])))
                 for v in value) and
             len({v["criterion_id"] for v in value}) == len(value),
             "C07_PRE_D_EXEC_ACCEPTANCE_ORACLES_INVALID")
    if "mandatory_issue_ids" in extras:
        need(strings(plan["mandatory_issue_ids"]),
             "C07_PRE_D_MANDATORY_ISSUE_IDS_INVALID")
    if "timebox_seconds" in extras:
        need(type(plan["timebox_seconds"]) is int and
             0 < plan["timebox_seconds"] <= 31_536_000,
             "C07_PRE_D_TIMEBOX_INVALID")
    if "visual_hierarchy_contract" in extras:
        value = plan["visual_hierarchy_contract"]
        need(type(value) is dict and bool(value) and len(value) <= 100 and
             all(type(k) is str and k.strip() and
                 type(v) in (str, list, dict) and bool(v)
                 for k, v in value.items()),
             "C07_PRE_D_VISUAL_HIERARCHY_INVALID")
    return {"pre_enrolled_contract_keys": sorted(extras),
            "no_rule_or_mg0_pass_issued": True,
            "original_evidence_must_be_reread": True}

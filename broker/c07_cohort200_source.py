"""C07 frozen 200: all 153 project-governance source obligations + Q254-Q300.

Authenticates original 763-rule inventory and current MASTER bytes. It never
substitutes the 600 assistant-conduct instructions for project governance.
A selected ID is not an MG0 PASS or reviewed semantic requirement.
"""
import re
from c07_questions_300 import extract_bank
from c07_positive_native_process import sha
from c07_cohort200_canonical import MASTER_SHA,FAMILY_COUNTS,Q_IDS,EXCLUDED,TOTAL

class CohortSourceBlocked(ValueError):pass
def need(ok,reason):
    if not ok:raise CohortSourceBlocked(reason)

def select(inventory,controller,work):
    need(type(inventory) is dict and
         inventory.get("schema")=="gg-effective-family-inventory-v1"
         and inventory.get("rule_count")==763 and
         type(inventory.get("rules")) is dict and
         len(inventory["rules"])==763 and
         type(inventory.get("families")) is dict,
         "COHORT200_ORIGINAL_763_INVENTORY_REQUIRED")
    master=controller.master.read_bytes()
    need(type(master) is bytes and sha(master)==MASTER_SHA==
         inventory.get("canonical_master_sha256")==work.get("master_sha256")
         and inventory.get("source_digests",{}).get("master")==MASTER_SHA,
         "COHORT200_CURRENT_MASTER_BYTES_ORIGINAL_SHA_CHANGED")
    families=inventory["families"]
    need(set(families)==set(FAMILY_COUNTS)|set(EXCLUDED),
         "COHORT200_ORIGINAL_20_FAMILIES_CHANGED")
    for name,count in FAMILY_COUNTS.items():
        need(type(families.get(name)) is list and
             len(families[name])==count and
             len(set(families[name]))==count,
             "COHORT200_FAMILY_MEMBERSHIP_CHANGED:"+name)
    need(len(families["AAA-200"])==200 and
         len(families["BEHAVIOR_110"])==110 and
         len(families["QUESTIONS_300"])==300,
         "COHORT200_EXCLUDED_FAMILY_COUNT_CHANGED")
    bank=extract_bank(master)
    need(len(bank)==300 and
         set(bank)==set(families["QUESTIONS_300"]),
         "COHORT200_Q300_MASTER_SOURCE_DRIFT")
    scope=tuple(sorted(rid for group,ids in families.items()
                       if group not in EXCLUDED for rid in ids))
    ids=scope+Q_IDS
    need(len(scope)==153 and len(ids)==TOTAL and
         len(set(ids))==TOTAL and
         set(ids).issubset(inventory["rules"]) and
         set(ids).isdisjoint(set(families["AAA-200"])|
                             set(families["BEHAVIOR_110"])|
                             set(families["QUESTIONS_300"])-set(Q_IDS)),
         "COHORT200_NOT_200_NEW_DISTINCT_ORIGINAL_RULES")
    source_digests=inventory["source_digests"]
    mapping={}
    for family,rs in families.items():
        for rid in rs:mapping[rid]=family
    for rid in ids:
        row=inventory["rules"][rid]
        source=row.get("source")
        expected=MASTER_SHA if source=="master" else source_digests.get(source)
        need(type(row) is dict and row.get("family")==mapping[rid]
             and type(row.get("requirement")) is str
             and bool(row["requirement"].strip())
             and row.get("requirement_sha256")==sha(row["requirement"].encode())
             and type(expected) is str and re.fullmatch("[a-f0-9]{64}",expected)
             and row.get("source_sha256")==expected and
             rid in families[row["family"]],
             "COHORT200_ORIGINAL_SOURCE_REQUIREMENT_TAMPERED:"+rid)
        if rid in Q_IDS:
            need(mapping[rid]=="QUESTIONS_300" and
                 row["requirement"]==bank[rid] and
                 row["source_sha256"]==MASTER_SHA,
                 "COHORT200_FINAL_BANK_QUESTION_CHANGED:"+rid)
    return ids,mapping

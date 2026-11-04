"""C07 original ID gaps, exact 25. This only validates canonical original source identities.
Not a full semantic/MG0 PASS; remaining native evidence consumers are separate.
"""
import hashlib
from c07_a10_c10_original_evidence import TEXT as REFERENCE
from c07_p1_thirty_native_domain import TEXT as DESIGN
from c07_p345_forty_native_evidence import TEXT as MESH
from c07_r171_r180_source_native import CLAUSES as PROCESS
from c07_bf50_canonical import CATALOG_SHA

NUMBERS = tuple(range(26,36))+tuple(range(111,121))+tuple(range(171,176))
IDS = tuple("AAA-200-%s-%03d" % (
    "C" if n<=30 else "D" if n<=35 else "L" if n<=120 else "R",n)
    for n in NUMBERS)

def canonical(inventory):
    if inventory.get("rule_count")!=763 or inventory.get("source_digests",{}).get("aaa_catalog")!=CATALOG_SHA:
        raise ValueError("C07_25_SOURCE_CATALOG_REQUIRED")
    if len(IDS)!=25 or len(set(IDS))!=25:
        raise ValueError("C07_25_DUPLICATE_IDS")
    for n,rid in zip(NUMBERS,IDS):
        clause,phase = ((REFERENCE[n],"P0") if n<=30 else
                       (DESIGN[str(n)],"P1") if n<=35 else
                       (MESH[str(n)][0],"P3") if n<=120 else
                       (PROCESS[n],"P0"))
        row=inventory["rules"].get(rid,{})
        if not (row.get("requirement")==clause and
                row.get("catalog_phase")==phase and
                row.get("source_sha256")==CATALOG_SHA and
                row.get("requirement_sha256")==hashlib.sha256(clause.encode("utf-8")).hexdigest()):
            raise ValueError("C07_25_CANONICAL_CLAUSE_CHANGED:"+rid)
    return IDS

"""Native exact-outcome semantic checks for EXEC-001/004/008/021.

Only machine-derived measurements of original authenticated GLB bytes and
SHA-identical restored source establish positive *components*. Neither signed
claims nor green tests nor event names constitute a full rule or MG0 PASS.
"""
import math
import re
from datetime import datetime

ALLOWED_METRICS=frozenset((
    "triangles_examined","vertices_examined","mesh_primitives",
    "degenerate_triangles","nonfinite_positions","geometry_groups_with_bounds"
))
OPERATORS=frozenset(("eq","lte","gte"))

def _numeric(value):
    return type(value) in (int,float) and math.isfinite(value)

def criteria_well_formed(plan):
    criteria=plan.get("acceptance_criteria")
    if type(criteria) is not list or not criteria:return False
    names=set()
    for row in criteria:
        if type(row) is not dict or set(row)!={"name","operator","expected"}:
            return False
        name=row["name"];op=row["operator"];v=row["expected"]
        if name not in ALLOWED_METRICS or name in names or op not in OPERATORS or not _numeric(v):
            return False
        if v<0:return False
        names.add(name)
    return True

def measured_original_glb(plan,technical):
    """Fail closed unless EVERY enrolled numeric criterion is independently
    recomputed from the SAME original binary's machine audit."""
    if not criteria_well_formed(plan) or type(technical) is not dict:
        return False
    if technical.get("errors") or technical.get("unsupported_requires_independent_check"):
        return False
    for criterion in plan["acceptance_criteria"]:
        key=criterion["name"];observed=technical.get(key)
        if not _numeric(observed):return False
        op=criterion["operator"];v=criterion["expected"]
        if op=="eq" and observed!=v:return False
        if op=="lte" and observed>v:return False
        if op=="gte" and observed<v:return False
    return True

def real_rollback_restored(originals,current):
    """Compare actual restored registered bytes to original baseline bytes.

    An audit event named ROLLBACK_READBACK or a file called "restored" alone
    can NEVER supply the positive outcome.
    """
    baseline=originals.get("BASELINE_SNAPSHOT",())
    restored=originals.get("ROLLBACK_RESTORED",())
    if len(baseline)!=1 or len(restored)!=1:return False
    if baseline[0][1]!=restored[0][1] or baseline[0][2]!=restored[0][2]:
        return False
    return any(
        r.get("event")=="ROLLBACK_READBACK" and
        r.get("result")=="PASS" and
        r.get("baseline_sha256")==baseline[0][1] and
        r.get("restored_sha256")==restored[0][1] and
        r.get("attempt_id") and r.get("operation_sha256")
        for r in current
    )

def measured_timebox(plan,current):
    """Only measure bounded same-attempt timestamps; never provider uptime."""
    budget=plan.get("timebox_seconds")
    if type(budget) is not int or budget<=0:return False
    def parse(s):
        if type(s) is not str:return None
        try:
            dt=datetime.fromisoformat(s.replace("Z","+00:00"))
            return dt.timestamp() if dt.tzinfo is not None else None
        except (ValueError,OverflowError):
            return None
    opened=[x for x in current if x.get("event")=="RUN_STARTED"]
    ended=[x for x in current if x.get("event")=="RUN_FINISHED"]
    if len(opened)!=1 or len(ended)!=1:return False
    t0=parse(opened[0].get("timestamp_utc"))
    t1=parse(ended[0].get("timestamp_utc"))
    return t0 is not None and t1 is not None and t0<=t1 and (t1-t0)<=budget

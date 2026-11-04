"""C07 ninth batch: reread five native source engines on the same Controller attempt.
Source observations alone never authorize full rule acceptance or MG0 PASS.
"""
import hashlib
import re
from c07_aaa25_gap_canonical import canonical, IDS
from c07_a10_c10_original_evidence import inspect as research
from c07_b011_f060_fifty_native import inspect as planning
from c07_p1_thirty_native_domain import inspect as design
from c07_p345_forty_native_evidence import inspect as topology
from c07_r171_r180_source_native import inspect as process
from c07_mg0_individual import inspect_batch

def need(ok, code):
    if not ok:raise ValueError(code)
def sha(b):return hashlib.sha256(b).hexdigest()

def source_readback(context):
    need(type(context) is dict and set(context)=={
        "inventory","plan","controller","asset","step","work","source_loader"
    } and callable(context["source_loader"]),"C07_25_CONTEXT_REQUIRED")
    inv=context["inventory"];plan=context["plan"];work=context["work"]
    ctrl=context["controller"]
    canonical(inv)
    need(type(plan) is dict and type(work) is dict and
         plan.get("phase")==work.get("phase") and
         work.get("phase") in ("P3","P4","P5","P6","P7","P8") and
         inv.get("canonical_master_sha256")==plan.get("master_sha256")==
         work.get("master_sha256") and
         all(type(work.get(k)) is str and
             re.fullmatch("[a-f0-9]{64}",work[k]) for k in (
                 "attempt_id","operation_sha256")),"C07_25_PHASE_ATTEMPT_REQUIRED")
    master=ctrl.master.read_bytes()
    audit=ctrl.audit_path(context["asset"]).read_bytes()
    need(type(master) is bytes and type(audit) is bytes and
         sha(master)==work["master_sha256"],"C07_25_MASTER_AUDIT_CHANGED")
    args=(inv,plan,ctrl,context["asset"],context["step"],work)
    kw={"source_loader":context["source_loader"]}
    sources=(research(*args,**kw),planning(*args,**kw),
             design(*args,**kw),topology(*args,**kw),process(*args,**kw))
    negative=inspect_batch(master,audit,context["asset"],work["master_sha256"],
                           list(IDS),work["attempt_id"])
    need(negative.get("rule_count")==25 and
         set(negative.get("rules",{}))==set(IDS) and
         negative.get("audit_sha256")==sha(audit) and
         negative.get("counts",{}).get("PASS")==0 and
         negative.get("individual_mg0_passes")==0 and
         negative.get("advancement_authorized") is False,
         "C07_25_MG0_NEGATIVE_REQUIRED")
    for engine,count in zip(sources,(20,50,30,40,10)):
        need(engine.get("original_audit_sha256")==sha(audit) and
             engine.get("original_audit_tail")==negative["audit_tail_sha256"] and
             engine.get("attempt_id")==work["attempt_id"] and
             engine.get("operation_sha256")==work["operation_sha256"] and
             (engine.get("source_rules_examined")==count or
              engine.get("source_rule_count")==count) and
             engine.get("full_rule_passes",engine.get("full_semantic_passes"))==0 and
             engine.get("individual_mg0_passes")==0 and
             engine.get("advancement_authorized") is False,
             "C07_25_NATIVE_SOURCE_REPLAY_DIVERGED:"+str(count))
    return sources,negative,sha(audit)

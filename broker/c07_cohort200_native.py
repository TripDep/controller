"""C07: real 200-rule governance and final QA original-evidence consumer.

200 new source IDs (153 whole non-asset governance families, Q254-Q300).
Every per-rule observation is tied to the current exact source, Controller
audit, registered source bytes, and the source-specific proof role.
These are NOT 200 certified semantic validators; missing independent owner,
native review or MG0 evidence remains UNKNOWN, never PASS.
"""
from pathlib import Path
import re
from c07_positive_native_process import _original_attempt,_registered_artifacts,sha
from c07_cohort200_source import select,CohortSourceBlocked
from c07_cohort200_canonical import FAMILY_COUNTS,Q_IDS,TOTAL
from c07_cohort200_domains import FAMILY_LANES,QUESTION_BANDS
from glb_machine_qa import audit_bytes,MAX_BYTES,GLBError
from glb_pbr_evidence import validate_png_chunks,MaterialEvidenceError

SCHEMA="gg-c07-153governance-47finalquestions-original-readback-v1"
class NativeCohort200Blocked(ValueError):pass
def need(value,why):
    if not value:raise NativeCohort200Blocked(why)

def inspect(inventory,plan,controller,asset,step,work,*,source_loader):
    need(callable(source_loader),"C07_200_ORIGINAL_BYTES_READER_REQUIRED")
    ids,families=select(inventory,controller,work)
    records,tail,state,audit_sha=_original_attempt(
        inventory,plan,controller,asset,step,work)
    need(state.get("last_audit_hash")==tail and
         (state.get("active_step") or {}).get("step")==step,
         "C07_200_AUDIT_STATE_SHA_CHANGED")
    artifacts=_registered_artifacts(
        records,state,step,source_loader,work)
    roles={}
    for role,path,digest,raw in artifacts:
        need(type(role) is str and type(raw) is bytes and
             sha(raw)==digest,"C07_200_UNVERIFIED_ORIGINAL_BYTES")
        roles.setdefault(role,[]).append((path,digest,raw))
    def artifact(role):
        rows=roles.get(role,[])
        if len(rows)!=1:return False
        path,digest,raw=rows[0]
        if role.startswith("VISUAL_VIEW_") and Path(path).suffix.lower()==".png":
            try:validate_png_chunks(raw)
            except (MaterialEvidenceError,ValueError,TypeError,IndexError):return False
            return True
        return not role.startswith("VISUAL_VIEW_")
    glbs=[row for row in roles.get("NATIVE_EXPORT",())
          if Path(row[0]).suffix.lower()==".glb"]
    need(len(glbs)<=1,"C07_200_AMBIGUOUS_GLB")
    glb=None
    if glbs:
        raw=glbs[0][2]
        need(len(raw)<=MAX_BYTES,"C07_200_GLB_BUDGET_EXCEEDED")
        try:glb=audit_bytes(raw)
        except (GLBError,ValueError,TypeError,KeyError,IndexError) as exc:
            raise NativeCohort200Blocked(
                "C07_200_INVALID_REGISTERED_GLB:"+str(exc)) from exc
        need(glb["source_sha256"]==glbs[0][1],
             "C07_200_GLB_ORIGINAL_SHA_CHANGED")
    scoped=[e for e in records if e.get("step")==step and
            e.get("attempt_id")==work["attempt_id"] and
            e.get("operation_sha256")==work["operation_sha256"]]
    def event(name):
        return any(e.get("event")==name for e in scoped)
    def field(name):
        x=plan
        for part in name.split("."):
            if type(x) is not dict or part not in x:return False
            x=x[part]
        return type(x) in (dict,list,str,int,float) and bool(x)
    def dependencies():
        dep=plan.get("dependency_files")
        declared=work.get("work_dependencies")
        if (type(dep) is not dict or not dep or
            type(declared) is not dict or set(dep)!=set(declared)):
            return False
        root=getattr(controller,"root",None)
        if not isinstance(root,Path):return False
        for k,p in dep.items():
            need(type(k) is str and re.fullmatch("[0-9a-f]{64}",k)
                 and type(p) is str and p and
                 not Path(p).is_absolute() and
                 ".." not in Path(p).parts and
                 (root/p).resolve().is_relative_to(root.resolve()),
                 "C07_200_DEPENDENCY_ESCAPED_ROOT")
            raw=source_loader(str(root/p))
            if type(raw) is not bytes or sha(raw)!=declared[k]:return False
        return True
    def check(desc):
        category,_,key=desc.partition(":")
        if category=="R":return artifact(key)
        if category=="E":return event(key)
        if category=="P":return field(key)
        if category=="M":
            return bool(glb and {
                "glb_geometry":glb["triangles_examined"]>0 and
                               not glb["errors"],
                "crossing_scan":glb["triangle_surface_crossing_evidence"]
                                  ["all_requested_pairs_fully_scanned"] is True,
            }.get(key,False))
        if category=="X":
            return {
                "master":sha(controller.master.read_bytes())==
                          inventory["canonical_master_sha256"],
                "current_audit":state.get("last_audit_hash")==tail,
                "original_dependencies":dependencies(),
                "lock_present":bool(plan.get("operation",{}).get("locks")),
                "delivery_status":state.get("delivery_status") in
                                  ("NOT_DELIVERABLE","PENDING","BLOCKED"),
                "regression_source":artifact("REGRESSION_EVIDENCE"),
            }.get(key,False)
        raise NativeCohort200Blocked("C07_200_UNKNOWN_EVIDENCE_ORACLE:"+desc)
    def question_band(n):
        results=[tuple(probes) for first,last,probes in QUESTION_BANDS
                 if first<=n<=last]
        need(len(results)==1,
             "C07_200_QUESTION_SCOPE_NOT_DEFINED:"+str(n))
        return results[0]
    need(len(FAMILY_LANES)==len(FAMILY_COUNTS)==17 and
         set(FAMILY_LANES)==set(FAMILY_COUNTS),
         "C07_200_ALL_17_DOMAINS_REQUIRED")
    need(len(QUESTION_BANDS)==6 and
         {n for a,b,_ in QUESTION_BANDS for n in range(a,b+1)}
         ==set(range(254,301)),
         "C07_200_ALL_47_QA_DOMAINS_REQUIRED")
    proofs={}
    # A per-rule receipt is not a producer PASS. It is observed only when
    # it binds this exact original source clause to actual original file bytes.
    available_hashes={d for _,_,d,_ in artifacts}
    for e in scoped:
        if e.get("event")!="SUPERVISOR_RULE_EVIDENCE":continue
        rid=e.get("rule_id")
        if rid not in ids:continue
        doc=inventory["rules"][rid]
        digest=e.get("artifact_sha256")
        if (e.get("requirement_sha256")==doc["requirement_sha256"] and
            digest in available_hashes):
            proofs.setdefault(rid,set()).add(digest)
    out={};observed=0
    for rid in ids:
        rule=inventory["rules"][rid]
        family=families[rid]
        is_question=family=="QUESTIONS_300"
        if is_question:
            n=int(rid.split("-")[1])
            probes=question_band(n)
        else:probes=FAMILY_LANES[family]
        need(len(probes)==3 and len(set(probes))==3,
             "C07_200_THREE_DISTINCT_NATIVE_CHECKS:"+rid)
        facts={
           "original_requirement_sha_recomputed":
                 rule["requirement_sha256"]==
                 sha(rule["requirement"].encode()),
           "original_domain_witness_1:"+probes[0]:bool(check(probes[0])),
           "original_domain_witness_2:"+probes[1]:bool(check(probes[1])),
           "original_domain_witness_3:"+probes[2]:bool(check(probes[2])),
           "current_rule_specific_original_file_witness":bool(proofs.get(rid)),
           "complete_semantics_independently_approved":False,
        }
        observed+=sum(facts.values())
        out[rid]={
           "rule_id":rid,"family":family,
           "original_requirement":rule["requirement"],
           "requirement_sha256":rule["requirement_sha256"],
           "original_source_sha256":rule["source_sha256"],
           "original_machine_criteria":facts,
           "observed_original_evidence":sorted(k for k,v in facts.items() if v),
           "missing_independent_evidence":sorted(k for k,v in facts.items() if not v),
           "full_rule_semantics":"UNKNOWN","individual_mg0":"UNKNOWN",
           "owner_approval":"UNKNOWN","advancement_authorized":False,
        }
    need(len(out)==TOTAL==200 and
         set(out)==set(ids) and all(len(x["original_machine_criteria"])==6
                                   for x in out.values()),
         "C07_200_EXACT_200_SOURCE_BOUND_CONTRACTS_REQUIRED")
    return {
       "schema":SCHEMA,"source_rules_examined":200,
       "governance_rules_examined":153,"final_question_rules_examined":47,
       "original_source_evidence_checks":1200,
       "original_evidence_observed":observed,
       "current_original_glb_sha256":glb["source_sha256"] if glb else None,
       "original_audit_sha256":audit_sha,"original_audit_tail":tail,
       "attempt_id":work["attempt_id"],
       "operation_sha256":work["operation_sha256"],
       "full_rule_passes":0,"individual_mg0_passes":0,
       "advancement_authorized":False,"rules":out,
    }

"""C07 R115: ONE authenticated semantic evidence pass over the first 200 rules.

This runs native source-code checks across all 200 rules, not a wording/count
review. Every rule gets its independently evaluated evidence lanes, failures,
source binding, and precise unknowns. It deliberately does NOT install 200 fake
positive/MG0 validators. All 200 retain independent positive obligations.
"""
import hashlib
import json
from pathlib import Path

import c07_answer_semantics as questions
import c07_compound_subchecks as compounds
import c07_operation_scope as scope
from approved_validators import REVIEWED
from glb_rule_bridge import CANONICAL_GLB_RULES, verify_live_batch
from c07_negative_semantic_replay import inspect as inspect_negative

SCHEMA='gg-c07-first200-executed-evidence-v1'

# Explicitly reviewed source-specific proof lanes, not automatic semantic PASS.
# These cover EVERY AAA-200 section. Each subject lane requires an independently
# audited source of its OWN type. One valid GLB cannot prove a reference license,
# artistic fidelity, game runtime, safety, or a client's approval.
SECTION_LANES = {
    'A': ('CONTROLLER_PROCESS', 'OWNER_SCOPE', 'INDEPENDENT_QUALITY_REVIEW'),
    'B': ('CONTROLLER_PROCESS', 'ARCHITECTURAL_PLAN', 'SOURCE_PROVENANCE'),
    'C': ('REFERENCE_PROVENANCE', 'LICENSE_COMPLIANCE', 'HUMAN_REFERENCE_REVIEW'),
    'D': ('VISUAL_MULTIVIEW', 'ARCHITECTURAL_PLAN', 'HUMAN_DESIGN_REVIEW'),
    'E': ('MEASURED_SITE', 'WORLD_ALIGNMENT', 'HUMAN_LAYOUT_REVIEW'),
    'F': ('GLB_GEOMETRY', 'VISUAL_MULTIVIEW', 'WALKABILITY_REVIEW'),
    'G': ('GLB_GEOMETRY', 'TOPOLOGY', 'HUMAN_GEOMETRY_REVIEW'),
    'H': ('GLB_GEOMETRY', 'CONSTRUCTION_REFERENCE', 'HUMAN_ARCHITECTURE_REVIEW'),
    'I': ('GLB_GEOMETRY', 'NATURAL_FORM_REFERENCE', 'HUMAN_ORGANIC_REVIEW'),
    'J': ('GLB_MATERIAL', 'BOTANY_SOURCE', 'FIVEM_VEGETATION_RUNTIME'),
    'K': ('MEASURED_TERRAIN', 'GLB_GEOMETRY', 'WATER_WALKABILITY_RUNTIME'),
    'L': ('GLB_GEOMETRY', 'GLB_MATERIAL', 'BLENDER_REIMPORT_VISUAL'),
    'M': ('GLB_MATERIAL', 'REFERENCE_PROVENANCE', 'FIVEM_SHADER_RUNTIME'),
    'N': ('MULTILIGHT_RENDER', 'VISUAL_MULTIVIEW', 'HUMAN_LIGHTING_REVIEW'),
    'O': ('GLB_GEOMETRY', 'MATERIAL_MEMORY', 'FIVEM_PERFORMANCE_BENCHMARK'),
    'P': ('COLLISION_SOURCE', 'FIVEM_WALKABILITY_RUNTIME', 'HUMAN_COLLISION_REVIEW'),
    'Q': ('GAME_NATIVE_FORMAT', 'FIVEM_RUNTIME', 'CODEWALKER_REIMPORT'),
    'R': ('CONTROLLER_PROCESS', 'SOURCE_PROVENANCE', 'DEPENDENCY_READBACK'),
    'S': ('GLB_GEOMETRY', 'VISUAL_MULTIVIEW', 'HUMAN_DELIVERY_QA'),
    'T': ('EXACT_DELIVERY_BYTES', 'SOURCE_PROVENANCE', 'OWNER_DELIVERY_APPROVAL'),
}

class BatchBlocked(ValueError):
    pass

def require(ok, why):
    if not ok: raise BatchBlocked(why)

def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,ensure_ascii=False,
              separators=(',',':'),allow_nan=False).encode('utf-8')).hexdigest()

def _first200(inventory):
    require(inventory.get('schema')=='gg-effective-family-inventory-v1' and
            inventory.get('rule_count')==763, 'R115_CANONICAL_763_REQUIRED')
    ids=[rid for group in inventory['families'].values() for rid in group]
    require(len(ids)==763 and len(set(ids))==763 and set(ids)==set(inventory['rules']),
            'R115_MEMBERSHIP_CHANGED')
    first=sorted(ids)[:200]
    require(first[:2]==['110_ERROR_REGISTRY','A'] and
      first[2:]==['AAA-200-'+chr(65+(n-1)//10)+'-'+str(n).zfill(3)
                  for n in range(1,199)],'R115_FIRST200_SOURCE_ORDER_DRIFT')
    return first

def inspect(inventory,plan,*,audit_raw=None,asset=None,attempt_id=None,
            operation_sha256=None,registered_glb_path=None,glb_sha256=None,
            r173_qa_raw=None,r173_catalog_raw=None,
            current_process_observation=None):
    """Execute 200 rule-bound contracts using actual verified source readers.

    No producer-supplied FAIL/PASS maps. The R173 historical report is re-read
    from raw private Git bytes; GLB is re-scanned by exact SHA; Controller audit
    is checked from complete raw chain. Optional R178 may be supplied ONLY as a
    Controller-produced source scope observation (never work acceptance).
    """
    first=_first200(inventory)
    applicability=scope.inspect(inventory,plan)
    ledger=questions.build(inventory)
    due=set(applicability['due'])
    require(set(applicability['by_rule'])==set(inventory['rules']),
            'R115_OPERATIONAL_SCOPE_INCOMPLETE')
    compos=compounds.inspect(inventory,sorted(due & set(first)))
    raw_inputs=[audit_raw,asset,attempt_id,operation_sha256]
    negative=None
    if any(v is not None for v in raw_inputs):
        require(type(audit_raw) is bytes and type(asset) is str and
                type(attempt_id) is str and type(operation_sha256) is str,
                'R115_EXACT_AUDIT_ALL_OR_NOTHING')
        negative=inspect_negative(inventory,plan,audit_raw,asset,attempt_id,
                                  operation_sha256=operation_sha256)
        require(negative['rule_count']==763 and
                negative['batch_counts']==[200,200,200,163] and
                negative['positive_semantic_passes']==0 and
                negative['individual_mg0_passes']==0 and
                negative['advancement_authorized'] is False,
                'R115_UNTRUSTED_NEGATIVE_AUDIT')
    native=None
    if registered_glb_path is not None or glb_sha256 is not None:
        require(negative is not None and registered_glb_path is not None and
                type(glb_sha256) is str and len(glb_sha256)==64,
                'R115_REGISTERED_GLB_REQUIRES_TRUSTED_AUDIT_AND_SHA')
        # Controller must supply a REGISTERED artifact path and its sha, never
        # an unchecked path or a producer's scanner report. The scanner itself
        # re-reads the exact original bytes and checks SHA.
        native=verify_live_batch(Path(registered_glb_path),glb_sha256,
             {'asset_id':asset,'attempt_id':attempt_id,
              'operation_sha256':operation_sha256,
              'master_sha256':inventory['canonical_master_sha256'],
              'phase':plan['phase']},sorted(first))
        require(native['rule_count']==200 and
                set(native['rules'])==set(first) and
                native['individual_mg0_passes']==0 and
                native['work_rule_passes']==0 and
                native['advancement_authorized'] is False,
                'R115_UNTRUSTED_NATIVE_BATCH')
    documents={}
    if r173_qa_raw is not None or r173_catalog_raw is not None:
        require(type(r173_qa_raw) is bytes and type(r173_catalog_raw) is bytes,
                'R115_DOCUMENTARY_SOURCE_PAIR')
        from r173_rule_semantics import inspect as inspect_r173
        doc=inspect_r173(r173_qa_raw,r173_catalog_raw)
        require(doc['individual_rule_mg0_passes']==0 and
                doc['advancement_authorized'] is False and
                len(doc['results'])==11,'R115_R173_SOURCE_REPLAY_INVALID')
        documents=doc['results']
    if current_process_observation is not None:
        require(negative is not None and
                current_process_observation.get('schema')==
                  'gg-c07-r178-current-process-readback-v1' and
                current_process_observation.get('attempt_id')==attempt_id and
                current_process_observation.get('operation_sha256')==operation_sha256 and
                current_process_observation.get('master_sha256')==
                   inventory['canonical_master_sha256'] and
                current_process_observation.get('positive_3d_rule_semantic_passes')==0 and
                current_process_observation.get('individual_mg0_passes')==0 and
                current_process_observation.get('advancement_authorized') is False,
                'R115_R178_CURRENT_PROCESS_SOURCE_MISMATCH')
    negmap={}
    if negative:
        negmap={rid:row for chunk in negative['batches'] for rid,row in chunk['rules'].items()}
        require(len(negmap)==763,'R115_NEGATIVE_FULL_SET_REQUIRED')
    rows={}
    counts={'DUE':0,'NOT_DUE':0,'FAIL':0,'UNKNOWN':0,
            'REGISTERED_GLB_BATCH_SLOTS_SCANNED':0,
            'RULE_SPECIFIC_GLTF_NEGATIVE_PREDICATES':0,
            'SOURCE_BOUND_MACHINE_POSITIVE_SUBPREDICATES_OBSERVED':0,
            'HISTORICAL_DOCUMENTARY_EVALUATED':0,
            'REVIEWED_NATIVE_POSITIVE_IMPLEMENTED':0,
            'NO_INDEPENDENT_POSITIVE_VERIFIER':0}
    for rid in first:
        source=inventory['rules'][rid]
        entry=ledger['entries'][rid]
        require(entry['requirement_sha256']==source['requirement_sha256'] and
                entry['source_sha256']==source['source_sha256'],
                'R115_SOURCE_REQUIREMENT_DRIFT:'+rid)
        family=source.get('catalog_section') if rid.startswith('AAA-200-') else None
        require(family is None or family in SECTION_LANES,
                'R115_NO_SPECIALIZED_PROOF_LANES:'+rid)
        required=SECTION_LANES[family] if family else (
                 'MASTER_AUTHORITY','CONTROLLER_PROCESS','OWNER_VERIFIED_SCOPE')
        relevant=rid in due
        counts['DUE' if relevant else 'NOT_DUE']+=1
        n=negmap.get(rid)
        flags=[]
        if relevant and n and n['semantic_negative_verdict']=='FAIL':
            flags.append('INDEPENDENT_AUDIT_OR_ADMITTED_DEFECT')
        if relevant and native:
            machine=native['rules'][rid]
            counts['REGISTERED_GLB_BATCH_SLOTS_SCANNED']+=1
            if rid in CANONICAL_GLB_RULES:
                counts['RULE_SPECIFIC_GLTF_NEGATIVE_PREDICATES']+=1
            if machine.get('scoped_positive_machine_observation',{}).get('result') == 'OBSERVED_SCOPE_PASS':
                counts['SOURCE_BOUND_MACHINE_POSITIVE_SUBPREDICATES_OBSERVED']+=1
            if machine['independent_native_rule_observation']=='FAIL':
                flags.extend(machine['native_negative_findings'])
        documentary=documents.get(rid)
        if relevant and documentary:
            counts['HISTORICAL_DOCUMENTARY_EVALUATED']+=1
            # R173 FAIL is a real documentary observation about R173 only,
            # NOT a current project failure for some unrelated work attempt.
        process=None
        if relevant and rid=='AAA-200-R-178' and current_process_observation:
            process=current_process_observation['current_operation_process_observation']
            if process=='FAIL': flags.extend(current_process_observation['failed_criteria'])
        verified_positive = rid in REVIEWED  # implementation, not successful evidence
        if relevant:
            counts['REVIEWED_NATIVE_POSITIVE_IMPLEMENTED' if verified_positive
                   else 'NO_INDEPENDENT_POSITIVE_VERIFIER']+=1
        status=('NOT_DUE' if not relevant else 'FAIL' if flags else 'UNKNOWN')
        if relevant:counts[status]+=1
        rows[rid]={
          'source_sha256':source['source_sha256'],
          'requirement_sha256':source['requirement_sha256'],
          'phase_applicability':applicability['by_rule'][rid]['disposition'],
          'semantic_requirement':source['requirement'],
          'source_questions':entry['questions'],
          'required_independent_evidence_lanes':list(required),
          'composite_source_clauses':compos['due_composites'].get(rid,{}).get('source_subcheck_count',0),
          'native_negative_test_executable':rid in CANONICAL_GLB_RULES,
          'negative_test_executed_on_original_glb':native is not None and rid in CANONICAL_GLB_RULES,
          'native_negative_findings':native['rules'][rid]['native_negative_findings'] if native and relevant else [],
          'registered_glb_scoped_positive_machine_observation':(
              native['rules'][rid].get('scoped_positive_machine_observation')
              if native and relevant else None),
          'registered_glb_machine_scope_does_not_grant_rule_pass': True,
          'documentary_source_result':documentary['documentary_result'] if documentary else 'NOT_EVALUATED',
          'current_process_R178_scope':process,
          'audit_negative':n['semantic_negative_verdict'] if n and relevant else 'NOT_CHECKED',
          'independent_positive_semantic_validator_installed':verified_positive,
          'full_current_attempt_semantic_verdict':status,
          'blocking_findings':sorted(set(flags)),
          'unresolved_evidence':([] if not relevant else [
                 'REVIEW_ALL_RULE_SPECIFIC_POSITIVE_SEMANTIC_CLAUSES',
                 'VERIFY_INDIVIDUAL_MG0_ON_CURRENT_ATTEMPT',
                 'DO_NOT_EQUATE_SCOPED_DOCUMENTARY_OR_GLTF_CHECK_WITH_ARTISTIC_PASS']),
          'individual_mg0':'NOT_DUE' if not relevant else 'UNKNOWN',
          'advancement_authorized':False,
        }
    require(len(rows)==200 and len(set(rows))==200 and
            counts['DUE']+counts['NOT_DUE']==200,
            'R115_RULES_NOT_ALL_EVALUATED')
    segments=[]
    for at in range(0,200,100):
        ids=first[at:at+100]
        segments.append({'chunk':1+at//100,'count':100,
                         'rule_ids_sha256':digest(ids),
                         'results_sha256':digest({rid:rows[rid] for rid in ids})})
    return {
       'schema':SCHEMA,'first_rule':first[0],'last_rule':first[-1],
       'source_rule_count':200,'source_rule_ids_sha256':digest(first),
       'actual_native_single_scan':native is not None,
       'actual_source_audit_replayed':negative is not None,
       'historical_R173_source_replayed':bool(documents),
       'batch_segments':segments,'counts':counts,
       'failed_due_rule_ids':[rid for rid in first if rows[rid]['full_current_attempt_semantic_verdict']=='FAIL'],
       'positive_semantic_and_mg0_rule_passes':0,
       'complete_200_semantic_certifications':False,
       'advancement_authorized':False,'rules':rows,
       'status':'200_EXECUTED_EVIDENCE_LANES_MISSING_POSITIVE_SEMANTICS_REMAIN_BLOCKED',
    }

"""C07 exact-attempt native GLB evidence bridge; never grants rule or MG0 PASS.

Independent consumer must call this on the real immutable-hash-pinned GLB. A
producer-supplied scan JSON is never enough. No model bytes enter GitHub.
"""
import hashlib
import json
import re

from glb_machine_qa import examine
from glb_winding_readback import scan_file as scan_winding_file
from glb_material_culling_readback import scan as scan_material_culling

SCHEMA = 'gg-c07-glb-rule-evidence-exact-attempt-v1'
# Rule IDs, not generic categories. Each maps only to observations the
# exact hash-pinned GLB scanners can genuinely support. Unknown stays UNKNOWN.
CANONICAL_GLB_RULES = {
    'AAA-200-G-065': 'WINDING_AND_NORMAL_ORIENTATION',
    'AAA-200-G-067': 'INTERSECTION_CANDIDATES_REQUIRE_ARTISTIC_CONTEXT',
    'AAA-200-G-068': 'TRANSFORMS_NEED_SOURCE_REVIEW',
    'AAA-200-L-111': 'TRIANGLE_TOPOLOGY',
    'AAA-200-L-113': 'DEGENERATE_OR_NONFINITE_GEOMETRY',
    'AAA-200-L-114': 'TRIANGULATION_WINDING_REVIEW',
    'AAA-200-M-123': 'REQUIRED_TEXTURE_TEXCOORDS',
    'AAA-200-O-142': 'TRIANGLE_COUNT_WITHOUT_BUDGET',
    'AAA-200-S-183': 'INTERSECTION_CANDIDATES_REQUIRE_CONTEXT',
    'AAA-200-S-184': 'NORMALS_TRIANGLES_AND_ARTIFACTS',
    'AAA-200-S-189': 'TECHNICAL_CRITICAL_FINDINGS',
    'AAA-200-T-193': 'FILE_OPENABILITY_NEEDS_TARGET_REIMPORT',
}
LEGACY_DIAGNOSTIC_RULES = frozenset((
    'MACHINE_QA', 'HARD_FAILURE_CLASSES', 'VISUAL_QA',
    'ROUND_QUALITY', 'EXPORT_REIMPORT', 'FIVEM_TARGET', 'REGRESSION_QA'))
SCANNED_RULES = LEGACY_DIAGNOSTIC_RULES | frozenset(CANONICAL_GLB_RULES)
EXPECTED_CONTEXT = frozenset(('asset_id', 'attempt_id', 'operation_sha256',
                              'master_sha256', 'phase', 'rule_id'))
HEX64 = re.compile(r'[0-9a-f]{64}\Z')

class GLBBridgeBlocked(ValueError):
    pass

def require(condition, reason):
    if not condition:
        raise GLBBridgeBlocked(reason)

def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()

def verify_live(path, expected_glb_sha256, context, claimed_report=None):
    """Independently read and scan bytes, bind result to exact Controller attempt.

    A structurally bad file supplies negative evidence (FAIL) to the scoped
    rule; structurally clean files remain UNKNOWN pending all other proof.
    This function is a native evidence producer candidate, not enrollment or
    an approved Controller-side gate until integrated and reviewed.
    """
    require(type(context) is dict and set(context)==EXPECTED_CONTEXT,
            'C07_GLB_EXACT_ATTEMPT_CONTEXT_REQUIRED')
    require(type(context['asset_id']) is str and context['asset_id'] and
            context['asset_id'] == context['asset_id'].upper() and
            type(context['phase']) is str and context['phase'] and
            context['rule_id'] in SCANNED_RULES and
            all(type(context[k]) is str and HEX64.fullmatch(context[k])
                for k in ('attempt_id', 'operation_sha256', 'master_sha256')),
            'C07_GLB_UNTRUSTED_WORK_CONTEXT')
    require(type(expected_glb_sha256) is str and HEX64.fullmatch(expected_glb_sha256),
            'C07_GLB_SOURCE_DIGEST_REQUIRED')
    # Only `examine` reads and parses the exact local model source bytes.
    # The input `claimed_report` is merely a consistency challenge.
    measured = examine(path, expected_glb_sha256)
    require(measured.get('schema') == 'gg-c07-glb-readonly-machine-audit-v1' and
            measured.get('source_sha256') == expected_glb_sha256 and
            measured.get('machine_evidence_status') in (
                'FAIL','UNKNOWN_UNSUPPORTED_INPUT','NO_FATAL_STRUCTURAL_DEFECT_DETECTED') and
            measured.get('overall_rule_semantics') == 'UNKNOWN' and
            measured.get('asset_acceptance') == 'NOT_AUTHORIZED' and
            measured.get('mg0') == 'UNKNOWN' and
            measured.get('overlaps_confirmed') is False,
            'C07_GLB_MACHINE_EVIDENCE_CANNOT_AUTHORIZE')
    if claimed_report is not None:
        require(type(claimed_report) is dict and claimed_report == measured,
                'C07_GLB_PRODUCER_REPORT_DIFFERS_FROM_BYTES')
    # Independent re-read of the same immutable source: shared-edge winding
    # conflicts and nonmanifold edge topology provide concrete negative QA.
    # Open boundaries alone do NOT imply wrong geometry, and even no conflicts
    # remain UNKNOWN until real visual/runtime/MG0 review.
    winding = scan_winding_file(path, expected_glb_sha256)
    require(winding['source_sha256'] == expected_glb_sha256 and
            winding['asset_approved'] is False and
            winding['individual_mg0'] == 'UNKNOWN',
            'C07_GLB_WINDING_CANNOT_SELF_CERTIFY')
    observed_conflict = winding['orientation_conflict_meshes'] > 0
    # Independently re-read the hash-pinned source's render-side metadata;
    # never accept a producer claim that materials or normals are correct.
    from pathlib import Path
    material_culling = scan_material_culling(Path(path).read_bytes(),
                                            expected_glb_sha256)
    require(material_culling['source_sha256'] == expected_glb_sha256 and
            material_culling['asset_acceptance'] == 'NOT_AUTHORIZED' and
            material_culling['individual_mg0'] == 'UNKNOWN' and
            material_culling['advancement_authorized'] is False,
            'C07_GLB_MATERIAL_CULLING_CANNOT_SELF_CERTIFY')
    missing_uv = material_culling['missing_required_texcoord_attributes_count']>0
    verdict = ('FAIL' if measured['machine_evidence_status'] == 'FAIL'
               or observed_conflict or missing_uv else 'UNKNOWN')
    evidence = {
      'schema': SCHEMA, 'binding': dict(context),
      'artifact_sha256': expected_glb_sha256,
      'machine_report_sha256': canonical_sha(measured),
      'machine_status': measured['machine_evidence_status'],
      'render_side_source_evidence': {
        'source_sha256':material_culling['source_sha256'],
        'primitive_instances_examined':material_culling['primitive_instances_examined'],
        'materials_catalog_count':material_culling['materials_catalog_count'],
        'explicit_NORMAL_primitive_count':material_culling['explicit_NORMAL_primitive_count'],
        'explicit_TANGENT_primitive_count':material_culling['explicit_TANGENT_primitive_count'],
        'single_sided_primitive_count':material_culling['single_sided_primitive_count'],
        'missing_required_texcoord_attributes_count':
            material_culling['missing_required_texcoord_attributes_count'],
        'negative_world_determinant_nodes_count':
            material_culling['negative_world_determinant_nodes_count'],
        'negative_world_determinant_nodes_sha256':
            material_culling['negative_world_determinant_nodes_sha256'],
        'actual_face_visibility': 'UNKNOWN_NO_RENDER',
        'native_blender_visual': 'UNKNOWN',
        'individual_mg0': 'UNKNOWN',
      },
      'indexed_winding_evidence': {
        'source_sha256': winding['source_sha256'],
        'mesh_count': winding['mesh_count'],
        'consistent_meshes': winding['consistent_meshes'],
        'orientation_conflict_meshes': winding['orientation_conflict_meshes'],
        'same_direction_shared_edges': winding['same_direction_shared_edges'],
        'boundary_edges': winding['boundary_edges'],
        'nonmanifold_edges': winding['nonmanifold_edges'],
        'flagged_meshes_sha256': winding['flagged_meshes_sha256'],
        'topology_observation': winding['topology_observation'],
        'index_only_not_welded': True,
      },
      'geometry': {k:measured[k] for k in ('scene_mesh_nodes','triangles_examined',
                  'degenerate_triangles','invalid_indices','nonfinite_positions',
                  'aabb_overlap_candidates_count')},
      'fatal_machine_findings': measured['errors'] +
          (['GLB_INDEX_WINDING_OR_NONMANIFOLD_OBSERVED:'+
            str(winding['orientation_conflict_meshes'])]
           if observed_conflict else []) +
          (['GLB_TEXTURE_REQUIRED_TEXCOORD_MISSING:'+
            str(material_culling['missing_required_texcoord_attributes_count'])]
           if missing_uv else []),
      'material_source_evidence':measured['material_source_evidence'],
      'basecolor_pixel_evidence':measured['basecolor_pixel_evidence'],
      'unverified_requirements': {
        'triangle_intersections':'UNKNOWN',
        'visual_qa':'UNKNOWN', 'materials_pbr':'UNKNOWN',
        'export_reimport':'UNKNOWN', 'fivem_runtime':'UNKNOWN', 'mg0':'UNKNOWN',
      },
      'semantic_verdict': verdict,
      'individual_mg0':'UNKNOWN',
      'acceptance_authorized':False,
    }
    if context['rule_id'] in CANONICAL_GLB_RULES:
        # Do not misattribute an unrelated GLB fatal finding to an individual
        # artistic rule. The shared scanner still records ALL raw observations.
        scoped = _canonical_rule_evidence(context['rule_id'], evidence)
        evidence['semantic_verdict'] = scoped['independent_native_rule_observation']
        evidence['canonical_rule_observation'] = scoped
    evidence['evidence_sha256'] = canonical_sha(evidence)
    return evidence

def _canonical_rule_evidence(rule_id, native):
    """Only exact negative observations, never a subjective/artistic PASS."""
    g = native['geometry']
    w = native['indexed_winding_evidence']
    m = native['render_side_source_evidence']
    conflicts = int(w['orientation_conflict_meshes']) > 0
    bad_uv = int(m['missing_required_texcoord_attributes_count']) > 0
    degenerate = int(g['degenerate_triangles']) > 0
    nonfinite = int(g['nonfinite_positions']) > 0
    invalid = int(g['invalid_indices']) > 0
    fatal = native['machine_status'] == 'FAIL'
    mappings = {
        'AAA-200-G-065': [(conflicts,'INCONSISTENT_INDEXED_WINDING')],
        'AAA-200-L-111': [(invalid,'INVALID_TRIANGLE_INDICES'),
                          (degenerate,'DEGENERATE_TRIANGLES'),
                          (nonfinite,'NONFINITE_POSITIONS')],
        'AAA-200-L-113': [(degenerate,'DEGENERATE_TRIANGLES'),
                          (nonfinite,'NONFINITE_POSITIONS')],
        'AAA-200-L-114': [(conflicts,'INCONSISTENT_INDEXED_WINDING'),
                          (invalid,'INVALID_TRIANGLE_INDICES')],
        'AAA-200-M-123': [(bad_uv,'REQUIRED_TEXTURE_UV_MISSING')],
        'AAA-200-S-184': [(conflicts,'INCONSISTENT_INDEXED_WINDING'),
                          (degenerate,'DEGENERATE_TRIANGLES'),
                          (nonfinite,'NONFINITE_POSITIONS')],
        'AAA-200-S-189': [(fatal,'GLB_FATAL_STRUCTURE'),
                          (conflicts,'INCONSISTENT_INDEXED_WINDING'),
                          (bad_uv,'REQUIRED_TEXTURE_UV_MISSING')],
    }
    findings = [name for found,name in mappings.get(rule_id,()) if found]
    # A triangle pair crossing or mirrored transform is NOT automatically an
    # illegal compenetration or incorrect pivot: artistic context is necessary.
    return {
        'evidence_kind': CANONICAL_GLB_RULES.get(rule_id,
                        'NO_GLTF_NATIVE_PREDICATE_FOR_THIS_RULE'),
        'native_negative_findings': findings,
        'independent_native_rule_observation': 'FAIL' if findings else 'UNKNOWN',
        'visual_and_owner_approval': 'UNKNOWN',
        'individual_mg0': 'UNKNOWN',
        'semantic_rule_pass': False,
        'advancement_authorized': False,
    }


# R120: positive evidence is allowed only for a narrow, observed machine
# subpredicate. It is NOT a positive semantic rule, artistic or MG0 PASS.
MACHINE_POSITIVE_SCOPES = {
    'AAA-200-G-065': 'INDEXED_WINDING_WITHOUT_DETECTED_CONFLICT',
    'AAA-200-L-111': 'INDEXED_TOPOLOGY_WITHOUT_DETECTED_FATAL_ERRORS',
    'AAA-200-L-113': 'NONDEGENERATE_FINITE_TRIANGLES_OBSERVED',
    'AAA-200-L-114': 'VALID_INDEXED_TRIANGULATION_OBSERVED',
    'AAA-200-M-123': 'REQUIRED_TEXTURE_COORDINATE_ATTRIBUTES_READ',
    'AAA-200-O-142': 'EXACT_TRIANGLE_COUNT_MEASURED',
    'AAA-200-S-184': 'FINITE_INDEXED_GEOMETRY_WITHOUT_WINDING_CONFLICT',
    'AAA-200-S-189': 'NO_DETECTED_FATAL_GLTF_MACHINE_FINDING',
    'AAA-200-T-193': 'GLB_SOURCE_BYTES_ARE_STRUCTURALLY_PARSEABLE',
}

def _positive_machine_scope(rid, verified):
    """Return independently measured facts without certifying broad rules."""
    if rid not in MACHINE_POSITIVE_SCOPES:
        return {'scope':'NO_MACHINE_POSITIVE_SUBPREDICATE',
                'result':'UNKNOWN','complete_semantic_rule_pass':False,
                'individual_mg0_pass':False}
    g=verified['geometry']
    w=verified['indexed_winding_evidence']
    m=verified['render_side_source_evidence']
    supported=(verified['machine_status']=='NO_FATAL_STRUCTURAL_DEFECT_DETECTED'
               and int(g['scene_mesh_nodes'])>0 and int(g['triangles_examined'])>0)
    winding=(int(w['mesh_count'])>0 and int(w['orientation_conflict_meshes'])==0
             and int(w['nonmanifold_edges'])==0)
    sound=(int(g['invalid_indices'])==0 and int(g['nonfinite_positions'])==0
           and int(g['degenerate_triangles'])==0)
    predicates={
        'AAA-200-G-065': winding,
        'AAA-200-L-111': sound,
        'AAA-200-L-113': int(g['degenerate_triangles'])==0 and
                         int(g['nonfinite_positions'])==0,
        'AAA-200-L-114': winding and int(g['invalid_indices'])==0,
        'AAA-200-M-123': int(m['primitive_instances_examined'])>0 and
                         int(m['missing_required_texcoord_attributes_count'])==0,
        'AAA-200-O-142': int(g['triangles_examined'])>0,
        'AAA-200-S-184': winding and sound,
        'AAA-200-S-189': not verified['fatal_machine_findings'],
        'AAA-200-T-193': True,
    }
    result=('OBSERVED_SCOPE_PASS' if supported and predicates[rid]
            else 'UNKNOWN_OR_MACHINE_NEGATIVE')
    return {'scope':MACHINE_POSITIVE_SCOPES[rid],'result':result,
            'supported_source_geometry':supported,
            'underlying_machine_observation':{
                'triangles_examined':int(g['triangles_examined']),
                'degenerate_triangles':int(g['degenerate_triangles']),
                'orientation_conflict_meshes':int(w['orientation_conflict_meshes']),
                'missing_required_texcoord_attributes_count':
                    int(m['missing_required_texcoord_attributes_count'])},
            'complete_semantic_rule_pass':False,'individual_mg0_pass':False}

def verify_live_batch(path, expected_glb_sha256, context, rule_ids):
    """Evaluate many canonical IDs from ONE registered-GLB scan.

    The Controller must derive all rule_ids from its trusted canonical
    inventory and approved exact-operation scope, not producer assertions.
    This standalone consumer never certifies a model or individual MG0.
    """
    require(type(context) is dict and set(context) ==
            EXPECTED_CONTEXT - {'rule_id'}, 'C07_GLB_BATCH_CONTEXT_SCHEMA')
    require(type(rule_ids) is list and 0 < len(rule_ids) <= 763 and
            rule_ids == sorted(set(rule_ids)) and
            all(type(v) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,90}',v)
                for v in rule_ids),
            'C07_GLB_BATCH_RULE_IDS_INVALID')
    common = verify_live(path, expected_glb_sha256,
                         {**context,'rule_id':'MACHINE_QA'})
    require(common['semantic_verdict'] in ('FAIL','UNKNOWN') and
            common['individual_mg0']=='UNKNOWN' and
            common['acceptance_authorized'] is False,
            'C07_GLB_BATCH_SCANNER_CANNOT_AUTHORIZE')
    shared_digest = common['evidence_sha256']
    results={}
    counts={'FAIL':0,'UNKNOWN':0}
    for rid in rule_ids:
        checked=_canonical_rule_evidence(rid,common)
        checked['scoped_positive_machine_observation'] = _positive_machine_scope(rid,common)
        verdict=checked['independent_native_rule_observation']
        counts[verdict]+=1
        checked.update({'rule_id':rid, 'source_sha256':expected_glb_sha256,
                        'shared_native_scan_sha256':shared_digest,
                        'attempt_id':context['attempt_id'],
                        'operation_sha256':context['operation_sha256'],
                        'requirement_digest_verified_by_controller':False})
        checked['evidence_sha256']=canonical_sha(checked)
        results[rid]=checked
    require(len(results)==len(rule_ids) and counts['FAIL']+counts['UNKNOWN'] ==
            len(rule_ids), 'C07_GLB_BATCH_RESULT_SET_INCOMPLETE')
    return {
        'schema':'gg-c07-real-glb-rule-observations-batch-v1',
        'source_sha256': expected_glb_sha256,
        'binding':dict(context),
        'shared_native_scan_sha256':shared_digest,
        'rule_count':len(rule_ids), 'rule_ids_sha256':canonical_sha(rule_ids),
        'native_observation_counts':counts, 'rules':results,
        'individual_mg0_passes':0, 'work_rule_passes':0,
        'advancement_authorized':False,
        'scope':'INDEPENDENT_NATIVE_NEGATIVE_ONLY_WITHOUT_VISUAL_OR_MG0_PASS',
    }

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
SCANNED_RULES = frozenset(('MACHINE_QA', 'HARD_FAILURE_CLASSES', 'VISUAL_QA',
                           'ROUND_QUALITY', 'EXPORT_REIMPORT', 'FIVEM_TARGET',
                           'REGRESSION_QA'))
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
    evidence['evidence_sha256'] = canonical_sha(evidence)
    return evidence
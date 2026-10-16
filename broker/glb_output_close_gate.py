"""C07 non-bypassable machine gate for Controller-registered GLB outputs.

A stable SHA and ARTIFACT_RECORDED event authenticate bytes, not their
quality. This gate re-scans the exact bytes before a mutating Controller
close(PASS). Fail/unsupported outputs STOP; structurally checked outputs
only proceed to the *existing* independent post-run Git semantic+MG0 gate.
No glTF, DCC, FiveM, visual, artistic or MG0 PASS is issued here.
"""
import hashlib
import json
import struct
from pathlib import Path

from glb_machine_qa import examine, GLBError
from native_format_evidence import inspect as inspect_native, NativeScanBlocked

SCHEMA='gg-c07-registered-output-preclose-machine-gate-v1'

class OutputGateBlocked(ValueError):
    pass

def require(ok,why):
    if not ok:
        raise OutputGateBlocked(why)

def canonical_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,
        separators=(',',':'),ensure_ascii=False).encode('utf-8')).hexdigest()

def inspect(artifacts,work,asset,step):
    require(type(artifacts) is list and type(work) is dict
            and type(asset) is str and type(step) is str,
            'OUTPUT_GATE_INPUT_SCHEMA')
    require(type(work.get('attempt_id')) is str and len(work['attempt_id'])==64
            and all(c in '0123456789abcdef' for c in work['attempt_id'])
            and type(work.get('operation_sha256')) is str
            and len(work['operation_sha256'])==64
            and type(work.get('master_sha256')) is str
            and len(work['master_sha256'])==64,
            'OUTPUT_GATE_EXACT_ATTEMPT_REQUIRED')
    results=[];blockers=[];seen=set();unsupported_formats=[];native_results=[]
    for item in artifacts:
        require(type(item) is dict and item.get('step')==step,
                'OUTPUT_GATE_STEP_OR_ARTIFACT_INVALID')
        raw_path=item.get('path')
        require(type(raw_path) is str and raw_path,
                'OUTPUT_GATE_MODEL_PATH')
        path=Path(raw_path)
        if path.suffix.lower()!='.glb':
            suffix=path.suffix.lower()
            unsupported_formats.append(suffix or 'NO_EXTENSION')
            sha=item.get('sha256')
            # All native paths must be registered, regular, immutable and
            # SHA-bound, not just .glb. This evidence cannot approve GTA/Blender.
            require(path.is_absolute() and path.is_file() and not path.is_symlink()
                    and not any(parent.is_symlink() for parent in path.parents),
                    'OUTPUT_GATE_NATIVE_PATH_INVALID')
            require(type(sha) is str and len(sha)==64
                    and all(c in '0123456789abcdef' for c in sha)
                    and type(item.get('size_bytes')) is int
                    and item['size_bytes']>20
                    and path.stat().st_size==item['size_bytes'],
                    'OUTPUT_GATE_NATIVE_SOURCE_METADATA_INVALID')
            require(sha not in seen,'OUTPUT_GATE_DUPLICATE_NATIVE_SOURCE')
            seen.add(sha)
            if suffix in ('.blend','.ydr'):
                try:
                    native=inspect_native(path,sha)
                    native_results.append(native)
                    if native['inspection']['binary_structure'] not in (
                            'BLOCK_FRAMING_CHECKED','RESOURCE_CONTAINER_VERIFIED_ONLY'):
                        blockers.append({'sha256':sha,
                            'reason':'NATIVE_STRUCTURE_UNKNOWN_OR_COMPRESSED',
                            'detail':native['inspection']['binary_structure']})
                except (NativeScanBlocked,ValueError,OSError,struct.error) as exc:
                    blockers.append({'sha256':sha,
                        'reason':'NATIVE_MACHINE_STRUCTURAL_INVALID',
                        'detail':str(exc)[:200]})
            blockers.append({'sha256':sha,
                             'reason':'OUTPUT_FORMAT_NO_INDEPENDENT_MACHINE_VERIFIER',
                             'detail':suffix or 'NO_EXTENSION'})
            continue
        require(path.is_absolute() and path.is_file() and not path.is_symlink()
                and not any(parent.is_symlink() for parent in path.parents),
                'OUTPUT_GATE_GLTF_PATH_INVALID')
        sha=item.get('sha256')
        require(type(sha) is str and len(sha)==64
                and all(c in '0123456789abcdef' for c in sha),
                'OUTPUT_GATE_ARTIFACT_DIGEST')
        require(sha not in seen,'OUTPUT_GATE_DUPLICATE_GLTF_SOURCE')
        seen.add(sha)
        size=item.get('size_bytes')
        require(type(size) is int and size>20 and path.stat().st_size==size,
                'OUTPUT_GATE_GLTF_SIZE_CHANGED')
        # examine reads bytes and independently verifies the recorded SHA.
        # The caller must also verify the append-only ARTIFACT_RECORDED entry.
        try:
            measured=examine(path,sha)
        except (GLBError,ValueError,KeyError,TypeError,IndexError,UnicodeError,
                OverflowError,MemoryError) as exc:
            blockers.append({'sha256':sha,'reason':'GLB_UNREADABLE_OR_UNSUPPORTED',
                             'detail':str(exc)[:200]})
            continue
        status=measured['machine_evidence_status']
        result={
            'registered_sha256':sha,
            'material_source_status':measured['material_source_evidence']['material_source_status'],
            'machine_status':status,
            'degenerate_triangles':measured['degenerate_triangles'],
            'invalid_indices':measured['invalid_indices'],
            'nonfinite_positions':measured['nonfinite_positions'],
            'strict_crossings_found':measured['triangle_surface_crossing_evidence'][
                'strict_surface_crossing_pairs_found'],
            'crossings_fully_scanned':measured['triangle_surface_crossing_evidence'][
                'all_requested_pairs_fully_scanned'],
            'material_warnings':measured['material_source_evidence']['pbr_diagnostic_warnings'],
            'real_basecolor_pixel_evidence':measured['basecolor_pixel_evidence'],
            'unverified_material_requirements':measured['material_source_evidence'][
                'pbr_unverified_requirements'],
            'asset_quality_and_runtime':'UNKNOWN',
            'individual_mg0':'UNKNOWN'
        }
        results.append(result)
        if measured['basecolor_pixel_evidence']['requires_visual_review']:
            blockers.append({'sha256':sha,
                'reason':'PBR_SYSTEMIC_DARK_TINT_REQUIRES_INDEPENDENT_VISUAL_REVIEW',
                'detail':'Actual base-color PNG pixels multiplied by near-1/255 factors across all used textured materials'})
        if status=='FAIL':
            blockers.append({'sha256':sha,'reason':'GLB_FATAL_GEOMETRY_OR_PBR_FINDING',
                             'detail':','.join(measured['errors'][:12])})
        elif status!='NO_FATAL_STRUCTURAL_DEFECT_DETECTED':
            blockers.append({'sha256':sha,'reason':'GLB_MACHINE_VERIFICATION_INCOMPLETE',
                             'detail':status})
        if not result['crossings_fully_scanned']:
            blockers.append({'sha256':sha,
                             'reason':'GLB_TRIANGLE_INTERSECTION_SCAN_INCOMPLETE',
                             'detail':str(measured['triangle_surface_crossing_evidence'][
                                 'unresolved_pairs'][:3])[:200]})
    if not artifacts:
        blockers.append({'sha256':'UNKNOWN','reason':'OUTPUT_GATE_NO_REGISTERED_ARTIFACTS',
                         'detail':'No output registered for controlled mutation'})
    if not results:
        blockers.append({'sha256':'UNKNOWN','reason':'OUTPUT_GATE_NO_VERIFIED_GLB',
                         'detail':'Non-GLB output requires an independently reviewed machine validator'})
    data={'schema':SCHEMA,'asset':asset,'step':step,
          'attempt_id':work['attempt_id'],'operation_sha256':work['operation_sha256'],
          'master_sha256':work['master_sha256'],
          'glb_outputs_scanned':len(results),'other_formats_not_verified':sorted(set(unsupported_formats)),
          'machine_results':results,'native_machine_results':native_results,
          'machine_blockers':blockers,
          'semantic_result':'UNKNOWN','individual_mg0':'UNKNOWN',
          'asset_acceptance':'NOT_AUTHORIZED','advancement_authorized':False,
          'may_continue_to_independent_native_post_review':not bool(blockers),
          'note':'Only a negative/unknown machine fail gate. A checked GLB is not an asset, rule, visual or MG0 PASS.'}
    data['evidence_sha256']=canonical_hash(data)
    return data

"""Executes inside official Blender bpy only; source is opened by Blender CLI.

This diagnostic inspects source and exports/reimports a GLB in a scratch dir.
Never saves the original .blend. Exporting and reimporting is not FiveM QA.
"""
import bpy
import hashlib
import json
import math
import os
import sys
from pathlib import Path


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def file_sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def geometry_info():
    """Scene visible objects; runtime-dependency and render judgments NOT made."""
    mesh_objects = [o for o in bpy.context.scene.objects
                    if o.type == 'MESH' and o.visible_get()]
    need(len(mesh_objects) > 0, 'BLENDER_SOURCE_NO_VISIBLE_MESH_OBJECTS')
    count_vertices = 0
    local_faces = 0
    bounds = [[float('inf')] * 3, [float('-inf')] * 3]
    from mathutils import Vector
    for o in mesh_objects:
        count_vertices += len(o.data.vertices)
        local_faces += len(o.data.polygons)
        for point in o.bound_box:
            world = o.matrix_world @ Vector(point)
            for i in range(3):
                bounds[0][i] = min(bounds[0][i], world[i])
                bounds[1][i] = max(bounds[1][i], world[i])
    need(all(math.isfinite(v) for b in bounds for v in b),
         'BLENDER_NONFINITE_SCENE_BOUNDS')
    return {'scene_name': bpy.context.scene.name,
            'visible_mesh_objects': len(mesh_objects),
            'visible_vertices_local': count_vertices,
            'visible_polygons_local': local_faces,
            'bounds_world': bounds,
            'materials_datablocks': len(bpy.data.materials),
            'images_datablocks': len(bpy.data.images)}


def main():
    # Blender invocation passes '-- --report-json ... --scratch-glb ...
    # --source-absolute ... --expected-source-sha256 ...'.
    from argparse import ArgumentParser
    need('--' in sys.argv, 'BLENDER_SCRIPT_MISSING_ARGUMENT_DELIMITER')
    p = ArgumentParser()
    p.add_argument('--report-json', required=True)
    p.add_argument('--scratch-glb', required=True)
    p.add_argument('--source-absolute', required=True)
    p.add_argument('--expected-source-sha256', required=True)
    args = p.parse_args(sys.argv[sys.argv.index('--') + 1:])
    source = Path(args.source_absolute)
    report_path = Path(args.report_json)
    target = Path(args.scratch_glb)
    need(source.is_absolute() and target.is_absolute() and report_path.is_absolute(),
         'BLENDER_SCRIPT_ABSOLUTE_PATHS_REQUIRED')
    need(source.exists() and file_sha(source) == args.expected_source_sha256,
         'BLENDER_SOURCE_SHA_INCONSISTENT')
    need(Path(bpy.data.filepath).resolve() == source.resolve(),
         'BLENDER_DID_NOT_OPEN_REQUESTED_SOURCE')
    before = geometry_info()
    need(hasattr(bpy.ops.export_scene, 'gltf'), 'BLENDER_GLTF_EXPORTER_UNAVAILABLE')
    # Note: do not use any code from the original blend (CLI disables autoexec).
    result = bpy.ops.export_scene.gltf(filepath=str(target), export_format='GLB',
                                      export_selected=False, export_apply=True)
    need('FINISHED' in result and target.is_file() and target.stat().st_size > 20,
         'BLENDER_GLTF_EXPORT_FAILED')
    export_sha = file_sha(target)
    # Clear all current objects before reimport; never save the source .blend.
    bpy.ops.wm.read_factory_settings(use_empty=True)
    importer = bpy.ops.import_scene.gltf(filepath=str(target))
    need('FINISHED' in importer, 'BLENDER_GLTF_REIMPORT_FAILED')
    after = geometry_info()
    need(file_sha(source) == args.expected_source_sha256,
         'BLENDER_ORIGINAL_SOURCE_CHANGED')
    bounds_before, bounds_after = before['bounds_world'], after['bounds_world']
    differences = [abs(bounds_before[k][i] - bounds_after[k][i])
                   for k in range(2) for i in range(3)]
    span = max(1.0, max(bounds_before[1][i] - bounds_before[0][i]
                        for i in range(3)))
    # Threshold is a diagnostic screen only, never a production-artifact verdict.
    bounds_within_tolerance = max(differences) <= max(0.02, span * 0.001)
    evidence = {
        'schema': 'gg-c07-headless-blender-roundtrip-runtime-v1',
        'source_sha256': args.expected_source_sha256,
        'source_name': source.name,
        'blender_version': bpy.app.version_string,
        'bpy_engine': 'REAL_BLENDER_BPY_HEADLESS',
        'source_opened_in_blender': True,
        'scratch_glb_sha256': export_sha,
        'scratch_glb_size_bytes': target.stat().st_size,
        'export_operator_finished': True,
        'reimport_operator_finished': True,
        'before': before,
        'after': after,
        'bounds_max_absolute_difference': max(differences),
        'bounds_within_diagnostic_tolerance': bounds_within_tolerance,
        'runtime_asset_approval': 'NOT_AUTHORIZED',
        'fiveM_runtime': 'NOT_TESTED',
        'artistic_judgment': 'UNKNOWN',
        'individual_mg0': 'UNKNOWN',
        'advancement_authorized': False,
    }
    report_path.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding='utf-8')
    # The report is written only after all stages, before normal process exit.


if __name__ == '__main__':
    main()
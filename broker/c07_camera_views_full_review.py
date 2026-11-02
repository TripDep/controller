"""Original Controller render-capture audit replay for P1 F056 and P4 N138.

Reopen four source PNGs and their current-attempt render events, compare true
decoded pixels and camera poses with original native geometry. This verifies
the documented QA capture operation, not aesthetic adequacy, camera truth
outside Controller, independent MG0, owner approval or FiveM runtime.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as p1_inspect, jbytes
from c07_p345_forty_native_evidence import inspect as p345_inspect
from c07_p678_forty_native_domain import inspect as p678_inspect
from c07_native_output_oracle import read_mesh_geometry
from visual_content_metrics import decode_grid, VisualContentBlocked

P1 = 'AAA-200-F-056'
P4 = 'AAA-200-N-138'
P8 = 'AAA-200-S-181'
RULES = frozenset((P1, P4, P8))
CRITERIA = {
    P1: (
        'pre_d_four_camera_capture_roles_and_current_operation_events_sha_pinned',
        'four_distinct_original_png_pixel_arrays_and_native_geometry_reopened',
        'front_left_right_top_original_camera_positions_and_axes_verified'),
    P4: (
        'pre_d_front_side_rear_top_capture_roles_and_current_operation_events_sha_pinned',
        'four_distinct_original_png_pixel_arrays_and_native_geometry_reopened',
        'front_side_rear_top_original_camera_positions_and_axes_verified'),
    P8: (
        'pre_d_six_original_view_roles_current_render_events_and_view_qa_sha_pinned',
        'six_original_view_pixel_arrays_and_native_geometry_independently_distinct',
        'six_original_camera_axes_and_individual_view_qa_checks_replayed'),
}
VIEWS = {
    P1: ('VISUAL_VIEW_FRONT','VISUAL_VIEW_LEFT',
         'VISUAL_VIEW_RIGHT','VISUAL_VIEW_TOP'),
    P4: ('VISUAL_VIEW_FRONT','VISUAL_VIEW_SIDE',
         'VISUAL_VIEW_REAR','VISUAL_VIEW_TOP'),
    P8: ('VISUAL_VIEW_FRONT','VISUAL_VIEW_LEFT','VISUAL_VIEW_RIGHT',
         'VISUAL_VIEW_REAR','VISUAL_VIEW_TOP','VISUAL_VIEW_UNDERSIDE'),
}
TRACE = {P1:'P1_CAMERA_CAPTURE_TRACE', P4:'P4_CAMERA_CAPTURE_TRACE',
         P8:'P8_CAMERA_CAPTURE_TRACE'}

class OriginalViewsBlocked(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise OriginalViewsBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def finite(x):
    return type(x) in (int, float) and math.isfinite(x)

def xyz(v):
    return type(v) is list and len(v) == 3 and all(finite(x) for x in v)

def direction_ok(role, camera, bounds):
    position = camera.get('position_xyz')
    direction = camera.get('forward_xyz')
    if not xyz(position) or not xyz(direction):
        return False
    length = math.sqrt(sum(x*x for x in direction))
    if not 0.99999 <= length <= 1.00001:
        return False
    label = role.rsplit('_', 1)[-1]
    axis = {'FRONT':(0,1,0),'LEFT':(1,0,0),'SIDE':(1,0,0),
            'RIGHT':(-1,0,0),'REAR':(0,-1,0),'TOP':(0,0,-1),
            'UNDERSIDE':(0,0,1)}.get(label)
    if axis is None or sum(direction[i]*axis[i] for i in range(3)) < 0.99999:
        return False
    lo, hi = bounds['bbox_min'], bounds['bbox_max']
    margin = 0.5
    side = {'FRONT':position[1] < lo[1]-margin,
            'LEFT':position[0] < lo[0]-margin,
            'SIDE':position[0] < lo[0]-margin,
            'RIGHT':position[0] > hi[0]+margin,
            'REAR':position[1] > hi[1]+margin,
            'TOP':position[2] > hi[2]+margin,
            'UNDERSIDE':position[2] < lo[2]-margin}
    return bool(side[label])

def inspect(source_context, rule_id):
    need(rule_id in RULES and type(source_context) is dict and
         set(source_context) == {'inventory', 'plan', 'controller',
                                 'asset', 'step', 'work', 'source_loader'},
         'C07_VIEWS_RULE_OR_CONTEXT')
    inv, plan, controller = (source_context[k] for k in
                             ('inventory','plan','controller'))
    asset, step, work, loader = (source_context[k] for k in
                                 ('asset','step','work','source_loader'))
    if rule_id == P1:
        p1_inspect(inv, plan, controller, asset, step, work,
                   source_loader=loader)
        pin_key = 'p1_evidence_contract'
    elif rule_id == P4:
        need(plan.get('phase') in ('P4','P5','P6','P7','P8','VERIFY',
                                  'G2','G3','G4','DELIVERY'),
             'C07_P4_VIEWS_WRONG_PHASE')
        p345_inspect(inv, plan, controller, asset, step, work,
                     source_loader=loader)
        pin_key = 'p345_evidence_contract'
    else:
        need(plan.get('phase') in ('P8','VERIFY','G2','G3','G4','DELIVERY'),
             'C07_P8_VIEWS_WRONG_PHASE')
        p678_inspect(inv, plan, controller, asset, step, work,
                     source_loader=loader)
        pin_key = 'p678_evidence_contract'
    rows, tail, state, audit_sha = _original_attempt(
        inv, plan, controller, asset, step, work)
    need(sha(controller.master.read_bytes()) == work['master_sha256'] and
         state.get('last_audit_hash') == tail and
         (state.get('active_step') or {}).get('step') == step,
         'C07_VIEWS_CURRENT_ORIGINAL_AUDIT_CHANGED')
    contract = plan.get(pin_key, {})
    pins = contract.get('original_artifact_sha256', {}) if type(contract) is dict else {}
    need(type(pins) is dict, 'C07_VIEWS_PRE_D_PINS')
    artifacts = {}
    for role, path, digest, raw in _registered_artifacts(
            rows, state, step, loader, work):
        need(role not in artifacts, 'C07_VIEWS_DUPLICATE_ROLE')
        artifacts[role] = (path, digest, raw)
    def original(role, ext):
        item = artifacts.get(role)
        return item[2] if (item and item[0].lower().endswith(ext)
            and pins.get(role) == item[1] and sha(item[2]) == item[1]) else None
    native = original('NATIVE_EXPORT', '.glb')
    bounds = read_mesh_geometry(native) if native is not None else None
    trace_raw = original(TRACE[rule_id], '.json')
    trace = jbytes(trace_raw) if trace_raw is not None else {}
    wanted = VIEWS[rule_id]
    frames = trace.get('frames')
    trace_ok = bool(trace.get('schema') == 'gg-c07-native-camera-capture-v1' and
        trace.get('attempt_id') == work['attempt_id'] and
        trace.get('operation_sha256') == work['operation_sha256'] and
        type(frames) is list and len(frames) == len(wanted) and
        all(type(frame) is dict and
            set(frame) == {'role','position_xyz','forward_xyz','image_sha256'}
            for frame in frames) and
        {frame['role'] for frame in frames} == set(wanted))
    frame_by_role = {frame['role']:frame for frame in frames} if trace_ok else {}
    open_index = next((i for i, row in enumerate(rows) if
        row.get('event') == 'SUPERVISOR_OPERATION_OPENED' and
        row.get('step') == step), -1)
    captures = [(i,row) for i,row in enumerate(rows) if
        row.get('event') == 'RENDER_CAPTURED' and row.get('step') == step]
    audit_ok = bool(open_index >= 0 and len(captures) == len(wanted) and
        {row.get('source_role') for _,row in captures} == set(wanted) and
        all(i > open_index and
            row.get('attempt_id') == work['attempt_id'] and
            row.get('operation_sha256') == work['operation_sha256'] and
            row.get('image_sha256') == frame_by_role.get(
                row.get('source_role'), {}).get('image_sha256')
            for i,row in captures))
    decoded = {}
    for role in wanted:
        raw = original(role, '.png')
        if raw is None:
            continue
        try:
            w,h,pixels = decode_grid(raw, step=1)
            if w >= 2 and h >= 2 and pixels:
                decoded[role] = {'sha256':sha(raw),
                    'pixel_sha256':sha(bytes(channel for pixel in pixels
                                             for channel in pixel))}
        except (ValueError, TypeError, VisualContentBlocked):
            continue
    pixels_ok = bool(bounds and len(decoded) == len(wanted) and
        len({v['pixel_sha256'] for v in decoded.values()}) == len(wanted) and
        all(decoded[role]['sha256'] == frame_by_role.get(role, {}).get('image_sha256')
            for role in wanted))
    qa_raw = original('P8_VIEW_QA', '.json') if rule_id == P8 else None
    qa = jbytes(qa_raw) if qa_raw is not None else {}
    qa_ok = (rule_id != P8 or bool(
        type(qa.get('checked_roles')) is list and
        len(qa['checked_roles']) == len(wanted) and
        set(qa['checked_roles']) == set(wanted) and
        type(qa.get('defect_counts')) is dict and
        set(qa['defect_counts']) == set(wanted) and
        all(type(v) is int and 0 <= v <= 10000
            for v in qa['defect_counts'].values())))
    camera_ok = bool(pixels_ok and trace_ok and audit_ok and qa_ok and
        all(direction_ok(role, frame_by_role[role], bounds) for role in wanted))
    checks = dict(zip(CRITERIA[rule_id], (
        bool(trace_ok and audit_ok and trace_raw is not None and
             (rule_id != P8 or qa_raw is not None) and
             all(original(role, '.png') is not None for role in wanted)),
        pixels_ok, camera_ok)))
    complete = bool(trace_ok and audit_ok and native is not None and
        trace_raw is not None and len(decoded) == len(wanted) and
        (rule_id != P8 or qa_raw is not None))
    need(set(checks) == set(CRITERIA[rule_id]) and
         all(type(v) is bool for v in checks.values()),
         'C07_VIEWS_EXACT_RULE_CRITERIA_CHANGED')
    return {'rule_id':rule_id,'checks':checks,
            'evidence_complete':complete,
            'source_sha256':inv['rules'][rule_id]['source_sha256'],
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'original_audit_sha256':audit_sha,
            'original_audit_tail':tail,
            'individual_mg0':'UNKNOWN','advancement_authorized':False}

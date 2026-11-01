"""N131/N132/N137 independent original P4 lighting and player-view QA.

Original PNG pixels, pre-D policy and current Controller capture events are
replayed. Technical QA captures do not prove artistic adequacy, external
renderer authenticity, independent MG0, owner approval or FiveM gameplay.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p345_forty_native_evidence import inspect as inspect_p345, binary_json
from c07_native_output_oracle import read_mesh_geometry
from visual_content_metrics import decode_grid, VisualContentBlocked
from c07_p345_light_pixel_replay import (neutral_pixel_qa, pixel_light_response,
                                         player_camera_horizontal_alignment)

NEUTRAL = 'AAA-200-N-131'
SEPARATE = 'AAA-200-N-132'
PLAYER = 'AAA-200-N-137'
RULES = frozenset((NEUTRAL, SEPARATE, PLAYER))
CRITERIA = {
    NEUTRAL: (
        'original_pre_d_neutral_light_policy_and_capture_event_sha_bound',
        'actual_neutral_view_pixels_redecoded_and_channel_balance_measured',
        'real_native_geometry_and_neutral_qa_luminance_in_source_range'),
    SEPARATE: (
        'pre_d_distinct_neutral_cinematic_modes_and_two_original_events_bound',
        'actual_neutral_and_cinematic_pixel_arrays_independently_distinct',
        'two_original_capture_modes_have_separate_source_roles_and_luminance'),
    PLAYER: (
        'pre_d_player_eye_height_camera_and_original_capture_event_sha_bound',
        'actual_player_view_png_and_native_geometry_independently_reopened',
        'measured_original_camera_at_player_height_and_facing_actual_asset'),
}

class LightingReviewBlocked(ValueError):
    pass

def need(value, why):
    if not value:
        raise LightingReviewBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def finite(x):
    return type(x) in (int, float) and math.isfinite(x)

def vec(x):
    return type(x) is list and len(x) == 3 and all(finite(v) for v in x)

def pixels(raw):
    if raw is None:
        return None
    try:
        w,h,grid = decode_grid(raw, step=1)
        if w < 2 or h < 2 or not grid:
            return None
        mean = tuple(sum(px[i] for px in grid)/len(grid) for i in range(3))
        return {'mean':mean, 'luma':sum(mean)/3,
                'pixel_sha256':sha(bytes(c for pixel in grid for c in pixel))}
    except (VisualContentBlocked, ValueError, TypeError):
        return None

def inspect(source_context, rule_id):
    need(rule_id in RULES and type(source_context) is dict and
         set(source_context) == {'inventory','plan','controller',
                                 'asset','step','work','source_loader'},
         'C07_P4_LIGHT_RULE_OR_CONTEXT')
    inv,plan,controller = (source_context[k] for k in
                           ('inventory','plan','controller'))
    asset,step,work,loader = (source_context[k] for k in
                              ('asset','step','work','source_loader'))
    need(plan.get('phase') in ('P4','P5','P6','P7','P8','VERIFY',
                              'G2','G3','G4','DELIVERY'),
         'C07_P4_LIGHT_PHASE_REQUIRED')
    inspect_p345(inv,plan,controller,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha = _original_attempt(
        inv,plan,controller,asset,step,work)
    need(sha(controller.master.read_bytes()) == work['master_sha256'] and
         state.get('last_audit_hash') == tail and
         (state.get('active_step') or {}).get('step') == step,
         'C07_P4_LIGHT_CURRENT_AUDIT_DRIFT')
    contract=plan.get('p345_evidence_contract',{})
    pins=contract.get('original_artifact_sha256',{}) if type(contract) is dict else {}
    need(type(pins) is dict,'C07_P4_LIGHT_PRE_D_PINS')
    found={}
    for role,path,digest,raw in _registered_artifacts(
            rows,state,step,loader,work):
        need(role not in found,'C07_P4_LIGHT_DUPLICATE_ORIGINAL_ROLE')
        found[role]=(path,digest,raw)
    def original(role,ext):
        item=found.get(role)
        return item[2] if (item and item[0].lower().endswith(ext)
            and pins.get(role)==item[1] and sha(item[2])==item[1]) else None
    policy_raw=original('P4_LIGHTING_QA','.json')
    policy=binary_json(policy_raw) if policy_raw is not None else {}
    native_raw=original('NATIVE_EXPORT','.glb')
    native=read_mesh_geometry(native_raw) if native_raw is not None else None
    neutral_raw=original('LIGHT_NEUTRAL_VIEW','.png')
    cinematic_raw=original('LIGHT_CINEMATIC_VIEW','.png')
    neutral_pixels=pixels(neutral_raw)
    cinematic_pixels=pixels(cinematic_raw)
    open_index=next((i for i,r in enumerate(rows) if
        r.get('event')=='SUPERVISOR_OPERATION_OPENED' and
        r.get('step')==step),-1)
    def capture(event,role,mode):
        matches=[(i,r) for i,r in enumerate(rows) if
            r.get('event')==event and r.get('step')==step and
            r.get('source_role')==role]
        return bool(open_index>=0 and len(matches)==1 and
            matches[0][0]>open_index and
            matches[0][1].get('attempt_id')==work['attempt_id'] and
            matches[0][1].get('operation_sha256')==work['operation_sha256'] and
            matches[0][1].get('mode')==mode and
            original(role,'.png') is not None and
            matches[0][1].get('image_sha256')==sha(original(role,'.png')))
    modes=policy.get('modes')
    light_policy=bool(type(modes) is list and
        set(modes)=={'neutral','cinematic'} and len(modes)==2 and
        finite(policy.get('neutral_lux')) and
        200<=policy['neutral_lux']<=1200)
    neutral_event=capture('LIGHT_CAPTURED','LIGHT_NEUTRAL_VIEW','neutral')
    cinematic_event=capture('LIGHT_CAPTURED','LIGHT_CINEMATIC_VIEW','cinematic')
    if rule_id==NEUTRAL:
        balanced=bool(neutral_pixels and
            max(neutral_pixels['mean'])-min(neutral_pixels['mean'])<=5 and
            neutral_pixel_qa(neutral_raw))
        checks=dict(zip(CRITERIA[rule_id],(
            bool(light_policy and neutral_event and policy_raw is not None),
            balanced,
            bool(native and balanced and 70<=neutral_pixels['luma']<=200))))
        complete=bool(policy_raw and native_raw and neutral_raw and neutral_event)
    elif rule_id==SEPARATE:
        different=bool(neutral_pixels and cinematic_pixels and
            neutral_pixels['pixel_sha256']!=cinematic_pixels['pixel_sha256'])
        separated=bool(different and
            abs(neutral_pixels['luma']-cinematic_pixels['luma'])>=20 and
            pixel_light_response(neutral_raw,cinematic_raw,direction=0,
                                 minimum_delta=20))
        checks=dict(zip(CRITERIA[rule_id],(
            bool(light_policy and neutral_event and cinematic_event),
            different, separated)))
        complete=bool(policy_raw and neutral_raw and cinematic_raw and
                      neutral_event and cinematic_event and
                      neutral_pixels and cinematic_pixels)
    else:
        camera_raw=original('P4_PLAYER_CAMERA','.json')
        camera=binary_json(camera_raw) if camera_raw is not None else {}
        player_raw=original('VISUAL_PLAYER_VIEW','.png')
        player_pixels=pixels(player_raw)
        camera_event=capture('RENDER_CAPTURED','VISUAL_PLAYER_VIEW','player')
        eye=policy.get('player_eye_height_m')
        position=camera.get('camera_xyz')
        forward=camera.get('forward_xyz')
        camera_policy=bool(camera_raw is not None and
            finite(eye) and 1.2<=eye<=2.2 and
            vec(position) and vec(forward) and
            abs(math.sqrt(sum(v*v for v in forward))-1)<1e-5)
        oriented=bool(camera_policy and native and
            abs(position[2]-native['bbox_min'][2]-eye)<=0.05 and
            position[1]<native['bbox_min'][1]-0.5 and
            abs(forward[0])<0.01 and forward[1]>0.999 and
            abs(forward[2])<0.01 and
            player_camera_horizontal_alignment(position,forward,native))
        checks=dict(zip(CRITERIA[rule_id],(
            bool(camera_policy and camera_event and policy_raw is not None),
            bool(native and player_pixels),
            oriented)))
        complete=bool(policy_raw and camera_raw and native_raw and
                      player_raw and camera_event and player_pixels)
    need(set(checks)==set(CRITERIA[rule_id]) and
         all(type(v) is bool for v in checks.values()),
         'C07_P4_LIGHT_PER_LITERAL_CRITERIA_CHANGED')
    return {'rule_id':rule_id,'checks':checks,
            'evidence_complete':complete,
            'source_sha256':inv['rules'][rule_id]['source_sha256'],
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256'],
            'original_audit_sha256':audit_sha,
            'original_audit_tail':tail,
            'individual_mg0':'UNKNOWN','advancement_authorized':False}

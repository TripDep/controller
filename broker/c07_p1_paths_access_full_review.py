"""Independent source-byte P1 path hierarchy and access-zone geometry review.

Only original Controller-registered, pre-D pinned GeoJSON and scene contracts
are accepted. P1 plan geometry is not proof of FiveM collision or owner approval.
"""
import hashlib
import math

from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_p1_thirty_native_domain import inspect as p1_inspect, jbytes

PATH_RULE = 'AAA-200-E-044'
ZONE_RULE = 'AAA-200-E-045'
RULES = frozenset((PATH_RULE, ZONE_RULE))
CRITERIA = {
    PATH_RULE: (
        'pre_d_original_geojson_and_path_class_contract_sha_pinned',
        'all_original_path_features_have_unique_ids_valid_nonzero_geometry_and_explicit_class',
        'measured_main_path_network_connected_and_every_secondary_joins_main',
    ),
    ZONE_RULE: (
        'pre_d_access_zone_and_player_actor_policy_sha_pinned',
        'original_access_and_exclusion_polygons_nonzero_and_actor_labels_valid',
        'actual_original_access_exclusion_polygon_interiors_do_not_overlap',
    ),
}
EPS = 1e-8

class OriginalPathReviewBlocked(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise OriginalPathReviewBlocked(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def point(v):
    return (type(v) is list and len(v) == 2 and
            all(type(c) in (int, float) and math.isfinite(c) for c in v))

def cross(a, b, c):
    return ((b[0]-a[0])*(c[1]-a[1]) -
            (b[1]-a[1])*(c[0]-a[0]))

def on_segment(a, b, p):
    return (abs(cross(a,b,p)) <= EPS and
            min(a[0],b[0])-EPS <= p[0] <= max(a[0],b[0])+EPS and
            min(a[1],b[1])-EPS <= p[1] <= max(a[1],b[1])+EPS)

def intersect(a,b,c,d):
    ab1,ab2 = cross(a,b,c),cross(a,b,d)
    cd1,cd2 = cross(c,d,a),cross(c,d,b)
    if ((ab1 > EPS and ab2 < -EPS or ab1 < -EPS and ab2 > EPS) and
        (cd1 > EPS and cd2 < -EPS or cd1 < -EPS and cd2 > EPS)):
        return True
    return any((abs(v) <= EPS and on_segment(*edge, p))
               for v,edge,p in ((ab1,(a,b),c),(ab2,(a,b),d),
                                (cd1,(c,d),a),(cd2,(c,d),b)))

def segments(points):
    return list(zip(points,points[1:]))

def length(points):
    return sum(math.hypot(b[0]-a[0],b[1]-a[1])
               for a,b in segments(points))

def intersects_polyline(a,b):
    return any(intersect(*s,*t) for s in segments(a) for t in segments(b))

def polygon(poly):
    if (type(poly) is not list or not 3 <= len(poly) <= 128 or
            not all(point(p) for p in poly)):
        return None
    coords = poly[:-1] if poly[0] == poly[-1] else poly
    if len(coords) < 3 or len(set(tuple(p) for p in coords)) != len(coords):
        return None
    edges = segments(coords + [coords[0]])
    if any(math.hypot(b[0]-a[0],b[1]-a[1]) <= EPS for a,b in edges):
        return None
    area = sum(a[0]*b[1]-a[1]*b[0] for a,b in edges)/2
    if abs(area) <= EPS:
        return None
    # Reject self-crossing and concave zones rather than treating AABBs
    # as proof that irregular polygon interiors do not overlap.
    for i,(a,b) in enumerate(edges):
        for j,(c,d) in enumerate(edges):
            if abs(i-j) <= 1 or {i,j} == {0,len(edges)-1}:
                continue
            if intersect(a,b,c,d):
                return None
    signs = [cross(a,b,c) for a,b,c in
             zip(coords,coords[1:]+coords[:1],coords[2:]+coords[:2])]
    if not (all(x >= -EPS for x in signs) or
            all(x <= EPS for x in signs)):
        return None
    return coords

def interiors_overlap(a,b):
    # Separating-axis theorem for two independently validated convex polygons.
    for p in (a,b):
        for x,y in segments(p+[p[0]]):
            axis = (y[1]-x[1], x[0]-y[0])
            av = [axis[0]*v[0]+axis[1]*v[1] for v in a]
            bv = [axis[0]*v[0]+axis[1]*v[1] for v in b]
            if max(av) <= min(bv)+EPS or max(bv) <= min(av)+EPS:
                return False
    return True

def inside_extent(points, footprint):
    return (type(footprint) is list and len(footprint) == 2 and
            all(type(x) in (int,float) and math.isfinite(x) and x>0
                for x in footprint) and
            all(-EPS <= p[0] <= footprint[0]+EPS and
                -EPS <= p[1] <= footprint[1]+EPS for p in points))

def inspect(source_context, rule_id):
    need(type(source_context) is dict and rule_id in RULES,
         'C07_P1_PATH_RULE_OR_CONTEXT_INVALID')
    inv = source_context['inventory']
    plan = source_context['plan']
    controller = source_context['controller']
    asset = source_context['asset']
    step = source_context['step']
    work = source_context['work']
    loader = source_context['source_loader']
    # Verify all 30 canonical literals and the current Controller operation.
    p1_inspect(inv,plan,controller,asset,step,work,source_loader=loader)
    rows,tail,state,audit_sha = _original_attempt(
        inv,plan,controller,asset,step,work)
    records = _registered_artifacts(rows,state,step,loader,work)
    found = {}
    for role,path,digest,raw in records:
        need(role not in found,'C07_P1_PATH_DUPLICATE_ORIGINAL_ROLE')
        found[role] = (path,digest,raw)
    pins = plan.get('p1_evidence_contract',{}).get('original_artifact_sha256',{})
    need(type(pins) is dict,'C07_P1_PATH_PRE_D_PIN_SCHEMA')
    def original(role):
        row = found.get(role)
        if (row is None or not row[0].lower().endswith('.json') or
                pins.get(role) != row[1] or sha(row[2]) != row[1]):
            return None
        return row[2]
    path_raw,scene_raw = original('P1_PATHS_GEOJSON'),original('P1_SCENE_CONTRACT')
    path_doc = jbytes(path_raw) if path_raw is not None else {}
    scene = jbytes(scene_raw) if scene_raw is not None else {}
    complete = bool(path_doc and scene)
    checks = {k:False for k in CRITERIA[rule_id]}
    if rule_id == PATH_RULE:
        keys = CRITERIA[rule_id]
        classes = path_doc.get('path_classes')
        features = path_doc.get('features')
        checks[keys[0]] = bool(complete and classes == ['main','secondary'])
        good = (type(features) is list and 2 <= len(features) <= 512)
        paths = []
        if good:
            for feature in features:
                if type(feature) is not dict:
                    good = False
                    break
                props = feature.get('properties')
                geo = feature.get('geometry')
                coords = geo.get('coordinates') if type(geo) is dict else None
                if (type(props) is not dict or
                        type(props.get('id')) is not str or
                        not props['id'].strip() or len(props['id'])>100 or
                        props.get('class') not in ('main','secondary') or
                        type(geo) is not dict or
                        geo.get('type') != 'LineString' or
                        type(coords) is not list or
                        not 2 <= len(coords) <= 1024 or
                        not all(point(p) for p in coords) or
                        length(coords) <= EPS or
                        not inside_extent(coords,scene.get('footprint_m'))):
                    good = False
                    break
                paths.append((props['id'],props['class'],coords))
        good = bool(good and len(paths)==len(features) and
                    len(set(x[0] for x in paths))==len(paths) and
                    {x[1] for x in paths}=={'main','secondary'})
        checks[keys[1]] = good
        if good:
            main = [x[2] for x in paths if x[1]=='main']
            secondary = [x[2] for x in paths if x[1]=='secondary']
            seen = {0}
            while True:
                added = {i for i in range(len(main)) if i not in seen and
                         any(intersects_polyline(main[i],main[j]) for j in seen)}
                if not added:
                    break
                seen.update(added)
            checks[keys[2]] = (len(seen)==len(main) and
                all(any(intersects_polyline(path, trunk) for trunk in main)
                    for path in secondary))
    else:
        keys = CRITERIA[rule_id]
        policy = scene.get('allowed_zone_classes')
        zones = path_doc.get('zones')
        checks[keys[0]] = bool(complete and
            type(policy) is list and len(policy)>0 and
            all(type(p) is str and bool(p.strip()) for p in policy) and
            len(set(policy)) == len(policy))
        good = type(zones) is list and 2 <= len(zones) <= 128
        areas = []
        if good:
            for zone in zones:
                if type(zone) is not dict:
                    good = False
                    break
                shape = polygon(zone.get('polygon'))
                actors = zone.get('allowed_actors')
                access = zone.get('access')
                if (type(zone.get('zone_id')) is not str or
                        not zone['zone_id'].strip() or
                        access not in ('ACCESSIBLE','EXCLUDED') or
                        shape is None or
                        not inside_extent(shape,scene.get('footprint_m')) or
                        type(actors) is not list or
                        (access == 'ACCESSIBLE' and
                         (not actors or not all(a in policy for a in actors))) or
                        (access == 'EXCLUDED' and actors != [])):
                    good = False
                    break
                areas.append((zone['zone_id'],access,shape))
        good = bool(good and len(areas)==len(zones) and
            len(set(x[0] for x in areas))==len(areas) and
            {x[1] for x in areas}=={'ACCESSIBLE','EXCLUDED'})
        checks[keys[1]] = good
        if good:
            checks[keys[2]] = not any(interiors_overlap(a[2],b[2])
                for i,a in enumerate(areas) for b in areas[i+1:]
                if a[1] != b[1])
    return {'rule_id':rule_id,'checks':checks,'evidence_complete':complete,
            'original_audit_sha256':audit_sha,'original_audit_tail':tail,
            'original_geojson_sha256':sha(path_raw) if path_raw else None,
            'original_scene_sha256':sha(scene_raw) if scene_raw else None,
            'attempt_id':work['attempt_id'],
            'operation_sha256':work['operation_sha256']}

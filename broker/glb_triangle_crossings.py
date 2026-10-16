"""C07 strictly proven triangle surface crossings, without artistic judgment.

Only counts strict edge/triangle piercings between distinct GLB primitive
instances. Shared-edge contacts and coplanar overlaps are not counted; a zero
count is NOT proof of zero collisions. Bounded candidate budget prevents
uncontrolled N^2 work. No asset, semantic, FiveM, or MG0 PASS.
"""
from bisect import bisect_right
import math

MAX_CANDIDATE_TESTS = 120000
MAX_EXAMPLES = 12
EPSILON = 1e-9

def sub(a,b):
    return (a[0]-b[0],a[1]-b[1],a[2]-b[2])

def dot(a,b):
    return a[0]*b[0]+a[1]*b[1]+a[2]*b[2]

def cross(a,b):
    return (a[1]*b[2]-a[2]*b[1],
            a[2]*b[0]-a[0]*b[2],
            a[0]*b[1]-a[1]*b[0])

def segment_pierces_triangle(p,q,triangle,eps=EPSILON):
    """Strict interior pierce; excludes contact at triangle edge or segment end."""
    a,b,c=triangle
    direction=sub(q,p)
    edge1=sub(b,a);edge2=sub(c,a)
    h=cross(direction,edge2)
    det=dot(edge1,h)
    if abs(det) <= eps: return False
    inverse=1.0/det
    s=sub(p,a)
    u=dot(s,h)*inverse
    if not eps < u < 1.0-eps: return False
    v=dot(direction,cross(s,edge1))*inverse
    if not eps < v and u+v < 1.0-eps: return False
    t=dot(edge2,cross(s,edge1))*inverse
    return eps < t < 1.0-eps

def strict_crossing(a,b):
    """Sufficient crossing test, intentionally NOT a complete mesh-intersection proof."""
    for edge in ((a[0],a[1]),(a[1],a[2]),(a[2],a[0])):
        if segment_pierces_triangle(*edge,b): return True
    for edge in ((b[0],b[1]),(b[1],b[2]),(b[2],b[0])):
        if segment_pierces_triangle(*edge,a): return True
    return False

def bbox(triangle):
    return (tuple(min(v[i] for v in triangle) for i in range(3)),
            tuple(max(v[i] for v in triangle) for i in range(3)))

def bbox_strict_overlap(a,b):
    return all(max(a[0][i],b[0][i])+EPSILON <
               min(a[1][i],b[1][i]) for i in range(3))

def inspect(groups, candidate_pairs, max_tests=MAX_CANDIDATE_TESTS):
    """Each group: {'key':(node,primitive), 'triangles':[(v1,v2,v3),...]}.

    Operates ONLY on candidate cross-group overlaps supplied by the scanner.
    Exhaustiveness is explicit, and even an exhaustive scan does not settle
    coplanar or touching geometry; no zero-crossings PASSES are produced.
    """
    if type(max_tests) is not int or max_tests < 1:
        raise ValueError('C07_CROSSING_BUDGET_INVALID')
    keyed = {tuple(item['key']):item['triangles'] for item in groups}
    pairs_tested=0
    strict=0
    incomplete=[]
    samples=[]
    for pair in candidate_pairs:
        left=(pair[0],pair[1]);right=(pair[2],pair[3])
        if left not in keyed or right not in keyed:
            incomplete.append({'pair':pair,'reason':'CROSSING_GROUP_MISSING'})
            continue
        A=keyed[left];B=keyed[right]
        b_order=sorted(((bbox(tri),idx,tri) for idx,tri in enumerate(B)),
                       key=lambda v:v[0][0][0])
        b_mins=[value[0][0][0] for value in b_order]
        was_cut=False
        for ai,tri_a in enumerate(A):
            bounds_a=bbox(tri_a)
            stop=bisect_right(b_mins,bounds_a[1][0]-EPSILON)
            for bounds_b,bi,tri_b in b_order[:stop]:
                if bounds_b[1][0] <= bounds_a[0][0]+EPSILON:
                    continue
                if not bbox_strict_overlap(bounds_a,bounds_b):
                    continue
                if pairs_tested == max_tests:
                    was_cut=True
                    break
                pairs_tested+=1
                if strict_crossing(tri_a,tri_b):
                    strict+=1
                    if len(samples)<MAX_EXAMPLES:
                        samples.append({'group_a':list(left),'triangle_a':ai,
                                        'group_b':list(right),'triangle_b':bi})
            if was_cut:break
        if was_cut:
            incomplete.append({'pair':pair,'reason':'CROSSING_PAIR_TEST_BUDGET_EXCEEDED'})
            break
    if not incomplete and any(
         tuple((p[0],p[1])) == tuple((p[2],p[3])) for p in candidate_pairs):
        incomplete.append({'reason':'SELF_PAIR_NOT_SUPPORTED'})
    return {'schema':'gg-c07-bounded-strict-triangle-crossings-v1',
            'strict_surface_crossing_pairs_found':strict,
            'strict_crossing_examples':samples,
            'candidate_triangle_pairs_tested':pairs_tested,
            'candidate_pair_budget':max_tests,
            'all_requested_pairs_fully_scanned':not bool(incomplete),
            'unresolved_pairs':incomplete,
            'contact_and_coplanar_cases':'NOT_COVERED',
            'missing_crossing_false_negative_possible':True,
            'defect_classification':'UNKNOWN_REQUIRES_ASSET_RULE_CONTEXT',
            'individual_mg0':'UNKNOWN',
            'advancement_authorized':False}

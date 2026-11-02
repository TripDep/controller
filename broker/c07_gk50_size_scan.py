"""Bounded exact GLB world-size variation check for rock/vegetation groups.

Distinct names are hints only: proof here is different actual world bounding
spans from mesh vertices after node transforms. Missing/budgeted scans UNKNOWN.
"""
import re
from glb_machine_qa import parse,read_accessor,matrix,multiply,xform,IDENT

POINT_BUDGET=60000
CATEGORIES={
    'rock':r'rock|boulder|stone|taihu|rocc',
    'vegetation':r'tree|bamboo|bush|shrub|leaf|grass|plant|foliage',
}

def readback(raw, technical):
    result={'rock':False,'vegetation':False}
    if technical is None or technical.get('vertices_examined',0)>POINT_BUDGET:
        return result
    g,binary=parse(raw)
    meshes=g.get('meshes',[]);nodes=g.get('nodes',[])
    buckets={k:[] for k in CATEGORIES}
    scanned=0
    def visit(i, parent):
        nonlocal scanned
        node=nodes[i];world=multiply(parent,matrix(node))
        if 'mesh' in node:
            mesh=meshes[node['mesh']]
            name=str(node.get('name',''))+' '+str(mesh.get('name',''))
            matches=[k for k,p in CATEGORIES.items() if re.search(p,name,re.I)]
            if matches:
                for prim in mesh.get('primitives',[]):
                    aid=prim.get('attributes',{}).get('POSITION')
                    if aid is None:continue
                    coords=read_accessor(g,binary,aid,'VEC3',(5126,))
                    scanned+=len(coords)
                    if scanned>POINT_BUDGET:raise ValueError('GK50_WORLD_VARIATION_POINT_BUDGET')
                    points=[xform(world,v) for v in coords]
                    if not points:continue
                    size=tuple(round(max(v[k] for v in points)-
                                     min(v[k] for v in points),5)
                               for k in range(3))
                    for key in matches:buckets[key].append(size)
        for child in node.get('children',[]):visit(child,world)
    try:
        for root in g['scenes'][g.get('scene',0)].get('nodes',[]):
            visit(root,IDENT)
    except (ValueError,OverflowError,RecursionError):
        return result
    return {key:len(set(entries))>=2 for key,entries in buckets.items()}

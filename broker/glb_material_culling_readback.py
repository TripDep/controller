"""C07 exact-byte glTF material, normal and single-sided culling diagnostics.

This scanner does NOT render, evaluate artistic quality or approve geometry.
Every observation comes from an exact SHA256-verified source GLB. Absent NORMAL
is not a failure (renderer computes flat normals); mirrored world transforms
are review flags, NOT automatic malformed-geometry conclusions.
"""
from collections import Counter
import hashlib
import json
import math
import re

from glb_machine_qa import parse, matrix, multiply, IDENT, GLBError

HEX64=re.compile(r'[a-f0-9]{64}\Z')


def check(value, reason):
    if not value:
        raise GLBError('C07_CULLING_'+reason)


def scan(raw, expected_sha256):
    check(type(raw) is bytes and len(raw) <= 250_000_000, 'SOURCE_BYTES')
    check(type(expected_sha256) is str and HEX64.fullmatch(expected_sha256)
          and hashlib.sha256(raw).hexdigest() == expected_sha256,
          'IMMUTABLE_SOURCE_SHA')
    gltf,_=parse(raw)
    materials=gltf.get('materials',[])
    meshes=gltf.get('meshes',[])
    nodes=gltf.get('nodes',[])
    scenes=gltf.get('scenes',[])
    check(type(materials) is list and type(meshes) is list and
          type(nodes) is list and type(scenes) is list,'SCENE_STRUCTURE')
    check(len(materials) <= 100000 and len(meshes) <= 100000 and
          len(nodes) <= 200000, 'STRUCTURE_LIMIT')
    scene_id=gltf.get('scene',0)
    check(type(scene_id) is int and 0<=scene_id<len(scenes),'ACTIVE_SCENE')
    all_primitives=0
    normals=0
    tangents=0
    single_sided=0
    no_explicit_normals_single_sided=0
    default_material=0
    missing_uv_for_textured=0
    alpha_modes=Counter()
    material_types=Counter()
    possible_mirrored=[]
    seen=set()
    stack=set()
    max_visit=300000

    def visit(node_id,parent):
        nonlocal all_primitives,normals,tangents,single_sided
        nonlocal no_explicit_normals_single_sided,default_material
        nonlocal missing_uv_for_textured
        check(type(node_id) is int and 0<=node_id<len(nodes),'NODE_INDEX')
        check(node_id not in stack,'NODE_CYCLE')
        check(node_id not in seen,'MULTIPLY_PARENTED_NODE_UNSUPPORTED')
        seen.add(node_id);stack.add(node_id)
        check(len(seen)<=max_visit,'NODE_VISIT_LIMIT')
        node=nodes[node_id]
        world=multiply(parent,matrix(node))
        a,b,c=world[0:3],world[4:7],world[8:11]
        det=(a[0]*(b[1]*c[2]-b[2]*c[1])-
             a[1]*(b[0]*c[2]-b[2]*c[0])+
             a[2]*(b[0]*c[1]-b[1]*c[0]))
        check(math.isfinite(det) and abs(det)>1e-12,'SINGULAR_OR_NONFINITE_TRANSFORM')
        if 'mesh' in node:
            mid=node['mesh']
            check(type(mid) is int and 0<=mid<len(meshes),'MESH_REF')
            if det<0:
                possible_mirrored.append({
                   'node_id':node_id,'mesh_index':mid,
                   'mesh_name':str(meshes[mid].get('name',''))[:140]})
            for p in meshes[mid].get('primitives',[]):
                all_primitives+=1
                check(all_primitives<=1200000,'PRIMITIVE_LIMIT')
                attrs=p.get('attributes',{})
                check(type(attrs) is dict,'ATTRIBUTES_SCHEMA')
                explicit_normal='NORMAL' in attrs
                normals+=int(explicit_normal)
                tangents+=int('TANGENT' in attrs)
                if 'material' not in p:
                    default_material+=1
                    material={}
                else:
                    matid=p['material']
                    check(type(matid) is int and 0<=matid<len(materials),'MATERIAL_REF')
                    material=materials[matid]
                doublesided=material.get('doubleSided',False)
                check(type(doublesided) is bool,'DOUBLE_SIDED_TYPE')
                alpha=material.get('alphaMode','OPAQUE')
                check(alpha in ('OPAQUE','MASK','BLEND'),'ALPHA_MODE')
                alpha_modes[alpha]+=1
                material_types['doubleSided' if doublesided else 'singleSided']+=1
                if not doublesided:
                    single_sided+=1
                    no_explicit_normals_single_sided+=int(not explicit_normal)
                pbr=material.get('pbrMetallicRoughness',{})
                textures=[
                    pbr.get('baseColorTexture'),pbr.get('metallicRoughnessTexture'),
                    material.get('normalTexture'),material.get('occlusionTexture'),
                    material.get('emissiveTexture')]
                for texture in textures:
                    if texture:
                        uv='TEXCOORD_'+str(texture.get('texCoord',0))
                        if uv not in attrs:
                            missing_uv_for_textured+=1
        for child in node.get('children',[]):
            visit(child,world)
        stack.remove(node_id)

    for nid in scenes[scene_id].get('nodes',[]):
        visit(nid,IDENT)
    check(all_primitives>0,'NO_RENDERABLE_PRIMITIVES')
    mirrored=sorted(possible_mirrored,key=lambda x:(x['node_id'],x['mesh_index']))
    mirrored_json=json.dumps(mirrored,sort_keys=True,separators=(',',':')).encode()
    return {
        'schema':'gg-c07-glb-material-culling-metadata-v1',
        'source_sha256':expected_sha256,
        'nodes_seen':len(seen),'primitive_instances_examined':all_primitives,
        'materials_catalog_count':len(materials),
        'explicit_NORMAL_primitive_count':normals,
        'explicit_TANGENT_primitive_count':tangents,
        'single_sided_primitive_count':single_sided,
        'single_sided_without_explicit_NORMAL_count':no_explicit_normals_single_sided,
        'default_material_primitive_count':default_material,
        'missing_required_texcoord_attributes_count':missing_uv_for_textured,
        'alpha_modes':dict(sorted(alpha_modes.items())),
        'material_side_modes':dict(sorted(material_types.items())),
        'negative_world_determinant_nodes_count':len(mirrored),
        'negative_world_determinant_nodes_first_20':mirrored[:20],
        'negative_world_determinant_nodes_sha256':
            hashlib.sha256(mirrored_json).hexdigest(),
        'flat_normals_recomputed_by_renderer_when_missing':True,
        'single_sided_means_backface_culling_possible':single_sided>0,
        'actual_face_visibility':'UNKNOWN_NO_RENDER',
        'material_pbr_visual_qa':'UNKNOWN',
        'fivem_runtime':'UNKNOWN','blender_reimport':'UNKNOWN',
        'individual_mg0':'UNKNOWN','asset_acceptance':'NOT_AUTHORIZED',
        'advancement_authorized':False,
    }

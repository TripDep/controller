"""C07 material sidedness and vertex-normal readback adversarial regression."""
import hashlib
import json
import struct
import unittest

from glb_machine_qa import GLBError
from glb_material_culling_readback import scan
from test_glb_machine_qa import synthetic_glb


def changed(raw, modify):
    n, typ=struct.unpack_from('<I4s',raw,12)
    assert typ==b'JSON'
    doc=json.loads(raw[20:20+n].decode('utf-8'))
    modify(doc)
    enc=json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
    enc+=b' '*(-len(enc)%4)
    binary=raw[20+n:]
    return struct.pack('<4sII',b'glTF',2,20+len(enc)+len(binary))+struct.pack(
        '<I4s',len(enc),b'JSON')+enc+binary


def probe(raw):
    return scan(raw,hashlib.sha256(raw).hexdigest())


class MaterialSourceTests(unittest.TestCase):
    def test_missing_vertex_normal_is_documented_not_defect_or_pass(self):
        r=probe(synthetic_glb())
        self.assertEqual(r['primitive_instances_examined'],1)
        self.assertEqual(r['explicit_NORMAL_primitive_count'],0)
        self.assertEqual(r['single_sided_without_explicit_NORMAL_count'],1)
        self.assertEqual(r['single_sided_primitive_count'],1)
        self.assertEqual(r['negative_world_determinant_nodes_count'],0)
        self.assertEqual(r['actual_face_visibility'],'UNKNOWN_NO_RENDER')
        self.assertEqual(r['individual_mg0'],'UNKNOWN')
        self.assertFalse(r['advancement_authorized'])

    def test_single_sided_material_remains_detectable(self):
        raw=changed(synthetic_glb(),lambda d:(
            d.update(materials=[{'name':'fixture','doubleSided':False,
                                 'alphaMode':'OPAQUE'}]),
            d['meshes'][0]['primitives'][0].update(material=0)))
        r=probe(raw)
        self.assertEqual(r['single_sided_primitive_count'],1)
        self.assertEqual(r['material_side_modes'],{'singleSided':1})
        self.assertEqual(r['alpha_modes'],{'OPAQUE':1})

    def test_explicit_double_sided_does_not_claim_runtime_verified(self):
        raw=changed(synthetic_glb(),lambda d:(
            d.update(materials=[{'doubleSided':True,'alphaMode':'BLEND'}]),
            d['meshes'][0]['primitives'][0].update(material=0)))
        r=probe(raw)
        self.assertEqual(r['single_sided_primitive_count'],0)
        self.assertEqual(r['alpha_modes'],{'BLEND':1})
        self.assertEqual(r['actual_face_visibility'],'UNKNOWN_NO_RENDER')
        self.assertEqual(r['material_pbr_visual_qa'],'UNKNOWN')

    def test_negative_scene_transform_is_flagged_without_fake_fail(self):
        raw=changed(synthetic_glb(),lambda d:
                    d['nodes'][0].update(scale=[-1,1,1]))
        r=probe(raw)
        self.assertEqual(r['negative_world_determinant_nodes_count'],1)
        self.assertEqual(r['negative_world_determinant_nodes_first_20'][0]['mesh_index'],0)
        self.assertFalse(r['advancement_authorized'])

    def test_texture_without_uv_produces_negative_machine_observation(self):
        def modified(d):
            d['materials']=[{'pbrMetallicRoughness':{
              'baseColorTexture':{'index':0}}}]
            d['meshes'][0]['primitives'][0]['material']=0
        r=probe(changed(synthetic_glb(),modified))
        self.assertEqual(r['missing_required_texcoord_attributes_count'],1)

    def test_verified_glb_bytes_required_prevents_replayed_report(self):
        raw=synthetic_glb()
        with self.assertRaisesRegex(GLBError,'IMMUTABLE_SOURCE_SHA'):
            scan(raw,'0'*64)

    def test_node_cycles_denied(self):
        raw=changed(synthetic_glb(),lambda d:
                    d['nodes'][0].update(children=[0]))
        with self.assertRaisesRegex(GLBError,'NODE_CYCLE'):
            probe(raw)


if __name__ == '__main__':
    unittest.main()

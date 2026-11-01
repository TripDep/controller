"""M123 source-specific original PBR normal and roughness texture adversarial tests."""
import copy
import json
import struct
import unittest

from test_c07_native_source_rule_replayers import NativeOriginalReplayerTests
from test_c07_p345_forty_native_evidence import P345Forty, encoded
from test_c07_p3_uv_semantics import uv_glb
from test_c07_p5_budget_semantics import with_embedded_texture
from test_c07_p4_texture_semantics import png
from c07_p4_pbr_maps_full_review import RULE, inspect
from c07_native_source_rule_replayers import (
    NATIVE_RULES, FULL_LITERAL_REVIEWED, VALIDATORS, build_packet,
    native_rule_readback, NativeRuleEvidenceBlocked)
from c07_native_replayer_dispatch import replay
from supervisor_judgment import binding, semantic_packet

def maps():
    normal=png([[(128,128,255,255)]*4 for _ in range(4)])
    rough=png([[(0,40+20*x+10*y,0,255) for x in range(4)]
               for y in range(4)])
    return normal,rough

def two_maps(*,normal_enabled=True,roughness=None):
    normal,rough=maps()
    if roughness is not None:
        rough=roughness
    raw=with_embedded_texture(uv_glb(with_texture=False),normal)
    size=struct.unpack_from('<I',raw,12)[0]
    doc=json.loads(raw[20:20+size])
    data=bytearray(raw[28+size:])
    offset=len(data)
    data.extend(rough)
    data.extend(bytes(-len(data)%4))
    doc['bufferViews'].append({'buffer':0,'byteOffset':offset,
                               'byteLength':len(rough)})
    doc['images'].append({'bufferView':len(doc['bufferViews'])-1,
                          'mimeType':'image/png'})
    doc['textures'].append({'source':1})
    mat=doc['materials'][0]
    if normal_enabled:
        mat['normalTexture']={'index':0}
    mat['pbrMetallicRoughness']['metallicRoughnessTexture']={'index':1}
    doc['buffers'][0]['byteLength']=len(data)
    js=json.dumps(doc,separators=(',',':')).encode()
    js+=bytes([32])*(-len(js)%4)
    return (struct.pack('<4sII',b'glTF',2,28+len(js)+len(data))+
            struct.pack('<I4s',len(js),b'JSON')+js+
            struct.pack('<I4s',len(data),bytes((66,73,78,0)))+bytes(data))

POLICY={'shader_family':'glTF2_PBR','target_phase':'P4_GLTF_PREVIEW',
        'supported_texture_channels':['normal','metallicRoughness'],
        'texcoord_set':0}

class PBRMapFullReviewTests(unittest.TestCase):
    def context(self):
        test,ctx=NativeOriginalReplayerTests.context(
            self,P345Forty,'test_p4_30_due_and_p5_40_due')
        test.f.plan['phase']=test.f.work['phase']='P4'
        test.add('NATIVE_EXPORT','scene.glb',two_maps())
        test.add('P4_SHADER_CAPABILITIES','p4_shader_capabilities.json',
                 encoded(POLICY))
        test.sync()
        ctx['controller']=test.f.controller
        return test,ctx

    def packet(self,ctx):
        expected=binding(ctx['work'],ctx['inventory']['rules'][RULE],RULE)
        packet=build_packet(ctx,RULE,expected=expected)
        spec={'validator_id':VALIDATORS[RULE],
              'criteria':list(NATIVE_RULES[RULE][1]),
              'requirement_sha256':expected['requirement_sha256'],
              'source_ref':'1'*40,
              'issuer':{'workflow_blob':'a'*40,'public_sha':'b'*40}}
        return packet,expected,spec

    def test_two_real_original_embedded_maps_positive_unknown_mg0(self):
        _,ctx=self.context()
        packet,expected,spec=self.packet(ctx)
        self.assertIn(RULE,FULL_LITERAL_REVIEWED)
        self.assertEqual(packet['rule']['result'],'PASS')
        self.assertTrue(all(packet['rule']['checks'].values()))
        self.assertEqual(packet['mg0']['result'],'UNKNOWN')
        self.assertEqual(replay(None,packet,expected,spec,
            source_context=lambda _:ctx)['documentary_result'],'PASS')
        self.assertEqual(semantic_packet(packet,expected,spec)['result'],'UNKNOWN')

    def test_missing_normal_binding_fails_original_material(self):
        test,ctx=self.context()
        test.add('NATIVE_EXPORT','scene.glb',two_maps(normal_enabled=False))
        test.sync()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[RULE][1][1]])

    def test_flat_original_roughness_pixels_fail(self):
        test,ctx=self.context()
        flat=png([[(0,80,0,255)]*4 for _ in range(4)])
        test.add('NATIVE_EXPORT','scene.glb',two_maps(roughness=flat))
        test.sync()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx)
        self.assertEqual(packet['rule']['result'],'FAIL')
        self.assertFalse(packet['rule']['checks'][NATIVE_RULES[RULE][1][2]])

    def test_unsupported_shader_profile_not_promoted(self):
        test,ctx=self.context()
        test.add('P4_SHADER_CAPABILITIES','p4_shader_capabilities.json',
                 encoded(dict(POLICY,shader_family='UNKNOWN_RAGE')))
        test.sync()
        ctx['controller']=test.f.controller
        packet,_,_=self.packet(ctx)
        self.assertNotEqual(packet['rule']['result'],'PASS')

    def test_unpinned_native_bytes_and_producer_packet_fail(self):
        test,ctx=self.context()
        packet,expected,spec=self.packet(ctx)
        forged=copy.deepcopy(packet)
        forged['rule']['proof_digest']='f'*64
        with self.assertRaisesRegex(NativeRuleEvidenceBlocked,
                                    'PRODUCER_PACKET_NOT_RECOMPUTED'):
            native_rule_readback(None,forged,expected,spec,
                                 source_context=lambda _:ctx)
        (test.f.root/'scene.glb').write_bytes(b'bad')
        with self.assertRaises(ValueError):
            inspect(ctx,RULE)

if __name__=='__main__':
    unittest.main()

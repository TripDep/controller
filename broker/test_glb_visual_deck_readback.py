"""Adversarial C07 eight-view deck integrity tests; fixtures are not model QA."""
import hashlib
import json
import tempfile
import unittest
import zlib
from pathlib import Path
from glb_visual_deck_readback import readback, VisualDeckBlocked, VIEWS, MODES, SCHEMA
from test_glb_machine_qa import synthetic_glb
from test_glb_pbr_evidence import png_chunk

WORK={'asset_id':'TEST','attempt_id':'a'*64,
      'operation_sha256':'b'*64,'master_sha256':'c'*64,'phase':'P8'}

def sha(x):return hashlib.sha256(x).hexdigest()

def png(seed):
    width,height=480,360
    # Different but valid nonempty, exact-sized 8-bit RGB png images.
    rgb=bytes([seed%256,(seed*11)%256,(seed*19)%256])*width
    raw=b''.join(b'\0'+rgb for _ in range(height))
    return (b'\x89PNG\r\n\x1a\n'
        +png_chunk(b'IHDR',__import__('struct').pack('>IIBBBBB',
                   width,height,8,2,0,0,0))
        +png_chunk(b'IDAT',zlib.compress(raw))
        +png_chunk(b'IEND',b''))

class DeckTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.d=Path(t.name)
        self.glb=self.d/'reference.glb'
        self.glb.write_bytes(synthetic_glb())
        self.source_sha=sha(self.glb.read_bytes())
        rows=[];self.pngs={}
        for i,v in enumerate(VIEWS):
            for j,mode in enumerate(MODES):
                name=v+'__'+mode+'.png'
                content=png(i*2+j+1)
                path=self.d/name;path.write_bytes(content)
                self.pngs[name]=path
                direction=[(i+1)/10, (i+2)/20, (i+3)/30]
                length=sum(x*x for x in direction)**.5
                direction=[round(x/length,8) for x in direction]
                rows.append({'view':v,'mode':mode,'filename':name,
                    'sha256':sha(content),'size_bytes':len(content),
                    'object_to_camera_direction':direction,'parallel_scale':7.25})
        sheet=self.d/'YOULANJU_C07_8_ANGLE_SOURCE_VS_RGB_NEUTRAL_CONTACT_SHEET.png'
        sheet.write_bytes(png(97))
        self.manifest={'schema':SCHEMA,
            'source_sha256':self.source_sha,
            'source_size_bytes':self.glb.stat().st_size,
            'source_asset':self.glb.name,'work_binding':dict(WORK),
            'renderer':'VTK glTF importer fixture',
            'camera_pairs':8,'actor_count':8,'no_semantic_pass':True,
            'asset_acceptance':'NOT_AUTHORIZED','individual_mg0':'UNKNOWN',
            'image_width':480,'image_height':360,
            'images':rows,'sheet_sha256':sha(sheet.read_bytes()),
            'contact_sheet_filename':sheet.name}
        self.path=self.d/'deck.json'
        self.write()
    def write(self):
        self.path.write_text(json.dumps(self.manifest))
        return sha(self.path.read_bytes())
    def check(self, sha_manifest=None, work=WORK):
        return readback(self.glb,self.path,self.source_sha,
                        sha_manifest or sha(self.path.read_bytes()),work)
    def test_authentic_file_integrity_does_not_grant_visual_pass(self):
        v=self.check()
        self.assertEqual(v['verified_pngs'],16)
        self.assertEqual(v['paired_unique_angles'],8)
        self.assertEqual(v['model_render_content_authenticity'],
                         'NOT_PROVEN_BY_HASHES')
        # A solid-color synthetic PNG has no visible geometry: fail closed
        # rather than pretending all eight views were visually measurable.
        self.assertEqual(v['pixel_content_analysis']['measured_views'],0)
        self.assertEqual(len(v['pixel_content_analysis']['unverified_views']),8)
        self.assertEqual(v['pixel_content_analysis']['semantic_verdict'],'UNKNOWN')
        self.assertEqual(v['pixel_content_analysis']['individual_mg0'],'UNKNOWN')
        self.assertTrue(v['visual_review_hold'])
        self.assertEqual(v['semantic_verdict'],'UNKNOWN')
        self.assertEqual(v['individual_mg0'],'UNKNOWN')
        self.assertFalse(v['work_advancement_authorized'])
    def test_stale_deck_from_prior_attempt_cannot_be_replayed(self):
        stale={**WORK,'attempt_id':'d'*64}
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_DECK_ATTEMPT_MISMATCH'):
            self.check(work=stale)
    def test_forged_work_context_inside_signed_deck_does_not_validate(self):
        self.manifest['work_binding']['operation_sha256']='d'*64
        self.write()
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_DECK_ATTEMPT_MISMATCH'):
            self.check()

    def test_changed_glb_not_accepted_with_same_deck(self):
        self.glb.write_bytes(self.glb.read_bytes()+b'tamper')
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_SOURCE_GLB_TAMPERED'):
            self.check()
    def test_changed_manifest_sha_fails(self):
        old=sha(self.path.read_bytes())
        self.manifest['camera_pairs']=7
        self.write()
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_MANIFEST_TAMPERED'):
            self.check(sha_manifest=old)
    def test_changed_one_pixel_image_fails(self):
        p=self.pngs[VIEWS[0]+'__'+MODES[0]+'.png']
        p.write_bytes(p.read_bytes()+b'changed')
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_IMAGE_SIZE_CHANGED'):
            self.check()
    def test_image_swapped_between_views_fails(self):
        a=self.pngs[VIEWS[0]+'__'+MODES[0]+'.png']
        b=self.pngs[VIEWS[1]+'__'+MODES[0]+'.png']
        a.write_bytes(b.read_bytes())
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_IMAGE_SIZE_CHANGED|VISUAL_IMAGE_TAMPERED'):
            self.check()
    def test_missing_view_fails(self):
        self.manifest['images'].pop()
        self.write()
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_REQUIRES_ALL_16_IMAGES'):
            self.check()
    def test_camera_replay_or_changed_angle_fails(self):
        self.manifest['images'][1]['object_to_camera_direction']=[0,0,1]
        self.write()
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_BEFORE_AFTER_CAMERA_MISMATCH'):
            self.check()
    def test_invalid_camera_duplicated_fails(self):
        direction=self.manifest['images'][0]['object_to_camera_direction']
        for row in self.manifest['images'][2:4]:
            row['object_to_camera_direction']=direction
        self.write()
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_CAMERAS_REPEATED'):
            self.check()
    def test_user_writable_manifest_cannot_invent_pass(self):
        self.manifest['no_semantic_pass']=False
        self.write()
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_FORGED_VERDICT_OR_RENDERER'):
            self.check()
    def test_stale_attempt_context_rejected(self):
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_WORK_IDENTITY_UNVERIFIED'):
            self.check(work={**WORK,'attempt_id':'bad'})
    def test_image_path_traversal_denied(self):
        self.manifest['images'][0]['filename']='../../other.png'
        self.write()
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_IMAGE_FILENAME_MISMATCH'):
            self.check()
    def test_contact_sheet_path_traversal_denied(self):
        self.manifest['contact_sheet_filename']='../unexpected.png'
        self.write()
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_CONTACT_SHEET_FILENAME_INVALID'):
            self.check()
    def test_other_assets_can_use_their_own_safe_contact_sheet_filename(self):
        old=self.d/'YOULANJU_C07_8_ANGLE_SOURCE_VS_RGB_NEUTRAL_CONTACT_SHEET.png'
        newer=self.d/'TEST_C07_CONTACT_SHEET.png'
        old.rename(newer)
        self.manifest['contact_sheet_filename']=newer.name
        self.write()
        v=self.check()
        self.assertEqual(v['verified_pngs'],16)
        self.assertFalse(v['work_advancement_authorized'])
    def test_contact_sheet_cannot_be_changed_silently(self):
        p=self.d/'YOULANJU_C07_8_ANGLE_SOURCE_VS_RGB_NEUTRAL_CONTACT_SHEET.png'
        p.write_bytes(p.read_bytes()+b'change')
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_CONTACT_SHEET_TAMPERED'):
            self.check()
    def test_wrong_work_object_not_accepted(self):
        with self.assertRaisesRegex(VisualDeckBlocked,'VISUAL_WORK_BINDING_SCHEMA'):
            self.check(work={**WORK,'visual_pass':True})
if __name__=='__main__':unittest.main()

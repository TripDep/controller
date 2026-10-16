"""Adversarial Blender runner contract tests using mocked process; no bpy PASS."""
import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import blender_roundtrip_driver as q


def sh(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fake_glb():
    data=b'{"asset":{"version":"2.0"}}'
    data+=b' '*(-len(data)%4)
    return struct.pack('<4sII',b'glTF',2,12+8+len(data))+struct.pack('<I4s',len(data),b'JSON')+data

class BlenderRoundtripTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.source=self.root/'model.blend'
        self.source.write_bytes(b'BLENDER17-01v0502\nFIXTURE_NOT_REAL')
        self.binary=self.root/'blender_executable'
        self.binary.write_bytes(b'fake runner; never a trusted Blender binary')
        self.script=self.root/'script.py'
        self.script.write_text('import bpy\n')
        self.calls=[]
    def fake(self,*,code=0,report_updates=None,glb=None,missing_report=False,
             mutate_source=False):
        def run(args,timeout,cwd,env):
            self.calls.append(args)
            self.assertEqual(args[:4],[str(self.binary),'--background',
                                      '--factory-startup','--disable-autoexec'])
            self.assertIn('--python-exit-code',args)
            self.assertEqual(args[args.index('--python-exit-code')+1],'41')
            self.assertEqual(args[args.index('--source-absolute')+1],str(self.source))
            target=Path(args[args.index('--scratch-glb')+1])
            report=Path(args[args.index('--report-json')+1])
            target.write_bytes(fake_glb() if glb is None else glb)
            source_summary={'visible_mesh_objects':3,'bounds_world':[[0.,0.,0.],[1.,1.,1.]]}
            payload={'schema':q.REPORT_SCHEMA,
                     'source_name':self.source.name,'source_sha256':sh(self.source),
                     'blender_version':'5.2.2','bpy_engine':'REAL_BLENDER_BPY_HEADLESS',
                     'source_opened_in_blender':True,'export_operator_finished':True,
                     'reimport_operator_finished':True,
                     'before':source_summary,'after':source_summary,
                     'scratch_glb_sha256':sh(target),
                     'scratch_glb_size_bytes':target.stat().st_size,
                     'runtime_asset_approval':'NOT_AUTHORIZED',
                     'fiveM_runtime':'NOT_TESTED','artistic_judgment':'UNKNOWN',
                     'individual_mg0':'UNKNOWN','advancement_authorized':False}
            if report_updates:payload.update(report_updates)
            if mutate_source:self.source.write_bytes(self.source.read_bytes()+b'CHANGED')
            if not missing_report:report.write_text(json.dumps(payload))
            return (code,'controlled mocked blender process')
        return run
    def check(self,**kwargs):
        return q.inspect(self.source,sh(self.source),self.binary,self.script,**kwargs)
    def test_valid_mocked_execution_has_no_approval(self):
        with patch.object(q,'_run_and_kill',self.fake()):
            d=self.check()
        self.assertEqual(d['script_runtime_report']['source_opened_in_blender'],True)
        self.assertEqual(d['binary_identity_independently_attested'],False)
        self.assertEqual(d['production_acceptance'],'NOT_AUTHORIZED')
        self.assertEqual(d['individual_mg0'],'UNKNOWN')
        self.assertFalse(d['advancement_authorized'])
        self.assertEqual(len(self.calls),1)
    def test_missing_blender_binary_blocks(self):
        self.binary.unlink()
        with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_UNTRUSTED_FILE_PATH'):
            self.check()
    def test_untrusted_source_symlink_blocks(self):
        link=self.root/'link.blend'
        link.symlink_to(self.source)
        with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_UNTRUSTED_FILE_PATH'):
            q.inspect(link,sh(self.source),self.binary,self.script)
    def test_untrusted_script_symlink_blocks(self):
        link=self.root/'scriptlink.py';link.symlink_to(self.script)
        with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_UNTRUSTED_FILE_PATH'):
            q.inspect(self.source,sh(self.source),self.binary,link)
    def test_source_wrong_hash_blocks_pre_execution(self):
        with patch.object(q,'_run_and_kill',side_effect=AssertionError('must not run')):
            with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_ORIGINAL_FILE_CHANGED'):
                q.inspect(self.source,'0'*64,self.binary,self.script)
    def test_process_error_blocks_even_if_report_forged(self):
        with patch.object(q,'_run_and_kill',self.fake(code=41)):
            with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_PROCESS_EXIT_NONZERO'):
                self.check()
    def test_no_report_blocks(self):
        with patch.object(q,'_run_and_kill',self.fake(missing_report=True)):
            with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_REPORT_MISSING'):
                self.check()
    def test_source_mutation_after_run_blocks(self):
        with patch.object(q,'_run_and_kill',self.fake(mutate_source=True)):
            with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_ORIGINAL_FILE_MODIFIED'):
                self.check()
    def test_mg0_forgery_blocks(self):
        with patch.object(q,'_run_and_kill',self.fake(report_updates={'individual_mg0':'PASS'})):
            with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_REPORT_CONTRACT_INVALID'):
                self.check()
    def test_fake_scene_empty_blocks(self):
        with patch.object(q,'_run_and_kill',self.fake(report_updates={'after':{'visible_mesh_objects':0}})):
            with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_SCENE_REIMPORT_UNVERIFIED'):
                self.check()
    def test_glb_digest_mismatch_blocks(self):
        with patch.object(q,'_run_and_kill',self.fake(report_updates={'scratch_glb_sha256':'0'*64})):
            with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_GLTF_EXPORT_MISSING_OR_TAMPERED'):
                self.check()
    def test_malformed_glb_header_blocks_even_hashed_success(self):
        with patch.object(q,'_run_and_kill',self.fake(glb=b'NOT A BLENDER GLB FILE TRULY ')):
            with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_GLTF_BINARY_INVALID'):
                self.check()
    def test_timeout_parameter_denied(self):
        with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_INVALID_TIMEOUT'):
            self.check(timeout_seconds=0)
    def test_export_budget_denied(self):
        with self.assertRaisesRegex(q.BlenderProbeBlocked,'BLENDER_INVALID_EXPORT_BUDGET'):
            self.check(max_export_bytes=4)

if __name__=='__main__':unittest.main()
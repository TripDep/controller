"""C07 non-mutating native Blender roundtrip diagnostic; NO WORK PASS.

Uses absolute Blender executable and a trusted local helper script; stdout is
not accepted as evidence. Source bytes are rehashed after actual execution.
Any exit != 0, mismatched GLB, invalid report or no Blender => STOP/UNKNOWN.
A forged executable or self-reported bpy result cannot be a semantic attestation.
"""
import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
from pathlib import Path

MAX_SOURCE_BYTES = 1_000_000_000
MAX_GLB_BYTES = 1_000_000_000
MAX_REPORT_BYTES = 200_000
REPORT_SCHEMA = 'gg-c07-headless-blender-roundtrip-runtime-v1'

class BlenderProbeBlocked(ValueError): pass

def need(ok, msg):
    if not ok: raise BlenderProbeBlocked(msg)

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):
            h.update(block)
    return h.hexdigest()

def regular(path, suffix=None):
    p=Path(path)
    need(p.is_absolute() and p.is_file() and not p.is_symlink() and
         not any(z.is_symlink() for z in p.parents), 'BLENDER_UNTRUSTED_FILE_PATH')
    if suffix:need(p.suffix.lower()==suffix, 'BLENDER_WRONG_SOURCE_FILE_TYPE')
    return p

def _run_and_kill(args, timeout, cwd, env):
    # Spool Blender output to disk: a verbose or compromised process must not
    # fill RAM via Popen.communicate(stdout=PIPE).
    with tempfile.TemporaryFile() as output:
        p=subprocess.Popen(args, cwd=str(cwd), env=env, shell=False,
                           stdin=subprocess.DEVNULL, stdout=output,
                           stderr=subprocess.STDOUT, start_new_session=True)
        try: p.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try: os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait()
            raise BlenderProbeBlocked('BLENDER_PROCESS_TIMEOUT') from exc
        output.seek(0,os.SEEK_END)
        end=output.tell()
        output.seek(max(0,end-20000))
        last=output.read().decode('utf-8','replace')
    return p.returncode, last

def inspect(source, source_sha, blender_binary, script_path=None, timeout_seconds=1800,
            max_export_bytes=MAX_GLB_BYTES):
    source=regular(source,'.blend')
    binary=regular(blender_binary)
    script=regular(script_path or Path(__file__).with_name('blender_headless_scene_probe.py'),'.py')
    need(type(source_sha) is str and re.fullmatch('[0-9a-f]{64}',source_sha),
         'BLENDER_PIN_MISSING')
    need(source.stat().st_size<=MAX_SOURCE_BYTES and sha(source)==source_sha,
         'BLENDER_ORIGINAL_FILE_CHANGED')
    need(type(timeout_seconds) is int and 1<=timeout_seconds<=3600,
         'BLENDER_INVALID_TIMEOUT')
    need(type(max_export_bytes) is int and 20<max_export_bytes<=MAX_GLB_BYTES,
         'BLENDER_INVALID_EXPORT_BUDGET')
    binary_sha=sha(binary); script_sha=sha(script)
    with tempfile.TemporaryDirectory(prefix='c07_blender_diag_') as tmp:
        temp=Path(tmp)
        export=temp/'roundtrip.glb';report=temp/'bpy_report.json'
        env=dict(os.environ)
        env.update({'BLENDER_USER_CONFIG':str(temp/'blender_user_config'),
                    'BLENDER_USER_SCRIPTS':str(temp/'blender_user_scripts'),
                    'PYTHONNOUSERSITE':'1'})
        cmd=[str(binary),'--background','--factory-startup','--disable-autoexec',
             str(source),'--python-exit-code','41','--python',str(script),
             '--','--report-json',str(report),'--scratch-glb',str(export),
             '--source-absolute',str(source),'--expected-source-sha256',source_sha]
        code, log_tail=_run_and_kill(cmd,timeout_seconds,temp,env)
        need(code==0,'BLENDER_PROCESS_EXIT_NONZERO:'+str(code)+':'+log_tail[-250:])
        need(report.is_file() and not report.is_symlink() and
             report.stat().st_size<=MAX_REPORT_BYTES,
             'BLENDER_REPORT_MISSING_OR_OVERSIZED')
        try: data=json.loads(report.read_bytes())
        except (ValueError,UnicodeError) as exc:
            raise BlenderProbeBlocked('BLENDER_REPORT_INVALID_JSON') from exc
        need(type(data) is dict and data.get('schema')==REPORT_SCHEMA and
             data.get('source_sha256')==source_sha and data.get('source_name')==source.name and
             data.get('source_opened_in_blender') is True and
             data.get('export_operator_finished') is True and
             data.get('reimport_operator_finished') is True and
             data.get('bpy_engine')=='REAL_BLENDER_BPY_HEADLESS' and
             data.get('runtime_asset_approval')=='NOT_AUTHORIZED' and
             data.get('fiveM_runtime')=='NOT_TESTED' and
             data.get('artistic_judgment')=='UNKNOWN' and
             data.get('individual_mg0')=='UNKNOWN' and
             data.get('advancement_authorized') is False,
             'BLENDER_REPORT_CONTRACT_INVALID')
        need(type(data.get('before')) is dict and type(data.get('after')) is dict
             and data['before'].get('visible_mesh_objects',0)>0
             and data['after'].get('visible_mesh_objects',0)>0 and
             type(data.get('blender_version')) is str and data['blender_version'].strip(),
             'BLENDER_SCENE_REIMPORT_UNVERIFIED')
        need(export.is_file() and not export.is_symlink() and
             20<export.stat().st_size<=max_export_bytes and
             data.get('scratch_glb_size_bytes')==export.stat().st_size and
             data.get('scratch_glb_sha256')==sha(export),
             'BLENDER_GLTF_EXPORT_MISSING_OR_TAMPERED')
        with open(export,'rb') as f:
            header=f.read(12)
        need(header[:4]==b'glTF' and int.from_bytes(header[4:8],'little')==2 and
             int.from_bytes(header[8:12],'little')==export.stat().st_size,
             'BLENDER_GLTF_BINARY_INVALID')
        need(sha(source)==source_sha,'BLENDER_ORIGINAL_FILE_MODIFIED')
        return {'schema':'gg-c07-blender-invocation-evidence-v1',
                'source_sha256':source_sha,'blender_binary_sha256':binary_sha,
                'bpy_script_sha256':script_sha,
                'script_runtime_report':data,
                'subprocess_exit_code':code,
                'binary_identity_independently_attested':False,
                'runtime_diagnostic_executed':True,
                'artistic_quality':'UNKNOWN',
                'fiveM_runtime':'NOT_TESTED','individual_mg0':'UNKNOWN',
                'production_acceptance':'NOT_AUTHORIZED',
                'advancement_authorized':False,
                'note':'Process/byte-level diagnostics only, not trusted semantic approval.'}
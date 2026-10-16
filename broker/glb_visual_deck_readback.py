"""C07 source-bound 8-angle visual deck readback, without visual/artist PASS.

Checks immutable source GLB, 16 PNG hashes/CRCs/dimensions, matched cameras,
coverage and manifest integrity. Contents can still be forged; independent
visual quality, renderer authenticity and FiveM fidelity remain UNKNOWN.
"""
import hashlib
import json
import math
import re
from pathlib import Path
from glb_pbr_evidence import validate_png_chunks, MaterialEvidenceError
from visual_content_metrics import inspect_bytes as inspect_visual_content

SCHEMA='gg-c07-vtk-eight-angle-source-bound-diagnostic-v1'
VIEWS=('front','front_right','right','rear_right','rear','left','roof','entry_close')
MODES=('SOURCE_RGB_OPAQUE','NEUTRAL_RGB_DIAGNOSTIC')
H64=re.compile('[a-f0-9]{64}\\Z')

class VisualDeckBlocked(ValueError): pass

def need(ok,why):
    if not ok:raise VisualDeckBlocked(why)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def readback(source,manifest_path,source_sha,manifest_sha,work):
    need(type(work) is dict and set(work)=={'asset_id','attempt_id',
         'operation_sha256','master_sha256','phase'},
         'VISUAL_WORK_BINDING_SCHEMA')
    need(type(work['asset_id']) is str and bool(work['asset_id'])
         and type(work['phase']) is str and bool(work['phase'])
         and all(type(work[k]) is str and H64.fullmatch(work[k])
             for k in ('attempt_id','operation_sha256','master_sha256')),
         'VISUAL_WORK_IDENTITY_UNVERIFIED')
    need(all(type(x) is str and H64.fullmatch(x) for x in (source_sha,manifest_sha)),
         'VISUAL_IMMUTABLE_SHA_REQUIRED')
    source=Path(source);manifest_path=Path(manifest_path)
    for path in (source,manifest_path):
        need(path.is_absolute() and path.is_file() and not path.is_symlink()
             and not any(p.is_symlink() for p in path.parents),
             'VISUAL_SOURCE_PATH_UNTRUSTED')
    need(source.suffix.lower()=='.glb' and manifest_path.suffix.lower()=='.json'
         and source.stat().st_size<=250_000_000
         and manifest_path.stat().st_size<=200_000,
         'VISUAL_FILE_TYPE_OR_SIZE_INVALID')
    need(digest(source.read_bytes())==source_sha,'VISUAL_SOURCE_GLB_TAMPERED')
    raw=manifest_path.read_bytes()
    need(digest(raw)==manifest_sha,'VISUAL_MANIFEST_TAMPERED')
    try: m=json.loads(raw)
    except (ValueError,UnicodeError) as exc:
        raise VisualDeckBlocked('VISUAL_BAD_MANIFEST_JSON') from exc
    need(type(m) is dict and m.get('schema')==SCHEMA,
         'VISUAL_MANIFEST_SCHEMA_INVALID')
    need(m.get('source_sha256')==source_sha
         and m.get('source_size_bytes')==source.stat().st_size
         and m.get('source_asset')==source.name,
         'VISUAL_DECK_WRONG_SOURCE')
    # A recycled image deck for the same unchanged GLB is not proof of a
    # new Controller attempt. Offline legacy decks lacking this binding
    # remain review-only and cannot be presented as current work evidence.
    need(m.get('work_binding')==work,'VISUAL_DECK_ATTEMPT_MISMATCH')
    need(type(m.get('renderer')) is str and
         m['renderer'].startswith('VTK glTF importer ') and
         m.get('camera_pairs')==8 and type(m.get('actor_count')) is int
         and m['actor_count']>0 and
         m.get('no_semantic_pass') is True and
         m.get('asset_acceptance')=='NOT_AUTHORIZED'
         and m.get('individual_mg0')=='UNKNOWN',
         'VISUAL_FORGED_VERDICT_OR_RENDERER')
    width=m.get('image_width');height=m.get('image_height')
    need(type(width) is int and type(height) is int
         and 400<=width<=4096 and 300<=height<=4096,
         'VISUAL_IMAGE_DIMENSIONS_INVALID')
    rows=m.get('images')
    need(type(rows) is list and len(rows)==16,
         'VISUAL_REQUIRES_ALL_16_IMAGES')
    used=set();digests=set();pairs={};image_bytes={}
    root=manifest_path.parent
    for row in rows:
        need(type(row) is dict and row.get('view') in VIEWS
             and row.get('mode') in MODES,'VISUAL_IMAGE_ROLE_INVALID')
        key=(row['view'],row['mode'])
        need(key not in used,'VISUAL_DUPLICATE_VIEW')
        used.add(key)
        name=row['view']+'__'+row['mode']+'.png'
        need(row.get('filename')==name,'VISUAL_IMAGE_FILENAME_MISMATCH')
        path=root/name
        need(path.is_file() and not path.is_symlink(),'VISUAL_IMAGE_MISSING')
        size=row.get('size_bytes')
        need(type(size) is int and 70<=size<=16_000_000
             and path.stat().st_size==size,
             'VISUAL_IMAGE_SIZE_CHANGED')
        image=path.read_bytes();hashval=digest(image)
        need(hashval==row.get('sha256'),'VISUAL_IMAGE_TAMPERED')
        need(hashval not in digests,'VISUAL_IDENTICAL_PNG_REPLAY')
        digests.add(hashval)
        image_bytes[key]=image
        try:dims=validate_png_chunks(image)
        except (MaterialEvidenceError,TypeError,ValueError) as exc:
            raise VisualDeckBlocked('VISUAL_PNG_INVALID') from exc
        need(dims==(width,height),'VISUAL_PNG_DIMENSION_MISMATCH')
        direction=row.get('object_to_camera_direction')
        scale=row.get('parallel_scale')
        need(type(direction) is list and len(direction)==3
             and all(type(v) in (int,float) and math.isfinite(v)
                     for v in direction)
             and .999<sum(v*v for v in direction)<1.001
             and type(scale) in (int,float) and math.isfinite(scale)
             and scale>0,'VISUAL_CAMERA_INVALID')
        pairs.setdefault(row['view'],[]).append(row)
    need(len(used)==16 and len(pairs)==8 and
         all(len(pairs[v])==2 for v in VIEWS),'VISUAL_ANGLES_MISSING')
    for name,group in pairs.items():
        a,b=group
        need(a['object_to_camera_direction']==b['object_to_camera_direction']
             and a['parallel_scale']==b['parallel_scale'],
             'VISUAL_BEFORE_AFTER_CAMERA_MISMATCH')
    need(len(set(tuple(pairs[v][0]['object_to_camera_direction'])
                 for v in VIEWS))==8,'VISUAL_CAMERAS_REPEATED')
    # Contact sheet is asset-specific and must never be a hard-coded
    # Youlanju-only filename or a caller-provided absolute/traversal path.
    sheet_name=m.get('contact_sheet_filename')
    need(type(sheet_name) is str and 1<=len(sheet_name)<=128
         and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.png',sheet_name)
         and '..' not in sheet_name,
         'VISUAL_CONTACT_SHEET_FILENAME_INVALID')
    sheet=root/sheet_name
    need(sheet.is_file() and not sheet.is_symlink()
         and sheet.resolve().parent==root.resolve()
         and digest(sheet.read_bytes())==m.get('sheet_sha256'),
         'VISUAL_CONTACT_SHEET_TAMPERED')
    measured=inspect_visual_content(image_bytes)
    need(measured['semantic_verdict']=='UNKNOWN'
         and measured['individual_mg0']=='UNKNOWN'
         and measured['work_advancement_authorized'] is False,
         'VISUAL_CONTENT_CANNOT_CERTIFY_ASSET')
    result={'schema':'gg-c07-eight-angle-evidence-readback-v1',
       'asset':work['asset_id'],'attempt_id':work['attempt_id'],
       'operation_sha256':work['operation_sha256'],
       'master_sha256':work['master_sha256'],'phase':work['phase'],
       'source_sha256':source_sha,'manifest_sha256':manifest_sha,
       'verified_pngs':16,'paired_unique_angles':8,
       'image_byte_integrity':'VERIFIED',
       'model_render_content_authenticity':'NOT_PROVEN_BY_HASHES',
       'pixel_content_analysis':measured,
       'visual_review_hold':measured['requires_independent_visual_review'],
       'visual_quality':'UNKNOWN_REQUIRES_INDEPENDENT_REVIEW',
       'fiveM_equivalence':'NOT_PROVEN',
       'semantic_verdict':'UNKNOWN','individual_mg0':'UNKNOWN',
       'work_advancement_authorized':False}
    result['evidence_sha256']=digest(json.dumps(result,sort_keys=True,
       separators=(',',':')).encode('utf-8'))
    return result

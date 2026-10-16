"""C07 deterministic PNG image-content comparisons. Diagnostic, never visual PASS."""
import hashlib
import math
import struct
import zlib

VIEWS=('front','front_right','right','rear_right','rear','left','roof','entry_close')
MODES=('SOURCE_RGB_OPAQUE','NEUTRAL_RGB_DIAGNOSTIC')
STEP=4
MAX_PIXELS=4_000_000
MAX_DECOMPRESSED=32_000_000
MIN_FOREGROUND_SAMPLES=150
MASK_IOU_FLOOR=.93
SOURCE_DARK_RATIO=.78
DIFF_FROM_BACKGROUND=22

class VisualContentBlocked(ValueError): pass

def need(ok,why):
    if not ok: raise VisualContentBlocked(why)

def _paeth(a,b,c):
    p=a+b-c;da,db,dc=abs(p-a),abs(p-b),abs(p-c)
    return a if da<=db and da<=dc else b if db<=dc else c

def decode_grid(data,step=STEP):
    """Strict CRC-checked bounded truecolor PNG decoder with five PNG filters."""
    need(type(data) is bytes and type(step) is int and 1<=step<=16,'PNG_INPUT_SCHEMA')
    need(data[:8]==b'\x89PNG\r\n\x1a\n','PNG_BAD_SIGNATURE')
    pos=8;parts=[];w=h=channels=None;ended=False;count=0
    while pos<len(data):
        need(pos+12<=len(data),'PNG_TRUNCATED_CHUNK')
        n=struct.unpack_from('>I',data,pos)[0];typ=data[pos+4:pos+8]
        need(n<=len(data)-pos-12,'PNG_INVALID_CHUNK_LENGTH')
        payload=data[pos+8:pos+8+n]
        crc=struct.unpack_from('>I',data,pos+8+n)[0]
        need((zlib.crc32(typ+payload)&0xffffffff)==crc,'PNG_CRC_INVALID')
        if count==0:
            need(typ==b'IHDR' and n==13,'PNG_MISSING_IHDR')
            w,h,depth,color,compression,fil,interlace=struct.unpack('>IIBBBBB',payload)
            need(0<w and 0<h and w*h<=MAX_PIXELS,'PNG_PIXEL_BUDGET')
            need(depth==8 and color in (2,6) and compression==fil==interlace==0,
                 'PNG_FORMAT_UNSUPPORTED')
            channels=3 if color==2 else 4
        if typ==b'IDAT':parts.append(payload)
        if typ==b'IEND':
            need(n==0 and pos+12==len(data),'PNG_TRAILING_CONTENT')
            ended=True
        pos+=n+12;count+=1
        need(count<=100000,'PNG_TOO_MANY_CHUNKS')
        if ended:break
    need(ended and bool(parts) and channels is not None,'PNG_INCOMPLETE')
    pitch=w*channels;expected=h*(pitch+1)
    need(expected<=MAX_DECOMPRESSED,'PNG_RAW_SIZE_BUDGET')
    decompressor=zlib.decompressobj();raw=bytearray()
    try:
        for chunk in parts:
            raw.extend(decompressor.decompress(chunk,expected+1-len(raw)))
            need(len(raw)<=expected and not decompressor.unconsumed_tail,
                 'PNG_DECOMPRESS_OVERFLOW')
        raw.extend(decompressor.flush(expected+1-len(raw)))
    except zlib.error as exc:
        raise VisualContentBlocked('PNG_ZLIB_CORRUPT') from exc
    need(len(raw)==expected and decompressor.eof and not decompressor.unused_data,
         'PNG_DECOMPRESS_INCOMPLETE')
    previous=bytearray(pitch);cursor=0;samples=[]
    for y in range(h):
        filter_id=raw[cursor];cursor+=1
        need(filter_id in (0,1,2,3,4),'PNG_ROW_FILTER_UNSUPPORTED')
        row=bytearray(raw[cursor:cursor+pitch]);cursor+=pitch
        for x in range(pitch):
            left=row[x-channels] if x>=channels else 0
            up=previous[x]
            upper_left=previous[x-channels] if x>=channels else 0
            prediction=(0 if filter_id==0 else left if filter_id==1
              else up if filter_id==2 else (left+up)//2 if filter_id==3
              else _paeth(left,up,upper_left))
            row[x]=(row[x]+prediction)&255
        if y%step==0:
            for x in range(0,w,step):
                k=x*channels
                samples.append((row[k],row[k+1],row[k+2]))
        previous=row
    return w,h,samples

def compare_pair(source_png,diagnostic_png):
    width,height,a=decode_grid(source_png)
    width2,height2,b=decode_grid(diagnostic_png)
    need((width,height)==(width2,height2) and len(a)==len(b),
         'PAIR_MISMATCHED_DIMENSIONS')
    bga=a[0];bgb=b[0]
    need(bga==bgb,'PAIR_DIFFERENT_BACKGROUND')
    n_a=n_b=common=union=changed=0
    sum_a=sum_b=0.
    for x,y in zip(a,b):
        ma=max(abs(x[i]-bga[i]) for i in range(3))>DIFF_FROM_BACKGROUND
        mb=max(abs(y[i]-bgb[i]) for i in range(3))>DIFF_FROM_BACKGROUND
        if ma:n_a+=1
        if mb:n_b+=1
        if ma and mb:common+=1
        if ma or mb:
            union+=1;sum_a+=sum(x)/3.;sum_b+=sum(y)/3.
            if x!=y:changed+=1
    coverage=union/len(a) if a else 0.
    iou=common/union if union else 0.
    ratio=sum_a/sum_b if union and sum_b>0 else None
    sufficient=union>=MIN_FOREGROUND_SAMPLES and coverage>=.01
    mismatch=sufficient and iou<MASK_IOU_FLOOR
    dark=bool(sufficient and not mismatch and ratio is not None
              and ratio<SOURCE_DARK_RATIO and changed/max(union,1)>.2)
    return {'sample_count':len(a),'foreground_union_samples':union,
       'foreground_fraction':round(coverage,6),
       'foreground_mask_iou':round(iou,6),
       'source_foreground_mean':round(sum_a/union,5) if union else None,
       'neutral_foreground_mean':round(sum_b/union,5) if union else None,
       'source_to_neutral_brightness_ratio':round(ratio,6) if ratio is not None else None,
       'changed_foreground_fraction':round(changed/union,6) if union else 0,
       'sufficient_visible_content':sufficient,
       'geometry_or_camera_mismatch_suspected':bool(mismatch),
       'significant_material_darkening_measured':dark}

def inspect_bytes(images):
    need(type(images) is dict and len(images)==16,'EXACT_16_IMAGE_BYTES_REQUIRED')
    found=[];unverified=[]
    for view in VIEWS:
        x=images.get((view,MODES[0]))
        y=images.get((view,MODES[1]))
        need(type(x) is bytes and type(y) is bytes,'PAIR_IMAGE_MISSING:'+view)
        try:result=compare_pair(x,y)
        except VisualContentBlocked as exc:
            unverified.append(view+':'+str(exc));continue
        found.append({'view':view,**result})
        if not result['sufficient_visible_content']:
            unverified.append(view+':INSUFFICIENT_OBJECT_COVERAGE')
    dark=sum(int(x['significant_material_darkening_measured']) for x in found)
    mismatched=sum(int(x['geometry_or_camera_mismatch_suspected']) for x in found)
    systemic=len(found)==8 and not unverified and mismatched==0 and dark>=6
    return {'schema':'gg-c07-visual-content-comparison-v1',
       'sampling_stride_pixels':STEP,'measured_views':len(found),
       'per_view':found,'significantly_darkened_views':dark,
       'content_geometry_mismatch_views':mismatched,
       'unverified_views':unverified,
       'systemic_darkening':'REVIEW_REQUIRED_MEASURED_6_OF_8' if systemic else
           'UNKNOWN' if unverified or mismatched else 'NOT_ESTABLISHED',
       'requires_independent_visual_review':systemic or mismatched>0 or bool(unverified),
       'asset_visual_quality':'UNKNOWN','source_render_authenticity':'NOT_PROVEN',
       'fivem_fidelity':'NOT_PROVEN','semantic_verdict':'UNKNOWN',
       'individual_mg0':'UNKNOWN','work_advancement_authorized':False}

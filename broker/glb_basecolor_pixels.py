"""C07 diagnostic sRGB pixel verification for embedded GLB PNG base colors.

Decode actual 8-bit RGB/RGBA PNG pixel rows with CRC/chunk validation,
bounded IDAT decompression and all five PNG row filters. Only tests baseColor
texture content and baseColorFactor. A systemic 1/255 multiplier becomes a
review HOLD, never an artistic FAIL or PASS. No GPU, FiveM or image-quality claim.
"""
import hashlib
import math
import struct
import zlib

MAX_PIXEL_COUNT = 4_000_000
MAX_RAW_BYTES = 32_000_000
SMALL_FACTOR = 1/255 + 1e-6

class PixelReviewUnsupported(ValueError):
    pass

def require(value,code):
    if not value:raise PixelReviewUnsupported(code)

def _paeth(a,b,c):
    p=a+b-c
    da,db,dc=abs(p-a),abs(p-b),abs(p-c)
    return a if da<=db and da<=dc else b if db<=dc else c

def png_rgb_means(raw):
    """Return means over all decoded pixels; unsupported PNG remains UNKNOWN."""
    require(type(raw) is bytes and raw.startswith(b'\x89PNG\r\n\x1a\n'),
            'PIXEL_PNG_HEADER')
    p=8;parts=[];w=h=channels=None;seen_end=False;first=True
    while p<len(raw):
        require(p+12<=len(raw),'PIXEL_PNG_CHUNK_TRUNCATED')
        n=struct.unpack_from('>I',raw,p)[0]
        typ=raw[p+4:p+8]
        require(n<=len(raw)-p-12,'PIXEL_PNG_CHUNK_OVERFLOW')
        payload=raw[p+8:p+8+n]
        crc=struct.unpack_from('>I',raw,p+8+n)[0]
        require((zlib.crc32(typ+payload)&0xffffffff)==crc,'PIXEL_PNG_CRC')
        if first:
            require(typ==b'IHDR' and n==13,'PIXEL_PNG_NO_IHDR')
            w,h,depth,color,comp,fil,interlace=struct.unpack_from('>IIBBBBB',payload)
            require(depth==8 and color in (2,6) and comp==0 and fil==0 and interlace==0,
                    'PIXEL_PNG_FORMAT_UNSUPPORTED')
            require(w>0 and h>0 and w*h<=MAX_PIXEL_COUNT,'PIXEL_PNG_DIMENSIONS_BUDGET')
            channels=3 if color==2 else 4
        if typ==b'IDAT':parts.append(payload)
        if typ==b'IEND':
            require(n==0 and p+12==len(raw),'PIXEL_PNG_IEND_INVALID')
            seen_end=True
        p+=12+n;first=False
        if seen_end:break
    require(seen_end and parts and w is not None,'PIXEL_PNG_INCOMPLETE')
    pitch=w*channels
    expected=h*(pitch+1)
    require(expected<=MAX_RAW_BYTES,'PIXEL_PNG_RAW_BUDGET')
    dec=zlib.decompressobj()
    data=b''
    for part in parts:
        max_output=expected+1-len(data)
        require(max_output>0,'PIXEL_PNG_RAW_OVERFLOW')
        data+=dec.decompress(part,max_output)
        require(len(data)<=expected and not dec.unconsumed_tail,
                'PIXEL_PNG_DECOMPRESSED_OVERFLOW')
    data+=dec.flush(expected+1-len(data))
    require(len(data)==expected and dec.eof and not dec.unused_data,
            'PIXEL_PNG_DECOMPRESSED_SIZE_OR_ZLIB_INVALID')
    sums=[0,0,0];linear=[0.,0.,0.];prev=bytearray(pitch);cursor=0
    linear_lut=[(v/255/12.92 if v/255<=0.04045 else ((v/255+0.055)/1.055)**2.4)
                for v in range(256)]
    for y in range(h):
        filt=data[cursor];cursor+=1
        require(filt in (0,1,2,3,4),'PIXEL_PNG_BAD_FILTER')
        row=bytearray(data[cursor:cursor+pitch]);cursor+=pitch
        for i in range(pitch):
            left=row[i-channels] if i>=channels else 0
            up=prev[i]
            ul=prev[i-channels] if i>=channels else 0
            pred=(0 if filt==0 else left if filt==1 else up if filt==2
                  else (left+up)//2 if filt==3 else _paeth(left,up,ul))
            row[i]=(row[i]+pred)&255
        for i in range(0,pitch,channels):
            for channel in range(3):
                value=row[i+channel]
                sums[channel]+=value
                linear[channel]+=linear_lut[value]
        prev=row
    total=w*h
    return {'width':w,'height':h,'pixel_count':total,
            'rgb_mean_srgb_0_255':[round(t/total,4) for t in sums],
            'rgb_mean_linear_0_1':[round(t/total,8) for t in linear],
            'image_sha256':hashlib.sha256(raw).hexdigest(),
            'pixel_decode':'COMPLETE_FOR_SUPPORTED_PNG_RGB_RGBA'}


def inspect(g, blob, used_materials, max_images=40):
    """Independent immutable embedded texture pixel review. No PASS."""
    require(type(g) is dict and type(blob) is bytes and
            type(used_materials) in (list,tuple),
            'PIXEL_SOURCE_SCHEMA')
    mats=g.get('materials',[]);tex=g.get('textures',[])
    imgs=g.get('images',[]);views=g.get('bufferViews',[])
    rows=[];unverified=[]
    if len(used_materials)>max_images:
        return {'schema':'gg-c07-basecolor-pixels-v1','rows':[],
                'unverified':['PIXEL_MATERIAL_REVIEW_BUDGET'],
                'systemic_tint_risk':'UNKNOWN','requires_visual_review':True,
                'semantic_result':'UNKNOWN','individual_mg0':'UNKNOWN',
                'advancement_authorized':False}
    for mid in sorted(set(used_materials)):
        if type(mid) is not int or not 0<=mid<len(mats):
            unverified.append('PIXEL_MATERIAL_REF_INVALID:'+str(mid));continue
        pbr=mats[mid].get('pbrMetallicRoughness',{})
        slot=pbr.get('baseColorTexture')
        if not isinstance(slot,dict):continue
        tid=slot.get('index')
        if type(tid) is not int or not 0<=tid<len(tex):
            unverified.append('PIXEL_TEXTURE_REF_INVALID:'+str(mid));continue
        image_id=tex[tid].get('source')
        if type(image_id) is not int or not 0<=image_id<len(imgs):
            unverified.append('PIXEL_IMAGE_REF_INVALID:'+str(mid));continue
        im=imgs[image_id]
        if 'uri' in im or im.get('mimeType')!='image/png':
            unverified.append('PIXEL_EXTERNAL_OR_NONPNG:'+str(mid));continue
        vid=im.get('bufferView')
        if type(vid) is not int or not 0<=vid<len(views):
            unverified.append('PIXEL_IMAGE_VIEW_INVALID:'+str(mid));continue
        v=views[vid];offset=v.get('byteOffset',0);size=v.get('byteLength')
        if v.get('buffer')!=0 or not isinstance(offset,int) or not isinstance(size,int) or offset<0 or size<0 or offset+size>len(blob):
            unverified.append('PIXEL_IMAGE_BOUNDS_INVALID:'+str(mid));continue
        try: pixels=png_rgb_means(blob[offset:offset+size])
        except (PixelReviewUnsupported,zlib.error,ValueError,struct.error) as exc:
            unverified.append('PIXEL_UNSUPPORTED_OR_INVALID:'+str(mid)+':'+str(exc));continue
        factor=pbr.get('baseColorFactor',[1,1,1,1])
        if not (type(factor) is list and len(factor)==4
                and all(type(x) in (float,int) and math.isfinite(x) and 0<=x<=1 for x in factor)):
            unverified.append('PIXEL_BASECOLOR_FACTOR_INVALID:'+str(mid));continue
        effective=[round(pixels['rgb_mean_linear_0_1'][i]*factor[i],10) for i in range(3)]
        nearblack=all(value<=SMALL_FACTOR for value in factor[:3])
        row={'material_index':mid,'image_index':image_id,**pixels,
             'base_color_factor':factor,
             'approx_mean_linear_after_basecolor_multiplier':effective,
             'near_black_multiplier':nearblack,
             'does_not_simulate_render_engine':True}
        rows.append(row)
    # Block suspicious widespread near-black multiplier only if every
    # *actually decoded* textured source has perceptible nonblack content,
    # and no required source was dropped. Not a general dark-material FAIL.
    ready=len(rows)>=2 and len(rows)==len(used_materials) and not unverified
    systemic=bool(ready and all(r['near_black_multiplier'] for r in rows)
                 and all(max(r['rgb_mean_linear_0_1'])>=0.02 for r in rows))
    return {'schema':'gg-c07-basecolor-pixels-v1',
            'rows':rows,'decoded_textured_materials':len(rows),
            'unverified':sorted(set(unverified)),
            'systemic_tint_risk':'REVIEW_REQUIRED_CONFIRMED_PIXEL_MULTIPLIER' if systemic
                                else 'NOT_CONFIRMED' if ready else 'UNKNOWN',
            'requires_visual_review':systemic,
            'visual_qa':'UNKNOWN','semantic_result':'UNKNOWN',
            'individual_mg0':'UNKNOWN','advancement_authorized':False}

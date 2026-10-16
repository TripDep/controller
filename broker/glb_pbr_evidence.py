"""C07 forensic PBR/UV/embedded-texture evidence for real glTF GLB bytes.

Validates texture->image->bufferView, image magic/dimensions, PBR factors,
samplers, actually used TEXCOORD sets and UV counts/finite values. Flags
suspicious 1/255 tint as a WARNING, not an assumed artistic defect. Never
grants artistic quality, MG0, FiveM, or semantic PASS.
"""
import hashlib
import math
import re
import struct
import zlib

SHA_THRESHOLD=1/255+1e-6
MAX_UV_SAMPLES=2_000_000
TEXTURE_SLOTS=('normalTexture','occlusionTexture','emissiveTexture')
PBR_SLOTS=('baseColorTexture','metallicRoughnessTexture')
NORMALIZED_MAX=1_000_000

class MaterialEvidenceError(ValueError):pass

def require(ok, reason):
    if not ok:raise MaterialEvidenceError(reason)

def finite_scalar(v):
    return type(v) in (int,float) and math.isfinite(v)

def validate_png_chunks(raw):
    """Validate embedded PNG chunk boundaries and CRC, not pixel appearance."""
    require(raw[:8] == b'\x89PNG\r\n\x1a\n', 'PBR_EMBEDDED_PNG_HEADER_INVALID')
    cursor=8;chunks=0;dimensions=None;idat=False;iend=False
    while cursor<len(raw):
        require(cursor+12<=len(raw),'PBR_EMBEDDED_PNG_TRUNCATED_CHUNK')
        length=struct.unpack_from('>I',raw,cursor)[0]
        typ=raw[cursor+4:cursor+8]
        require(length<=len(raw)-cursor-12,'PBR_EMBEDDED_PNG_CHUNK_BOUNDS')
        body=raw[cursor+8:cursor+8+length]
        expected=struct.unpack_from('>I',raw,cursor+8+length)[0]
        actual=zlib.crc32(typ+body)&0xffffffff
        require(expected==actual,'PBR_EMBEDDED_PNG_CRC_INVALID')
        if chunks==0:
            require(typ==b'IHDR' and length==13,'PBR_EMBEDDED_PNG_IHDR_INVALID')
            width,height=struct.unpack_from('>II',body,0)
            require(0<width<=65536 and 0<height<=65536,'PBR_IMAGE_DIMENSIONS_INVALID')
            dimensions=(width,height)
        if typ==b'IDAT':idat=True
        if typ==b'IEND':
            require(length==0 and cursor+12==len(raw),'PBR_EMBEDDED_PNG_IEND_INVALID')
            iend=True
        chunks+=1
        require(chunks<=100000,'PBR_EMBEDDED_PNG_CHUNKS_EXCESSIVE')
        cursor+=12+length
        if iend:break
    require(dimensions is not None and idat and iend,'PBR_EMBEDDED_PNG_INCOMPLETE')
    return dimensions

def image_bounds(g,bin_blob,image_id):
    images=g.get('images',[])
    require(type(image_id) is int and 0<=image_id<len(images),'PBR_IMAGE_REF_OUT_OF_RANGE')
    image=images[image_id]
    require(type(image) is dict,'PBR_IMAGE_ROW_NOT_OBJECT')
    if 'uri' in image:
        return None,'URI_IMAGE_UNVERIFIED'
    if 'bufferView' not in image:
        return None,'IMAGE_HAS_NO_DATA'
    views=g.get('bufferViews',[])
    vid=image['bufferView']
    require(type(vid) is int and 0<=vid<len(views),'PBR_IMAGE_VIEW_REF_OUT_OF_RANGE')
    view=views[vid]
    require(view.get('buffer')==0,'PBR_IMAGE_NOT_IN_EMBEDDED_BUFFER')
    start=view.get('byteOffset',0);length=view.get('byteLength')
    require(type(start) is int and type(length) is int and start>=0 and length>0 and start+length<=len(bin_blob),
            'PBR_IMAGE_VIEW_OUT_OF_BOUNDS')
    raw=bin_blob[start:start+length];kind=image.get('mimeType')
    if kind=='image/png':
        width,height=validate_png_chunks(raw)
        return (width,height),'PNG_CHUNKS_AND_CRC_VERIFIED_PIXELS_NOT_DECODED'
    if kind=='image/jpeg':
        require(raw[:2]==b'\xff\xd8' and raw[-2:]==b'\xff\xd9',
                'PBR_EMBEDDED_JPEG_HEADER_INVALID')
        return None,'JPEG_HEADER_ONLY_NOT_DECODED'
    if kind=='image/webp':
        require(raw[:4]==b'RIFF' and raw[8:12]==b'WEBP' and len(raw)>=16,
                'PBR_EMBEDDED_WEBP_HEADER_INVALID')
        return None,'WEBP_HEADER_ONLY_NOT_DECODED'
    return None,'IMAGE_MIMETYPE_UNSUPPORTED_UNVERIFIED'

def uv_count_and_finiteness(g,bin_blob,accessor_id,expected_count,limit):
    accessors=g.get('accessors',[]);views=g.get('bufferViews',[])
    require(type(accessor_id) is int and 0<=accessor_id<len(accessors),'PBR_UV_ACCESSOR_REF')
    a=accessors[accessor_id]
    component=a.get('componentType')
    require(a.get('type')=='VEC2' and component in (5126,5120,5121,5122,5123),
            'PBR_UV_FORMAT_UNSUPPORTED')
    if component != 5126:
        require(a.get('normalized') is True,'PBR_INTEGER_UV_REQUIRES_NORMALIZED')
    component_fmt={5126:'f',5120:'b',5121:'B',5122:'h',5123:'H'}[component]
    component_size=struct.calcsize('<'+component_fmt)
    uv_bytes=component_size*2
    require('sparse' not in a and 'bufferView' in a,'PBR_UV_SPARSE_OR_UNBACKED_UNSUPPORTED')
    count=a.get('count')
    require(type(count) is int and count==expected_count,'PBR_UV_VERTEX_COUNT_MISMATCH')
    vid=a['bufferView'];require(type(vid) is int and 0<=vid<len(views),'PBR_UV_VIEW_MISSING')
    v=views[vid];require(v.get('buffer')==0,'PBR_UV_EXTERNAL_BUFFER')
    start=v.get('byteOffset',0);offset=a.get('byteOffset',0)
    length=v.get('byteLength');stride=v.get('byteStride',uv_bytes)
    require(all(type(k) is int and k>=0 for k in (start,offset,length)) and
            type(stride) is int and stride>=uv_bytes and stride%component_size==0,
            'PBR_UV_INVALID_STRIDE_OR_OFFSET')
    first=start+offset
    require(start+length<=len(bin_blob) and
            (count==0 or first+(count-1)*stride+uv_bytes<=start+length),
            'PBR_UV_OUTSIDE_BUFFER_VIEW')
    if count>limit: return 'NOT_SAMPLED_BUDGET',0
    unpack=struct.Struct('<'+component_fmt*2).unpack_from
    bad=sum(1 for i in range(count) if any(not math.isfinite(x) for x in unpack(bin_blob,first+i*stride)))
    return 'COMPLETE_FINITE_CHECK',bad

def inspect(g,bin_blob,reachable_mesh_instances):
    require(type(g) is dict and type(bin_blob) is bytes and
            type(reachable_mesh_instances) is list,'PBR_SOURCE_INPUT_SCHEMA')
    errors=[];warnings=[];unknown=[];used=set();uv_inspected=set()
    mat_use={};tex_use=set();image_use=set();factors={}
    materials=g.get('materials',[]);meshes=g.get('meshes',[])
    textures=g.get('textures',[]);images=g.get('images',[]);samplers=g.get('samplers',[])
    require(all(type(x) is list for x in (materials,meshes,textures,images,samplers)),
            'PBR_GTLF_TABLE_SCHEMA')
    total_mesh_primitives=0;uv_sets_verified=0;uv_values_checked=0
    for instance in reachable_mesh_instances:
        require(type(instance) in (tuple,list) and len(instance)>=2,'PBR_REACHABLE_INSTANCE_SCHEMA')
        _,mid=instance[:2]
        require(type(mid) is int and 0<=mid<len(meshes),'PBR_MESH_REF_INVALID')
        for pid,prim in enumerate(meshes[mid].get('primitives',[])):
            total_mesh_primitives+=1
            if not isinstance(prim,dict):errors.append('PBR_NONOBJECT_PRIMITIVE:'+str(mid)+':'+str(pid));continue
            ref=prim.get('material')
            if ref is None:
                unknown.append('PBR_DEFAULT_MATERIAL_UNVERIFIED:'+str(mid)+':'+str(pid))
                continue
            if type(ref) is not int or not 0<=ref<len(materials):
                errors.append('PBR_USED_MATERIAL_REF_INVALID:'+str(mid)+':'+str(pid))
                continue
            used.add(ref);mat_use.setdefault(ref,[]).append((mid,pid,prim))
    for mat_id in sorted(used):
        mat=materials[mat_id]
        if type(mat) is not dict:
            errors.append('PBR_MATERIAL_NOT_OBJECT:'+str(mat_id));continue
        pbr=mat.get('pbrMetallicRoughness',{})
        if type(pbr) is not dict:
            errors.append('PBR_PROPERTIES_NOT_OBJECT:'+str(mat_id));continue
        mode=mat.get('alphaMode','OPAQUE')
        if mode not in ('OPAQUE','MASK','BLEND'):
            errors.append('PBR_ALPHA_MODE_INVALID:'+str(mat_id))
        if mode=='MASK' and not (finite_scalar(mat.get('alphaCutoff',0.5)) and 0<=mat.get('alphaCutoff',0.5)<=1):
            errors.append('PBR_ALPHA_CUTOFF_INVALID:'+str(mat_id))
        factor=pbr.get('baseColorFactor',[1,1,1,1])
        if not (type(factor) is list and len(factor)==4 and all(finite_scalar(x) and 0<=x<=1 for x in factor)):
            errors.append('PBR_BASE_COLOR_FACTOR_INVALID:'+str(mat_id))
        else:
            factors[mat_id]=factor
            if 'baseColorTexture' in pbr and all(x<=SHA_THRESHOLD for x in factor[:3]):
                warnings.append('PBR_NEAR_BLACK_TEXTURE_MULTIPLIER:'+str(mat_id))
        for prop in ('metallicFactor','roughnessFactor'):
            value=pbr.get(prop,1.0)
            if not finite_scalar(value) or not 0<=value<=1:
                errors.append('PBR_FACTOR_INVALID:'+str(mat_id)+':'+prop)
        slots={key:pbr[key] for key in PBR_SLOTS if key in pbr}
        slots.update({key:mat[key] for key in TEXTURE_SLOTS if key in mat})
        if mat.get('extensions'):
            unknown.append('PBR_MATERIAL_EXTENSIONS_REQUIRE_SEPARATE_REVIEW:'+str(mat_id))
        for slot,info in slots.items():
            if type(info) is not dict or type(info.get('index')) is not int or not 0<=info['index']<len(textures):
                errors.append('PBR_TEXTURE_REF_INVALID:'+str(mat_id)+':'+slot);continue
            tex_id=info['index'];tex_use.add(tex_id)
            tex=textures[tex_id]
            if type(tex) is not dict:
                errors.append('PBR_TEXTURE_ROW_INVALID:'+str(tex_id));continue
            src=tex.get('source')
            if type(src) is int and 0<=src<len(images):
                image_use.add(src)
            elif 'extensions' in tex and 'KHR_texture_basisu' in tex['extensions']:
                unknown.append('PBR_BASISU_REQUIRES_EXTERNAL_DECODER:'+str(tex_id))
            else:
                errors.append('PBR_TEXTURE_HAS_NO_VALID_SOURCE:'+str(tex_id))
            if 'sampler' in tex and (type(tex['sampler']) is not int or not 0<=tex['sampler']<len(samplers)):
                errors.append('PBR_TEXTURE_SAMPLER_REF_INVALID:'+str(tex_id))
            coord=info.get('texCoord',0)
            transform=info.get('extensions',{}).get('KHR_texture_transform') if isinstance(info.get('extensions',{}),dict) else None
            if transform is not None:
                if not isinstance(transform,dict):
                    errors.append('PBR_TEXTURE_TRANSFORM_INVALID:'+str(mat_id));continue
                coord=transform.get('texCoord',coord)
                unknown.append('PBR_TEXTURE_TRANSFORM_VISUAL_REVIEW:'+str(mat_id)+':'+slot)
            if type(coord) is not int or not 0<=coord<=7:
                errors.append('PBR_TEXCOORD_SET_INVALID:'+str(mat_id)+':'+slot);continue
            key='TEXCOORD_'+str(coord)
            for mid,pid,prim in mat_use[mat_id]:
                attrs=prim.get('attributes',{})
                if type(attrs) is not dict or key not in attrs:
                    errors.append('PBR_USED_TEXCOORD_MISSING:'+str(mid)+':'+str(pid)+':'+key)
                    continue
                descriptor=(mid,pid,key)
                if descriptor in uv_inspected:continue
                uv_inspected.add(descriptor)
                pos_id=attrs.get('POSITION')
                if type(pos_id) is not int or not 0<=pos_id<len(g.get('accessors',[])):
                    errors.append('PBR_POSITION_REF_INVALID:'+str(mid)+':'+str(pid));continue
                expected=g['accessors'][pos_id].get('count')
                try:
                    state,invalid=uv_count_and_finiteness(g,bin_blob,attrs[key],expected,MAX_UV_SAMPLES-uv_values_checked)
                    if state=='NOT_SAMPLED_BUDGET':
                        unknown.append('PBR_UV_FULL_FINITE_CHECK_BUDGET:'+str(mid)+':'+str(pid))
                    else:
                        uv_values_checked+=expected;uv_sets_verified+=1
                        if invalid:errors.append('PBR_NONFINITE_UV:'+str(mid)+':'+str(pid)+':'+str(invalid))
                except (MaterialEvidenceError,KeyError,TypeError,IndexError) as exc:
                    errors.append(str(exc)+':'+str(mid)+':'+str(pid))
            if slot=='normalTexture':
                if not any('TANGENT' in r[2].get('attributes',{}) for r in mat_use[mat_id]):
                    unknown.append('PBR_TANGENT_FRAME_RUNTIME_REVIEW:'+str(mat_id))
    dims={}
    for img_id in sorted(image_use):
        try:
            dim,status=image_bounds(g,bin_blob,img_id)
            dims[str(img_id)]=list(dim) if dim else None
            if status!='PNG_CHUNKS_AND_CRC_VERIFIED_PIXELS_NOT_DECODED':
                unknown.append('PBR_IMAGE_CONTENT_NOT_FULLY_DECODED:'+str(img_id)+':'+status)
            else:
                unknown.append('PBR_PNG_PIXELS_NOT_DECODED:'+str(img_id))
        except (MaterialEvidenceError,KeyError,TypeError,IndexError) as exc:
            errors.append(str(exc)+':'+str(img_id))
    nearblack=sum(1 for id in used if id in factors and 'PBR_NEAR_BLACK_TEXTURE_MULTIPLIER:'+str(id) in warnings)
    if len(used)>=2 and nearblack==len(used):
        warnings.append('PBR_ALL_USED_TEXTURED_MATERIALS_NEAR_BLACK_POSSIBLE_DOUBLE_NORMALIZATION')
    return {'schema':'gg-c07-glb-pbr-source-integrity-v1',
            'used_materials_count':len(used),
            'used_material_indices':sorted(used),
            'referenced_textures_count':len(tex_use),
            'referenced_images_count':len(image_use),
            'referenced_image_dimensions':dims,
            'mesh_primitive_instances_seen':total_mesh_primitives,
            'uv_sets_finite_checked':uv_sets_verified,
            'uv_coordinates_finite_checked':uv_values_checked,
            'near_black_textured_materials_count':nearblack,
            'pbr_structural_errors':sorted(set(errors)),
            'pbr_diagnostic_warnings':sorted(set(warnings)),
            'pbr_unverified_requirements':sorted(set(unknown)),
            'material_source_status':'FAIL' if errors else 'NO_STRUCTURAL_PBR_DEFECT_DETECTED',
            'color_fidelity':'UNKNOWN','texture_decoding':'UNKNOWN',
            'visual_material_quality':'UNKNOWN',
            'fivem_runtime':'UNKNOWN','individual_mg0':'UNKNOWN',
            'overall_rule_semantics':'UNKNOWN','advancement_authorized':False}

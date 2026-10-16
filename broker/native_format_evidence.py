"""C07 native format source integrity: Blender (.blend, .blend.zstd), GTA V RSC7 (.ydr).

Only machine evidence; never artist, semantic, runtime or MG0 PASS.
Blender: modern and legacy block framing, DNA1/ENDB presence, header versions.
RSC7: container header and bounded raw/zlib deflate payload verification; does
NOT understand drawable hierarchy or verify FiveM/Sollumz reimport.
Compressed blend: decompress with available trusted zstd executable outside this
parser; scan the verified decompressed bytes or report UNKNOWN, never claim PASS.
"""
import hashlib
import mmap
import re
import struct
import zlib
from pathlib import Path

MAX_FILE_SIZE=1024*1024*1024
MAX_RSC_UNPACKED=512*1024*1024
MAX_BLOCKS=2_000_000

class NativeScanBlocked(ValueError):pass

def need(ok,message):
    if not ok:raise NativeScanBlocked(message)

def sha256_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()

def recognized_header(view):
    """Return Blender header tuple (format, version, size, struct fmt, endian) or error."""
    need(len(view)>=12 and bytes(view[:7])==b'BLENDER','BLEND_HEADER_MAGIC')
    if bytes(view[7:8]) in (b'-',b'_'):
        ptr=8 if bytes(view[7:8])==b'-' else 4
        endian={b'v':'<',b'V':'>'}.get(bytes(view[8:9]))
        need(endian is not None and bytes(view[9:12]).isdigit(),'BLEND_LEGACY_HEADER_INVALID')
        bhead=endian+('4sIQII' if ptr==8 else '4sIIII')
        return {'variant':'LEGACY_12','version':int(bytes(view[9:12])),
                'pointer_bytes':ptr,'header_size':12,'bhead_format':bhead}
    need(len(view)>=17 and bytes(view[7:9])==b'17' and
         bytes(view[9:13])==b'-01v' and bytes(view[13:17]).isdigit(),
         'BLEND_MODERN_HEADER_INVALID')
    return {'variant':'MODERN_17','version':int(bytes(view[13:17])),
            'pointer_bytes':8,'header_size':17,'bhead_format':'<4sIQQQ'}

def scan_blend_buffer(view):
    header=recognized_header(view);fmt=header['bhead_format'];size=struct.calcsize(fmt)
    pos=header['header_size'];blocks=0;dna=0;end=0;data_total=0;code_counts={}
    while pos<len(view):
        need(blocks<MAX_BLOCKS,'BLEND_BLOCKS_EXCEED_LIMIT')
        need(pos+size<=len(view),'BLEND_TRUNCATED_BLOCK_HEADER')
        block=struct.unpack_from(fmt,view,pos)
        if header['variant']=='MODERN_17':
            code,sdna,old,block_len,count=block
        else:
            code,block_len,old,sdna,count=block
        need(block_len>=0 and block_len<=MAX_FILE_SIZE,'BLEND_BLOCK_LENGTH_INVALID')
        pos+=size
        need(pos+block_len<=len(view),'BLEND_TRUNCATED_BLOCK_BODY')
        blocks+=1
        code_name=code.decode('latin1')
        code_counts[code_name]=code_counts.get(code_name,0)+1
        if code==b'DNA1':
            dna+=1
            need(block_len>=4 and bytes(view[pos:pos+4])==b'SDNA',
                 'BLEND_DNA1_BODY_INVALID')
        if code==b'ENDB':
            end+=1
            need(block_len==0,'BLEND_ENDB_NONZERO_LENGTH')
            # Small trailing pad can occur, but never silently allow extra block data.
            need(len(view)-pos<=16 and all(b==0 for b in view[pos:]),
                 'BLEND_UNEXPECTED_TRAILING_BLOCKS')
            break
        data_total+=block_len
        pos+=block_len
    need(end==1 and dna==1,'BLEND_DNA1_OR_ENDB_NOT_FOUND')
    return {'header_variant':header['variant'],'blender_file_version':header['version'],
      'pointer_bytes':header['pointer_bytes'],'file_blocks':blocks,
      'block_payload_bytes':data_total,'dna1_blocks':dna,'endb_blocks':end,
      'object_blocks':code_counts.get('OB\x00\x00',0),
      'mesh_blocks':code_counts.get('ME\x00\x00',0),
      'sdna_exists':True,'binary_structure':'BLOCK_FRAMING_CHECKED',
      'runtime_open_by_blender':'NOT_TESTED','object_geometry':'NOT_VERIFIED',
      'asset_acceptance':'NOT_AUTHORIZED','semantic_verdict':'UNKNOWN','individual_mg0':'UNKNOWN'}

def scan_blend_file(path):
    with open(path,'rb') as f:
        with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
            if bytes(data[:4])==b'\x28\xb5\x2f\xfd':
                return {'compression':'ZSTANDARD','binary_structure':'UNKNOWN_NEEDS_BOUNDED_DECOMPRESSION',
                  'runtime_open_by_blender':'NOT_TESTED','asset_acceptance':'NOT_AUTHORIZED',
                  'semantic_verdict':'UNKNOWN','individual_mg0':'UNKNOWN'}
            return {'compression':'NONE',**scan_blend_buffer(data)}

def _limited_inflate(payload,wbits):
    d=zlib.decompressobj(wbits)
    out=d.decompress(payload,MAX_RSC_UNPACKED+1)
    need(len(out)<=MAX_RSC_UNPACKED and not d.unconsumed_tail,'RSC7_DEFLATE_OVERSIZE')
    more=d.flush()
    need(len(out)+len(more)<=MAX_RSC_UNPACKED,'RSC7_DEFLATE_OVERSIZE')
    need(d.eof and not d.unused_data,'RSC7_DEFLATE_STREAM_INCOMPLETE')
    return len(out)+len(more)

def scan_ydr_bytes(raw):
    need(len(raw)>=24 and raw[:4]==b'RSC7','YDR_RSC7_MAGIC_OR_HEADER_MISSING')
    version,system_flags,graphics_flags=struct.unpack_from('<III',raw,4)
    need(version>0 and version<10000,'YDR_RSC7_VERSION_INVALID')
    need(system_flags or graphics_flags,'YDR_RSC7_PAGE_FLAGS_EMPTY')
    data=raw[16:];unpacked=None;method=None
    for wbits,name in ((-15,'RAW_DEFLATE'),(15,'ZLIB')):
        try:
            unpacked=_limited_inflate(data,wbits)
            method=name;break
        except (zlib.error,NativeScanBlocked):continue
    need(unpacked is not None,'YDR_RSC7_COMPRESSED_DATA_INVALID_OR_UNSUPPORTED')
    return {'rsc_magic':'RSC7','rsc_version':version,'system_flags':system_flags,
       'graphics_flags':graphics_flags,'compressed_payload_bytes':len(data),
       'decompressed_payload_bytes':unpacked,'decompression':method,
       'binary_structure':'RESOURCE_CONTAINER_VERIFIED_ONLY',
       'drawable_geometry':'NOT_PARSED','texture_references':'NOT_PARSED',
       'fivem_runtime':'NOT_TESTED','asset_acceptance':'NOT_AUTHORIZED',
       'semantic_verdict':'UNKNOWN','individual_mg0':'UNKNOWN'}

def inspect(path,sha_expected,uncompressed_blend=None):
    path=Path(path)
    need(path.is_absolute() and path.is_file() and not path.is_symlink() and
        not any(p.is_symlink() for p in path.parents),'NATIVE_SOURCE_PATH_INVALID')
    need(path.suffix.lower() in ('.blend','.ydr'),'NATIVE_FORMAT_UNSUPPORTED')
    need(path.stat().st_size<=MAX_FILE_SIZE,'NATIVE_FILE_TOO_LARGE')
    need(type(sha_expected) is str and re.fullmatch('[0-9a-f]{64}',sha_expected),
         'NATIVE_SOURCE_SHA_REQUIRED')
    actual=sha256_file(path)
    need(actual==sha_expected,'NATIVE_SOURCE_SHA_MISMATCH')
    if path.suffix.lower()=='.ydr':
        data=path.read_bytes()
        inspected=scan_ydr_bytes(data)
    elif uncompressed_blend is not None:
        unpacked=Path(uncompressed_blend)
        need(unpacked.is_file() and path.read_bytes()[:4]==b'\x28\xb5\x2f\xfd',
             'NATIVE_COMPRESSED_PAIR_INVALID')
        need(unpacked.stat().st_size<=MAX_FILE_SIZE,'NATIVE_UNCOMPRESSED_TOO_LARGE')
        inspected=scan_blend_file(unpacked)
        inspected['compression']='ZSTANDARD_EXTERNALLY_DECOMPRESSED'
        inspected['unpacked_sha256']=sha256_file(unpacked)
        inspected['decompressor_integrity']='EXTERNAL_DECODER_MUST_BE_ATTESTED'
    else: inspected=scan_blend_file(path)
    return {'schema':'gg-c07-native-source-forensic-v1',
      'source_name':path.name,'source_sha256':actual,'source_bytes':path.stat().st_size,
      'format':path.suffix.lower(),'inspection':inspected,
      'machine_evidence_only':True,'semantic_verdict':'UNKNOWN',
      'runtime_compatibility':'UNKNOWN','individual_mg0':'UNKNOWN',
      'advancement_authorized':False}
"""C07 R151: original-byte, per-source-line proof intake for the frozen 200.

This closes a specific gap left by R122/R127: a producer could supply a YES
and a hash pointer for a broad composite without the Controller ever reopening
the purported original evidence bytes for that *source line*. Every nonblank
line of all 200 requirements, and all 72 composite source requirements, is
indexed by UTF-8 byte offset. Evidence is accepted only from artifacts already
registered on the exact open Controller attempt, then independently re-read.

A line is a *coverage target*, not an automatically complete semantic clause.
A PNG/GLB/JSON format probe, a source hash, a positive answer or an authentic
registered file is NOT a full-rule semantic result, independent human review,
MG0 PASS, or authorization. No synthetic evidence is minted when absent.
"""
import hashlib
import json
import re

from c07_positive200_evidence import select, _lanes, digest
from c07_compound_subchecks import ids as composite_ids, inspect as composite_inspect
from c07_positive_native_process import _original_attempt, _registered_artifacts
from c07_a10_c10_original_evidence import original_image
from c07_native_output_oracle import read_mesh_geometry, OriginalGeometryBlocked

SCHEMA = 'gg-c07-r151-frozen200-original-line-evidence-v1'
MANIFEST = 'gg-c07-r151-current-attempt-line-evidence-v1'
ROLE = 'C07_R151_RULE_LINE_EVIDENCE'
HEX64 = re.compile(r'[a-f0-9]{64}\Z')
PACKET_FIELDS = frozenset((
    'rule_id', 'line_id', 'line_sha256', 'requirement_sha256',
    'master_sha256', 'attempt_id', 'operation_sha256', 'source_lane',
    'evidence_role', 'evidence_path', 'evidence_sha256', 'answer'))
GEOMETRY_LANES = frozenset((
    'GLB_GEOMETRY', 'TOPOLOGY', 'MEASURED_TERRAIN',
    'GEOMETRY_OR_WORLD_COORDINATE_MEASUREMENT'))
IMAGE_LANES = frozenset((
    'VISUAL_MULTIVIEW', 'MULTILIGHT_RENDER', 'REFERENCE_PROVENANCE',
    'NATURAL_FORM_REFERENCE', 'HUMAN_REFERENCE_REVIEW'))

class UnverifiedLineEvidence(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise UnverifiedLineEvidence(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def source_lines(rid, row):
    """Exact, lossless UTF-8 source coverage, including unlisted prose.

    The original 72 composite bullet extractors do not account for headings,
    prose and embedded unnumbered obligations. This is a lossless source
    coverage map; semantic splitting within each line remains to be reviewed.
    """
    requirement = row.get('requirement')
    need(type(requirement) is str and requirement.strip(),
         'R151_CANONICAL_REQUIREMENT_MISSING:' + rid)
    raw = requirement.encode('utf-8')
    need(row.get('requirement_sha256') == sha(raw) and
         HEX64.fullmatch(str(row.get('source_sha256', ''))) is not None,
         'R151_CANONICAL_SOURCE_CHANGED:' + rid)
    offset = 0
    nonempty = []
    for number, line in enumerate(requirement.splitlines(keepends=True), 1):
        original = line.encode('utf-8')
        start = offset
        offset += len(original)
        if not line.strip():
            continue
        nonempty.append({
            'line_id': rid + ':L' + str(number).zfill(5),
            'source_line_number': number,
            'start_byte': start,
            'end_byte': offset,
            'line_sha256': sha(original),
        })
    need(offset == len(raw) and nonempty and
         all(0 <= x['start_byte'] < x['end_byte'] <= len(raw)
             for x in nonempty),
         'R151_SOURCE_BYTE_COVERAGE_CHANGED:' + rid)
    return {
        'rule_id': rid,
        'source_sha256': row['source_sha256'],
        'requirement_sha256': row['requirement_sha256'],
        'source_byte_length': len(raw),
        'all_source_bytes_accounted_for': True,
        'source_line_count': len(nonempty),
        'line_index_sha256': digest(nonempty),
        'lines': nonempty,
        'semantic_clause_exhaustiveness_independently_reviewed': False,
    }

def compile_contract(inventory, plan):
    selected, scope = select(inventory, plan)
    need(len(selected) == 200 and len(set(selected)) == 200,
         'R151_EXACT_FROZEN_200_REQUIRED')
    all_composites = composite_ids(inventory)
    need(len(all_composites) == 72 and all_composites <= set(inventory['rules']),
         'R151_EXACT_72_COMPOSITE_SOURCE_REQUIRED')
    composite = composite_inspect(inventory, sorted(all_composites))
    need(composite['canonical_composite_count'] == 72 and
         len(composite['due_composites']) == 72 and
         composite['independently_verified_count'] == 0 and
         composite['advancement_authorized'] is False,
         'R151_UNREVIEWED_COMPOSITE_MISREPRESENTED')
    source = inventory['rules']
    covered = set(selected) | all_composites
    rows = {}
    for rid in sorted(covered):
        row = source[rid]
        item = source_lines(rid, row)
        item['family'] = row['family']
        item['required_independent_lanes'] = list(_lanes({**row, 'rule_id': rid}))
        item['composite_flag'] = rid in all_composites
        if rid in all_composites:
            comp = composite['due_composites'][rid]
            need(comp['requirement_sha256'] == item['requirement_sha256'] and
                 comp['source_sha256'] == item['source_sha256'] and
                 comp['independent_verifier_ready'] is False,
                 'R151_COMPOSITE_CANONICAL_DRIFT:' + rid)
            item['original_candidate_subchecks'] = len(comp['subchecks'])
            item['composite_semantic_review'] = comp['source_decomposition']
        rows[rid] = item
    need(set(selected) <= set(rows) and
         len([rid for rid in rows if rows[rid]['composite_flag']]) == 72,
         'R151_SOURCE_RULE_OR_COMPOSITE_OMITTED')
    return {
        'schema': SCHEMA,
        'master_sha256': inventory['canonical_master_sha256'],
        'source_rule_count': 200,
        'source_rule_ids_sha256': digest(selected),
        'all_composite_source_rules': 72,
        'source_lines_covered': sum(r['source_line_count'] for r in rows.values()),
        'rows': rows,
        'selected': selected,
        'all_source_bytes_accounted_for': True,
        'all_semantic_obligations_reviewed': False,
        'individual_mg0_passes': 0,
        'advancement_authorized': False,
    }

def _native_format_probe(lane, raw):
    """A format readback only; NEVER a domain semantic verdict."""
    if lane in GEOMETRY_LANES:
        try:
            return bool(read_mesh_geometry(raw))
        except (OriginalGeometryBlocked, ValueError, KeyError, TypeError):
            return False
    if lane in IMAGE_LANES:
        return original_image(raw) is not None
    if lane in ('CONTROLLER_PROCESS', 'DEPENDENCY_READBACK',
                'SOURCE_PROVENANCE', 'ARCHITECTURAL_PLAN'):
        try:
            value = json.loads(raw)
            return type(value) is dict and bool(value)
        except (ValueError, UnicodeError, TypeError):
            return False
    return None

def assess(contract, work, packets, registered, source_loader):
    """Reopen exact original registered bytes for every supplied line witness.

    A positive result is *byte existence*, not semantic verification.
    Unverified YES is UNKNOWN, admitted NO is FAIL, missing lines are UNKNOWN.
    """
    need(type(contract) is dict and contract.get('schema') == SCHEMA and
         type(work) is dict and type(packets) is list and
         type(registered) is list and callable(source_loader),
         'R151_ORIGINAL_PROOF_SCHEMA')
    for key in ('master_sha256', 'attempt_id', 'operation_sha256'):
        need(type(work.get(key)) is str and
             HEX64.fullmatch(work[key]) is not None,
             'R151_EXACT_WORK_DIGEST:' + key)
    need(work['master_sha256'] == contract['master_sha256'],
         'R151_MASTER_CONTEXT_CHANGED')
    allowed = {}
    for item in registered:
        need(type(item) is tuple and len(item) == 4,
             'R151_REGISTERED_ARTIFACT_SCHEMA')
        role, path, checksum, raw = item
        need(type(role) is str and role and type(path) is str and path and
             type(raw) is bytes and raw and checksum == sha(raw),
             'R151_REGISTERED_ORIGINAL_BYTES_INVALID')
        need(path not in allowed, 'R151_DUPLICATE_ORIGINAL_ARTIFACT_PATH')
        allowed[path] = item
    expected = {}
    for rid in contract['selected']:
        for line in contract['rows'][rid]['lines']:
            expected[(rid, line['line_id'])] = line
    received = {}
    no = []
    format_positive = 0
    for packet in packets:
        need(type(packet) is dict and set(packet) == PACKET_FIELDS,
             'R151_LINE_PACKET_SCHEMA')
        rid, lid = packet['rule_id'], packet['line_id']
        key = (rid, lid)
        need(key in expected, 'R151_UNEXPECTED_SOURCE_LINE')
        need(key not in received, 'R151_DUPLICATE_SOURCE_LINE')
        row = contract['rows'][rid]
        line = expected[key]
        need(packet['line_sha256'] == line['line_sha256'] and
             packet['requirement_sha256'] == row['requirement_sha256'] and
             all(packet[k] == work[k] for k in
                 ('master_sha256', 'attempt_id', 'operation_sha256')),
             'R151_SOURCE_LINE_OR_ATTEMPT_REPLAY')
        need(packet['answer'] in ('YES', 'NO', 'UNKNOWN') and
             type(packet['answer']) is str,
             'R151_ANSWER_ENUM')
        lane = packet['source_lane']
        need(lane in row['required_independent_lanes'],
             'R151_UNRELATED_EVIDENCE_DOMAIN')
        path = packet['evidence_path']
        need(path in allowed, 'R151_NOT_REGISTERED_ORIGINAL_ARTIFACT')
        role, registered_path, checksum, original = allowed[path]
        need(role != ROLE and packet['evidence_role'] == role and
             packet['evidence_sha256'] == checksum and
             type(source_loader(path)) is bytes and
             source_loader(path) == original and sha(original) == checksum,
             'R151_ORIGINAL_EVIDENCE_REHASH_OR_ROLE_FAILED')
        format_probe = _native_format_probe(lane, original)
        format_positive += int(format_probe is True)
        received[key] = {
            'answer': packet['answer'],
            'evidence_role': role,
            'evidence_sha256': checksum,
            'source_lane': lane,
            'original_bytes_reopened': True,
            'format_probe_only': format_probe,
            'verdict': 'FAIL' if packet['answer'] == 'NO' else 'UNKNOWN',
            'full_source_semantics': 'UNKNOWN',
            'individual_mg0': 'UNKNOWN',
        }
        if packet['answer'] == 'NO':
            no.append(lid)
    missing = sorted(set(expected) - set(received))
    rule_status = {}
    for rid in contract['selected']:
        failed = any(k[0] == rid and v['verdict'] == 'FAIL'
                     for k, v in received.items())
        rule_status[rid] = 'FAIL' if failed else 'UNKNOWN'
    need(len(rule_status) == 200 and all(v in ('FAIL', 'UNKNOWN')
                                         for v in rule_status.values()),
         'R151_FALSE_FULL_RULE_SEMANTIC_PASS')
    return {
        'schema': SCHEMA,
        'source_rule_count': 200,
        'source_rule_ids_sha256': contract['source_rule_ids_sha256'],
        'all_composite_source_rules': 72,
        'source_lines_covered': contract['source_lines_covered'],
        'original_proof_packets_reopened': len(received),
        'machine_format_probes_positive_not_semantic': format_positive,
        'missing_source_line_witnesses': len(missing),
        'admitted_negative_line_ids': sorted(no),
        'rule_status': rule_status,
        'result': 'FAIL' if no else 'UNKNOWN',
        'full_rule_semantic_passes': 0,
        'individual_mg0_passes': 0,
        'owner_approval_verified': False,
        'advancement_authorized': False,
    }

def inspect(inventory, plan, controller, asset, step, work, *, source_loader):
    """Operational read-only intake: actual Controller and registered files."""
    contract = compile_contract(inventory, plan)
    need(type(work) is dict and
         work.get('master_sha256') == contract['master_sha256'] and
         type(asset) is str and asset == asset.upper() and
         type(step) is str and step,
         'R151_WORK_CONTEXT_REQUIRED')
    records, tail, state, audit_sha = _original_attempt(
        inventory, plan, controller, asset, step, work)
    need(state.get('last_audit_hash') == tail and
         (state.get('active_step') or {}).get('step') == step and
         sha(controller.master.read_bytes()) == contract['master_sha256'],
         'R151_ORIGINAL_CONTROLLER_DRIFT')
    registered = _registered_artifacts(records, state, step, source_loader, work)
    manifests = [x for x in registered if x[0] == ROLE]
    need(len(manifests) <= 1, 'R151_DUPLICATE_LINE_MANIFEST')
    packets = []
    if manifests:
        raw = manifests[0][3]
        need(len(raw) <= 8_000_000, 'R151_MANIFEST_SIZE')
        try:
            obj = json.loads(raw)
        except (UnicodeError, ValueError, TypeError) as exc:
            raise UnverifiedLineEvidence('R151_MANIFEST_JSON_INVALID') from exc
        need(type(obj) is dict and set(obj) == {
            'schema', 'master_sha256', 'attempt_id',
            'operation_sha256', 'source_rule_ids_sha256', 'packets'} and
             obj['schema'] == MANIFEST and
             all(obj.get(k) == work[k] for k in
                 ('master_sha256', 'attempt_id', 'operation_sha256')) and
             obj['source_rule_ids_sha256'] == contract['source_rule_ids_sha256'] and
             type(obj['packets']) is list,
             'R151_MANIFEST_NOT_EXACT_CURRENT_ATTEMPT')
        packets = obj['packets']
    result = assess(contract, work, packets, registered, source_loader)
    result.update({
        'asset': asset, 'step': step,
        'master_sha256': work['master_sha256'],
        'attempt_id': work['attempt_id'],
        'operation_sha256': work['operation_sha256'],
        'original_audit_sha256': audit_sha,
        'original_audit_tail': tail,
        'manifest_present': bool(manifests),
    })
    result['report_sha256'] = digest(result)
    return result

"""Verify frozen private governance blobs at the exact signed PR base SHA.

Candidate-only component; no network or repository mutation on import. Caller
provides an authenticated read-only, single-repository GitHub API client.
This guard is NOT a replacement for the canonical Library MASTER authority.
"""
import re

class Blocked(Exception):
    pass

# Exact blob identities observed on private main f11d7c4... after R149 release 2026-10-13.
# These are Git blob IDs, NOT canonical MASTER SHA256. Before production,
# regenerate only by explicitly reviewed protected release procedure.
TRUSTED_GOVERNANCE_BLOBS = {
    '.github/workflows/gg-phase-guard.yml': 'a438061bd8b00aa6cfa60a57c290d666d2e6bb8e',
    'governance/gg_phase_guard.py': 'dddb8230d4cedbd0f76bebbf5c74a511a0fd139b',
    'governance/gg_controlled_executor.py': '204f324b07245b264eab9c0ab8aec6db3d21e24b',
    'governance/gg_broker_service.py': '3cc211c33332c5886b05cbb4ef136e79f0b60501',
    'governance/test_gg_phase_guard.py': '11ecd21aff1e69583b954850a1e021ce54b17658',
    'governance/test_gg_controlled_executor.py': 'f676fc2ee2cd4643ab6cfe1dc0fd6eac342c6064',
    'governance/test_gg_broker_service.py': '0c1f5205765595d302b2e01feaac16a88aa30a4f',
    'governance/test_gg_broker_os_isolation.py': 'f55cb0b15b6d7cd3dadf36465f076e8c98022c3a',
    'governance/rule_family_registry.json': 'd0a74efd27bb6a39769b9b63abddc1224327e8b6',
    'governance/sources/GOLDEN_GARDEN_MASTER_RULES_AND_STATE.md': 'c26ae9c856550c361c3d1a777a0645b9a7d3634f',
}
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
# Sources and executable governance must not mutate in an automatically
# approved PR. Such a change needs an independent human-reviewed release.
FROZEN_PATTERNS = (
    re.compile(r'^\.github(?:/|$)', re.I),
    re.compile(r'^governance/(?:sources|tests|catalogs|policies)(?:/|$)', re.I),
    re.compile(r'^governance/(?:test_.*\.py|gg_(?:phase_guard|controlled_executor|broker_service|broker_os_isolation)\.py)$', re.I),
    re.compile(r'^governance/.*(?:_catalog|_registry|_policy)\.(?:json|py)$', re.I),
    re.compile(r'^governance/.*(?:MASTER|AAA)[^/]*\.(?:md|json)$', re.I),
)


def validate_no_authority_changes(files):
    if not isinstance(files, list) or not files:
        raise Blocked('AUTOMERGE_EMPTY_FILE_LIST')
    for item in files:
        if not isinstance(item, dict) or 'filename' not in item:
            raise Blocked('AUTOMERGE_BAD_FILE_ENTRY')
        for field in ('filename', 'previous_filename'):
            if field in item:
                name = item[field]
                if not isinstance(name, str) or not name or '\\' in name or '\x00' in name:
                    raise Blocked('AUTOMERGE_BAD_FILENAME')
                if any(pattern.search(name) for pattern in FROZEN_PATTERNS):
                    raise Blocked('AUTOMERGE_PROTECTED_SURFACE')
    return True


def validate_authority_blobs(api, signed_base_sha, *, anchors=TRUSTED_GOVERNANCE_BLOBS):
    if not isinstance(signed_base_sha, str) or not HEX40.fullmatch(signed_base_sha):
        raise Blocked('AUTOMERGE_BASE_ID_INVALID')
    if not isinstance(anchors, dict) or not anchors:
        raise Blocked('AUTOMERGE_ANCHORS_MISSING')
    for path, expected_sha in anchors.items():
        if path not in TRUSTED_GOVERNANCE_BLOBS or not isinstance(expected_sha, str) or not HEX40.fullmatch(expected_sha):
            raise Blocked('AUTOMERGE_ANCHOR_INVALID')
        response = api.call('GET', '/contents/' + path + '?ref=' + signed_base_sha)
        if not isinstance(response, dict) or response.get('type') != 'file' or response.get('path') != path:
            raise Blocked('AUTOMERGE_SOURCE_RECORD_INVALID')
        if response.get('sha') != expected_sha:
            raise Blocked('AUTOMERGE_SOURCE_DRIFT')
    return True

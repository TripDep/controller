#!/usr/bin/env python3
"""Pine Haven / Golden Garden: offline policy-to-MASTER authority alignment.

Checks actual bytes against policy snapshots without transporting the MASTER to
public GitHub. An aligned policy is necessary, not sufficient, for automatic
merging. This program NEVER mutates GitHub, Library, secrets or model assets.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

HEX40 = re.compile(r'^[0-9a-f]{40}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')

class Blocked(ValueError):
    pass


def unique_object_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Blocked('DUPLICATE_JSON_KEY:' + key)
        out[key] = value
    return out


def no_nonstandard(value):
    raise Blocked('NONSTANDARD_JSON_VALUE:' + value)


def strict_json(raw: bytes, *, max_size=200000):
    if not isinstance(raw, bytes) or len(raw) > max_size:
        raise Blocked('JSON_SIZE_OR_TYPE_INVALID')
    try:
        return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique_object_pairs,
                          parse_constant=no_nonstandard)
    except UnicodeError as exc:
        raise Blocked('JSON_ENCODING_INVALID') from exc


def sha256(raw: bytes):
    return hashlib.sha256(raw).hexdigest()


def master_revision(raw: bytes):
    if len(raw) < 100 or len(raw) > 3000000:
        raise Blocked('MASTER_BYTES_INVALID')
    try:
        value = raw.decode('utf-8')
    except UnicodeError as exc:
        raise Blocked('MASTER_ENCODING_INVALID') from exc
    entries = re.findall(r'(?m)^\*\*Revision:\*\*\s*(.+?)\s*$', value)
    if len(entries) != 1 or not entries[0].strip():
        raise Blocked('MASTER_REVISION_MISSING_OR_DUPLICATE')
    return entries[0].strip()


def normalize_pins(master_bytes: bytes, supervisor: dict, broker: dict,
                   private_master_bytes: bytes | None = None, *, private_action_pin: str | None = None):
    """Generate a precise offline *proposal*, never silently apply changes.

    The GitHub private source is a frozen snapshot, NOT the authority. If it
    does not match the Library, even a public policy SHA refresh cannot PASS.
    """
    if not isinstance(supervisor, dict) or not isinstance(broker, dict):
        raise Blocked('POLICY_STRUCTURE_INVALID')
    if supervisor.get('schema') != 'public-process-supervisor-v1':
        raise Blocked('SUPERVISOR_SCHEMA_INVALID')
    if broker.get('schema') != 'gg-git-broker-v1':
        raise Blocked('BROKER_SCHEMA_INVALID')
    for key, count in (('non_aaa_id_count',551),('aaa_count',200),('behavior_110_count',110)):
        if type(supervisor.get(key)) is not int or supervisor[key] != count:
            raise Blocked('SUPERVISOR_RULE_COUNT_CHANGED:' + key)
    if broker.get('enabled') is not False:
        raise Blocked('BROKER_MUST_REMAIN_DISABLED_DURING_ALIGNMENT')
    if broker.get('reviewer_public_key_sha256') is not None:
        raise Blocked('UNREVIEWED_REVIEWER_CHANGE')
    if broker.get('required_checks') != ['guard-tests','phase-guard','public-controller']:
        raise Blocked('REQUIRED_CHECKS_CHANGED')
    for name, value in (('supervisor.canonical_master_sha256',supervisor.get('canonical_master_sha256')),
                        ('broker.master_sha256',broker.get('master_sha256'))):
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            raise Blocked('INVALID_POLICY_HASH:' + name)
    for name in ('repository_sha256',):
        if not isinstance(broker.get(name), str) or not HEX64.fullmatch(broker[name]):
            raise Blocked('BROKER_TARGET_INVALID')
    if not isinstance(broker.get('public_controller_sha'),str) or not HEX40.fullmatch(broker['public_controller_sha']):
        raise Blocked('PUBLIC_CONTROLLER_PIN_INVALID')
    if broker.get('base_branch') != 'main':
        raise Blocked('UNTRUSTED_BASE_BRANCH')
    revision = master_revision(master_bytes)
    canonical_sha = sha256(master_bytes)
    copy_sha = sha256(private_master_bytes) if private_master_bytes is not None else None
    private_alignment = 'MATCH' if copy_sha == canonical_sha else ('MISMATCH' if copy_sha else 'UNKNOWN')
    current_public = supervisor['canonical_master_sha256'] == canonical_sha
    current_broker = broker['master_sha256'] == canonical_sha
    if private_action_pin is not None and (not isinstance(private_action_pin,str) or not HEX40.fullmatch(private_action_pin)):
        raise Blocked('PRIVATE_WORKFLOW_PIN_INVALID')
    action_match = (private_action_pin == broker['public_controller_sha']) if private_action_pin else None
    report = {
        'schema': 'pinehaven-broker-authority-alignment-v4',
        'master_revision': revision,
        'canonical_library_master_sha256': canonical_sha,
        'private_source_sha256': copy_sha,
        'private_source_alignment': private_alignment,
        'public_supervisor_sha_match': current_public,
        'public_broker_sha_match': current_broker,
        'private_workflow_public_action_sha': private_action_pin,
        'action_pin_match': action_match,
        'proposed_metadata_only': {
            'supervisor/policy.json': {'canonical_master_sha256':canonical_sha},
            'broker/broker_policy.json': {'master_sha256':canonical_sha,'enabled':False},
        },
        'must_keep': {
            'broker_enabled':False,
            'assets_on_github':False,
            'private_repo_public':False,
            'extra_cost':False,
            'immutable_public_action_sha':broker['public_controller_sha'],
        },
        'status': ('ALIGNED_METADATA_ONLY' if (private_alignment=='MATCH' and current_public and current_broker and action_match is True)
                   else ('BLOCKED_CONTROLLER_PIN_DRIFT' if private_alignment=='MATCH' and current_public and current_broker and action_match is False
                   else 'BLOCKED_SOURCE_DRIFT')),
        'independent_auto_merge_authorized':False,
        'note': ('Do not update public SHA alone while private snapshot is stale. '
                 'Do not mistake matching SHA for protection of private main.')
    }
    return report


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--library-master',type=Path,required=True)
    p.add_argument('--public-supervisor-policy',type=Path,required=True)
    p.add_argument('--public-broker-policy',type=Path,required=True)
    p.add_argument('--private-master-snapshot',type=Path)
    p.add_argument('--private-workflow-action-sha',type=str)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        private=a.private_master_snapshot.read_bytes() if a.private_master_snapshot else None
        report=normalize_pins(a.library_master.read_bytes(),
             strict_json(a.public_supervisor_policy.read_bytes()),
             strict_json(a.public_broker_policy.read_bytes()),private,private_action_pin=a.private_workflow_action_sha)
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
        print(report['status'])
        return 0 if report['status']=='ALIGNED_METADATA_ONLY' else 2
    except (Blocked,OSError,ValueError,TypeError) as exc:
        print('BLOCKED:',str(exc))
        return 2

if __name__=='__main__':
    raise SystemExit(main())

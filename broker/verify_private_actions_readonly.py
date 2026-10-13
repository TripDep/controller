#!/usr/bin/env python3
"""One-time PRIVATE Actions:read permission and frozen-workflow proof.

READ ONLY: GET repository installation, GET workflow metadata and GET pinned
workflow blob. Never prints private repo name, keys, response bodies or tokens.
It does not authorize, stage, or execute any Git merge.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from urllib import request, error

API = 'https://api.github.com'
WORKFLOW = '.github/workflows/gg-phase-guard.yml'
# Verified GitHub blob on private main after the coordinated R149 release.
EXPECTED_BLOB = 'a438061bd8b00aa6cfa60a57c290d666d2e6bb8e'
# Identity sha256 from owner's existing disabled protected broker policy.
TARGET_SHA256 = 'ba6c371db01f88a9a16e02a03d673f320bd3c04adc3ebdff97b2ef102a188e70'
REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')

class Blocked(Exception):
    pass

def validate_installation(record):
    if not isinstance(record, dict) or type(record.get('total_count')) is not int or record['total_count'] != 1:
        raise Blocked('INSTALLATION_NOT_SINGLE_REPOSITORY')
    rows=record.get('repositories')
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise Blocked('INSTALLATION_RESULT_INCOMPLETE')
    repo=rows[0]
    name=repo.get('full_name')
    if not isinstance(name, str) or not REPO.fullmatch(name) or repo.get('private') is not True:
        raise Blocked('INSTALLATION_TARGET_INVALID')
    if hashlib.sha256(name.encode('utf-8')).hexdigest() != TARGET_SHA256:
        raise Blocked('INSTALLATION_PIN_MISMATCH')
    return name

def validate_actions_record(item):
    if not isinstance(item, dict) or type(item.get('id')) is not int or item['id'] <= 0:
        raise Blocked('PRIVATE_ACTIONS_DATA_MISSING')
    if item.get('path') != WORKFLOW or item.get('state') != 'active':
        raise Blocked('PRIVATE_ACTIONS_WORKFLOW_NOT_TRUSTED')
    return True

def validate_source_blob(item):
    if not isinstance(item,dict) or item.get('type')!='file' or item.get('path')!=WORKFLOW:
        raise Blocked('SOURCE_BLOB_RECORD_INVALID')
    if item.get('sha')!=EXPECTED_BLOB:
        raise Blocked('SOURCE_BLOB_CHANGED')
    return True

def get_json(relative_url, token):
    if not isinstance(relative_url,str) or not relative_url.startswith('/') or '://' in relative_url:
        raise Blocked('API_ROUTE_NOT_ALLOWED')
    req=request.Request(API+relative_url, headers={
        'Accept':'application/vnd.github+json',
        'Authorization':'Bearer '+token,
        'X-GitHub-Api-Version':'2022-11-28',
        'User-Agent':'pinehaven-private-actions-readonly-preflight'
    }, method='GET')
    try:
        with request.urlopen(req,timeout=20) as res:
            data=res.read(100000)
    except (OSError,error.HTTPError,error.URLError) as exc:
        raise Blocked('READ_ONLY_API_NOT_AUTHORIZED_OR_UNAVAILABLE') from exc
    try:
        return json.loads(data.decode('utf-8'))
    except (ValueError, UnicodeError) as exc:
        raise Blocked('API_JSON_INVALID') from exc

def run(getter=get_json):
    if os.environ.get('GITHUB_REPOSITORY')!='TripDep/controller' or os.environ.get('GITHUB_REF')!='refs/heads/main':
        raise Blocked('NOT_PROTECTED_PUBLIC_MAIN')
    token=os.environ.get('BROKER_APP_TOKEN')
    if not isinstance(token,str) or len(token)<20:
        raise Blocked('APP_TOKEN_UNAVAILABLE')
    repo=validate_installation(getter('/installation/repositories?per_page=2',token))
    validate_actions_record(getter('/repos/'+repo+'/actions/workflows/gg-phase-guard.yml',token))
    validate_source_blob(getter('/repos/'+repo+'/contents/'+WORKFLOW+'?ref=main',token))
    print('PASS: SINGLE PINNED PRIVATE ACTIONS WORKFLOW READABLE; SOURCE BLOB PIN MATCHED; NO WRITE/MERGE.')
    return True

if __name__=='__main__':
    try:
        run()
    except (Blocked, ValueError, TypeError, KeyError) as exc:
        print('BLOCKED: '+(str(exc) if isinstance(exc,Blocked) else type(exc).__name__),file=sys.stderr)
        raise SystemExit(1)
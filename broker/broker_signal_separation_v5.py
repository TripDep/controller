#!/usr/bin/env python3
"""Read-only GG_RUN_DONE signal triage, separated from Git merge authorizations.

Consumes a *complete* GitHub pull-request snapshot supplied by a trusted caller.
This code never dispatches a workflow, merges, resets a clock, or emits an
approval token. Historical PRs are not proof that a webhook was delivered.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

TRUSTED_PRIVATE_REPO = 'TripDep/SERVE-PER-FARTI-LAVORARE-'
SHA40 = re.compile(r'^[0-9a-f]{40}$')
PR_URL = re.compile(r'^https://github\.com/TripDep/SERVE-PER-FARTI-LAVORARE-/pull/([1-9]\d*)$')

class Blocked(ValueError):
    pass


def pairs_strict(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise Blocked('DUPLICATE_JSON_KEY')
        result[name] = value
    return result


def reject_nonfinite(_):
    raise Blocked('NONFINITE_JSON_VALUE')


def read_snapshot(path: Path, max_size: int = 300_000) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_size:
        raise Blocked('SNAPSHOT_FILE_INVALID')
    try:
        data = json.loads(path.read_bytes().decode('utf-8'), object_pairs_hook=pairs_strict,
                          parse_constant=reject_nonfinite)
    except (UnicodeError, ValueError) as exc:
        raise Blocked('SNAPSHOT_JSON_INVALID') from exc
    if not isinstance(data, dict):
        raise Blocked('SNAPSHOT_NOT_OBJECT')
    return data


def classify(snapshot: dict) -> dict:
    if not isinstance(snapshot, dict) or snapshot.get('schema') != 'pinehaven-github-pr-readonly-v1':
        raise Blocked('SNAPSHOT_SCHEMA_INVALID')
    if snapshot.get('repository') != TRUSTED_PRIVATE_REPO:
        raise Blocked('WRONG_PRIVATE_REPOSITORY')
    if snapshot.get('default_branch') != 'main':
        raise Blocked('DEFAULT_BRANCH_INVALID')
    main = snapshot.get('current_main_sha')
    if not isinstance(main, str) or not SHA40.fullmatch(main):
        raise Blocked('PRIVATE_MAIN_SHA_INVALID')
    if snapshot.get('private_main_protected') is not False:
        raise Blocked('PRIVATE_PROTECTION_CLAIM_UNVERIFIED')
    prs = snapshot.get('pull_requests')
    if not isinstance(prs, list) or len(prs) > 100:
        raise Blocked('PR_LIST_INVALID_OR_INCOMPLETE')
    total = snapshot.get('total_open_count')
    if type(total) is not int or total != len(prs):
        raise Blocked('PR_LIST_NOT_COMPLETE')
    numbers = set()
    signals, others = [], []
    for pr in prs:
        if not isinstance(pr, dict):
            raise Blocked('PR_NOT_OBJECT')
        number = pr.get('number')
        if type(number) is not int or number < 1 or number > 100_000_000 or number in numbers:
            raise Blocked('PR_NUMBER_INVALID_OR_DUPLICATE')
        numbers.add(number)
        title = pr.get('title')
        if not isinstance(title, str) or not (1 <= len(title) <= 500):
            raise Blocked('PR_TITLE_INVALID')
        if pr.get('state') != 'open' or type(pr.get('draft')) is not bool:
            raise Blocked('PR_STATE_UNVERIFIED')
        if pr.get('head_repo') != TRUSTED_PRIVATE_REPO or pr.get('base_repo') != TRUSTED_PRIVATE_REPO:
            raise Blocked('PR_CROSS_REPO_UNVERIFIED')
        if pr.get('base_ref') != 'main':
            raise Blocked('PR_TARGET_BRANCH_INVALID')
        base, head = pr.get('base_sha'), pr.get('head_sha')
        if not isinstance(base, str) or not SHA40.fullmatch(base) or not isinstance(head, str) or not SHA40.fullmatch(head):
            raise Blocked('PR_COMMIT_SHA_INVALID')
        url = pr.get('url')
        match = PR_URL.fullmatch(url) if isinstance(url, str) else None
        if match is None or int(match.group(1)) != number:
            raise Blocked('PR_URL_INVALID')
        stale = base != main
        if title.startswith('GG_RUN_DONE'):
            # The prefix is an event selector, NEVER a signature or a merge authorization.
            event_id = hashlib.sha256((TRUSTED_PRIVATE_REPO+'\n'+str(number)+'\n'+head).encode()).hexdigest()
            signals.append({'pr_number': number, 'url': url, 'title': title,
                            'event_id_sha256':event_id, 'base_matches_current_main':not stale,
                            'category':'SIGNAL_ONLY', 'merge_authorized':False,
                            'event_received_by_monitor':'NOT_PROVEN',
                            'timer_reset':'NOT_PERFORMED'})
        else:
            others.append({'pr_number':number,'url':url,'base_matches_current_main':not stale,
                           'category':'REQUIRES_FULL_BROKER_REVIEW','merge_authorized':False})
    return {'schema':'pinehaven-broker-signal-separation-v5',
            'repository': TRUSTED_PRIVATE_REPO, 'observed_private_main_sha':main,
            'signals':sorted(signals,key=lambda p:p['pr_number']),
            'other_prs':sorted(others,key=lambda p:p['pr_number']),
            'signal_count':len(signals),'other_count':len(others),
            'stale_signals':sum(1 for p in signals if not p['base_matches_current_main']),
            'broker_merge_authorized':False,'github_mutation_performed':False,
            'monitor_event_delivery':'UNVERIFIED', 'private_main_protected':False,
            'interpretation':'Presence of GG_RUN_DONE pull requests is NOT proof of monitor activation or broker merge readiness.'}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--snapshot',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    a=ap.parse_args(argv)
    try:
        result = classify(read_snapshot(a.snapshot))
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8')
        print('PASS_SIGNAL_TRIAGE_ONLY; MERGE_NOT_AUTHORIZED; MONITOR_NOT_PROVEN; SIGNALS='+str(result['signal_count']))
        return 0
    except (Blocked,OSError,TypeError) as exc:
        print('BLOCKED:'+str(exc),file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())

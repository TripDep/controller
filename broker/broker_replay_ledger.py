"""Atomic nonce-claim concept using GitHub create-ref, candidate ONLY.

A claim remains as an immutable-to-the-broker ref after any failure. A failed
network response may mean the claim succeeded: FAIL CLOSED, never retry with
same nonce. GitHub private writers with delete-ref permission can still erase
claims, so this is NOT production protection until privilege separation.
"""
import hashlib
import json
import re

class Blocked(Exception):
    pass

HEX40 = re.compile(r'[0-9a-f]{40}\Z')
NONCE = re.compile(r'[A-Za-z0-9_-]{16,80}\Z')
PREFIX = 'refs/heads/gg-broker-claims/'


def claim_name(authorization):
    if not isinstance(authorization, dict) or not isinstance(authorization.get('nonce'), str) or not NONCE.fullmatch(authorization['nonce']):
        raise Blocked('NONCE_INVALID')
    for field in ('repository', 'pr_number', 'head_sha', 'base_sha', 'master_sha256', 'public_controller_sha', 'decision', 'expires_at'):
        if field not in authorization:
            raise Blocked('AUTH_INCOMPLETE')
    sha = authorization['head_sha']
    if not isinstance(sha, str) or not HEX40.fullmatch(sha):
        raise Blocked('HEAD_SHA_INVALID')
    # Claim depends only on repository+nonce so reusing the nonce with altered
    # PR fields cannot create another one-time claim.
    repo = authorization['repository']
    if not isinstance(repo, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise Blocked('REPOSITORY_INVALID')
    raw = ('pinehaven-nonce-v1\0' + repo + '\0' + authorization['nonce']).encode('utf-8')
    return PREFIX + hashlib.sha256(raw).hexdigest()


def claim_once(api, authorization):
    ref = claim_name(authorization)
    try:
        result = api.call('POST', '/git/refs', {'ref': ref, 'sha': authorization['head_sha']})
    except Exception as exc:
        # Includes 422 from GitHub duplicate reference and all ambiguous writes.
        raise Blocked('NONCE_CLAIM_FAILED_OR_ALREADY_USED') from exc
    if not isinstance(result, dict) or result.get('ref') != ref or result.get('object', {}).get('sha') != authorization['head_sha']:
        raise Blocked('NONCE_CLAIM_UNVERIFIED')
    return ref


def verify_pr_still_fresh(api, authorization):
    fresh = api.call('GET', f"/pulls/{authorization['pr_number']}")
    base = api.call('GET', '/branches/main')
    if not isinstance(fresh, dict) or not isinstance(base, dict):
        raise Blocked('FINAL_REVALIDATION_INCOMPLETE')
    if (fresh.get('state') != 'open' or fresh.get('draft') is not False or
            fresh.get('mergeable') is not True or fresh.get('head', {}).get('sha') != authorization['head_sha'] or
            fresh.get('base', {}).get('sha') != authorization['base_sha'] or
            base.get('commit', {}).get('sha') != authorization['base_sha']):
        raise Blocked('PR_CHANGED_BEFORE_MERGE')
    return True

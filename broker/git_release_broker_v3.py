#!/usr/bin/env python3
"""Hardened Git governance candidate v3: no deployment or live merge authorized.

Extends v2 with per-base trusted blob pins, frozen security surfaces, one-time
nonce refs and final PR/base revalidation. GitHub policy is disabled. The code
remains a test candidate held in Library, not an installed Actions broker.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
import argparse

import git_release_broker_v2 as b
from git_release_broker_v2 import Blocked
from workflow_provenance_gate import Blocked as ProvenanceBlocked, checked_same_trusted_run, prohibit_workflow_mutations
from broker_trust_anchors import Blocked as AnchorBlocked, validate_no_authority_changes, validate_authority_blobs
from broker_replay_ledger import Blocked as ReplayBlocked, claim_once, verify_pr_still_fresh


def approve_and_merge_v3(policy, auth, signature, key_path, api):
    # Signature verification uses the pinned external Ed25519 public key.
    b.verify_owner_signature(auth, signature, key_path, policy['reviewer_public_key_sha256'])
    pr, base, files, checks = api.snapshot(auth['pr_number'], auth['head_sha'])
    b.validate_snapshot(policy, auth, pr, base, files, checks)
    try:
        # Important: PR jobs execute code from the PR branch. Security sources
        # are fixed and the immutable base code is re-attested via GitHub API.
        validate_no_authority_changes(files)
        prohibit_workflow_mutations(files)
        validate_authority_blobs(api, auth['base_sha'])
        checked_same_trusted_run(api, auth['repository'], auth['head_sha'], auth['pr_number'], checks)
        # A durable CREATE, before merge: failed/uncertain responses consume
        # the nonce. Never DELETE a claim after merge failure.
        claim_once(api, auth)
        verify_pr_still_fresh(api, auth)
    except (AnchorBlocked, ProvenanceBlocked, ReplayBlocked) as exc:
        raise Blocked('V3_SECURITY_PRECONDITION_FAILED:' + str(exc)) from exc
    result = api.merge(auth['pr_number'], auth['head_sha'])
    if not isinstance(result, dict) or result.get('merged') is not True:
        raise Blocked('V3_MERGE_NOT_CONFIRMED')
    return {'status': 'MERGED', 'pr_number': auth['pr_number'], 'merge_sha': result.get('sha')}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', type=Path, default=b.POLICY_FILE)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--reviewer-public-key', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    try:
        policy = b.read_policy(args.policy)  # default enabled=false -> STOP
        auth, sig = b.read_request(args.request)
        if not args.execute:
            raise Blocked('BROKER_DRY_RUN_ONLY_NO_NETWORK_OR_MERGE')
        if os.environ.get('GITHUB_REPOSITORY') != b.PUBLIC_REPO or os.environ.get('GITHUB_REF') != 'refs/heads/main':
            raise Blocked('BROKER_NOT_IN_PROTECTED_PUBLIC_MAIN')
        api = b.GitHubAPI(os.environ.get('BROKER_GITHUB_APP_TOKEN'), auth['repository'])
        result = approve_and_merge_v3(policy, auth, sig, args.reviewer_public_key, api)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Blocked, KeyError, ValueError, TypeError, OSError) as exc:
        print('BROKER_BLOCKED:' + (str(exc) if isinstance(exc, Blocked) else type(exc).__name__), file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())

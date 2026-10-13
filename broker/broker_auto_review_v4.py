#!/usr/bin/env python3
"""Pine Haven: automatic, no-human routine PR eligibility preflight.

Reuses v3's GitHub Actions provenance and frozen-authority checks. This module
DOES NOT MERGE, CREATE NONCES, OR SET POLICY ENABLED. A synthetic/automated
eligibility result cannot replace the owner-side write-isolation guarantee.
Only trusted public-protected runners may later use this as part of a broker.
"""
from __future__ import annotations
import hashlib
import re

import git_release_broker_v2 as base
from workflow_provenance_gate import checked_same_trusted_run, prohibit_workflow_mutations, Blocked as ProvenanceBlocked
from broker_trust_anchors import validate_authority_blobs, validate_no_authority_changes, Blocked as AnchorBlocked
from broker_authority_alignment_v4 import normalize_pins

class Blocked(ValueError):
    pass


def public_boundary(public_branch, ruleset, pinned_main):
    """Use GitHub API records; a caller-supplied boolean is not sufficient."""
    if not isinstance(public_branch,dict) or public_branch.get('protected') is not True:
        raise Blocked('PUBLIC_MAIN_NOT_PROTECTED')
    if public_branch.get('name')!='main' or public_branch.get('commit',{}).get('sha')!=pinned_main:
        raise Blocked('PUBLIC_MAIN_MOVED')
    if not isinstance(ruleset,dict) or ruleset.get('enforcement')!='active':
        raise Blocked('PUBLIC_RULESET_NOT_ACTIVE')
    if ruleset.get('bypass_actors')!=[]:
        raise Blocked('PUBLIC_RULESET_BYPASS_PRESENT_OR_UNKNOWN')
    rules=ruleset.get('rules')
    if not isinstance(rules,list):
        raise Blocked('PUBLIC_RULESET_INVALID')
    types={x.get('type') for x in rules if isinstance(x,dict)}
    if not {'pull_request','required_status_checks','non_fast_forward','deletion'} <= types:
        raise Blocked('PUBLIC_RULESET_INSUFFICIENT')
    checks=[x for x in rules if x.get('type')=='required_status_checks']
    if len(checks)!=1:
        raise Blocked('PUBLIC_STATUS_RULE_AMBIGUOUS')
    required=checks[0].get('parameters',{}).get('required_status_checks')
    if not isinstance(required,list) or not any(x.get('context')=='selftests' for x in required if isinstance(x,dict)):
        raise Blocked('PUBLIC_REQUIRED_SELFTESTS_MISSING')
    return True


def assess_routine_eligibility(*, canonical_master:bytes, private_master:bytes,
    supervisor_policy:dict, broker_policy:dict, public_branch:dict, public_ruleset:dict,
    private_api, pr_number:int, pinned_public_main_sha:str, private_workflow_action_sha:str):
    """Auto-evaluate an ordinary PR; NEVER emit a merge-authorizing token.

    This proves an eligible *candidate* given trusted APIs and canonical bytes.
    It intentionally does not authorize or execute a merge. Source changes and
    stale policies fail closed; master bytes never leave the trusted runtime.
    """
    alignment=normalize_pins(canonical_master,supervisor_policy,broker_policy,private_master,private_action_pin=private_workflow_action_sha)
    if alignment['status']!='ALIGNED_METADATA_ONLY':
        raise Blocked('LIBRARY_MASTER_OR_POLICY_DRIFT')
    public_boundary(public_branch,public_ruleset,pinned_public_main_sha)
    if type(pr_number) is not int or not (1<=pr_number<=100000000):
        raise Blocked('PR_ID_INVALID')
    pr=private_api.call('GET',f'/pulls/{pr_number}')
    if not isinstance(pr,dict):
        raise Blocked('PR_RECORD_INVALID')
    head=pr.get('head',{}).get('sha')
    if not isinstance(head,str) or not re.fullmatch(r'[0-9a-f]{40}',head):
        raise Blocked('HEAD_SHA_INVALID')
    pr_snapshot, base_branch, files, check_runs=private_api.snapshot(pr_number,head)
    repo=pr.get('head',{}).get('repo',{}).get('full_name')
    auth={'repository':repo,'pr_number':pr_number,'head_sha':head,
          'base_sha':pr.get('base',{}).get('sha'),
          'master_sha256':alignment['canonical_library_master_sha256'],
          'public_controller_sha':broker_policy['public_controller_sha']}
    try:
        base.validate_snapshot(broker_policy,auth,pr_snapshot,base_branch,files,check_runs)
        validate_no_authority_changes(files)
        prohibit_workflow_mutations(files)
        validate_authority_blobs(private_api,auth['base_sha'])
        checked_same_trusted_run(private_api,repo,head,pr_number,check_runs)
    except (base.Blocked,ProvenanceBlocked,AnchorBlocked,ValueError,TypeError,KeyError,AttributeError) as exc:
        raise Blocked('ROUTINE_GATE_FAILED:'+type(exc).__name__+':'+str(exc)) from exc
    # Deliberately not return APPROVED / MERGED. Direct-writer isolation is NOT
    # proven by PR checks. A protected public runner must attest this separately.
    return {'status':'ROUTINE_PRECHECK_PASS_ONLY', 'merge_authorized':False,
            'broker_enabled':False, 'private_write_isolation_verified':False,
            'master_sha256':alignment['canonical_library_master_sha256'],
            'pr_number':pr_number,'pr_head_sha':head,
            'public_controller_sha':broker_policy['public_controller_sha'],
            'remaining':'PRIVATE_WRITE_ISOLATION_AND_TRUSTED_RUNNER_NOT_ESTABLISHED'}

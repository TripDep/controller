#!/usr/bin/env python3
"""Read-only GitHub App installation scope check; no merge/write API is used.

This script is intentionally not the operational Git merge broker. It uses
a short-lived GitHub App installation token restricted to read permissions.
Do not print the token, private repo name, repository metadata or secrets.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib import request, error

POLICY_PATH = Path(__file__).with_name("broker_policy.json")
INSTALLATION_URL = "https://api.github.com/installation/repositories?per_page=2"

class Blocked(Exception):
    pass

def verify_installation(data, expected_sha256):
    if not isinstance(data, dict):
        raise Blocked("INSTALLATION_RESPONSE_INVALID")
    if data.get("total_count") != 1:
        raise Blocked("INSTALLATION_SCOPE_NOT_SINGLE_REPO")
    repos = data.get("repositories")
    if not isinstance(repos, list) or len(repos) != 1:
        raise Blocked("INSTALLATION_SCOPE_INCOMPLETE")
    item = repos[0]
    if not isinstance(item, dict) or item.get("private") is not True:
        raise Blocked("INSTALLATION_TARGET_NOT_PRIVATE")
    fullname = item.get("full_name")
    if not isinstance(fullname, str):
        raise Blocked("INSTALLATION_NAME_INVALID")
    actual = hashlib.sha256(fullname.encode("utf-8")).hexdigest()
    if actual != expected_sha256:
        raise Blocked("INSTALLATION_TARGET_MISMATCH")
    return True

def verify_environment():
    if os.environ.get("GITHUB_REPOSITORY") != "TripDep/controller":
        raise Blocked("PUBLIC_ORIGIN_MISMATCH")
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise Blocked("PROTECTED_MAIN_REQUIRED")

def verify_policy(policy):
    if policy.get("schema") != "gg-git-broker-v1":
        raise Blocked("BROKER_POLICY_INVALID")
    if policy.get("enabled") is not False or policy.get("reviewer_public_key_sha256") is not None:
        raise Blocked("BROKER_MUST_REMAIN_UNARMED_FOR_READONLY_PROOF")
    digest = policy.get("repository_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise Blocked("BROKER_TARGET_HASH_INVALID")
    return digest

def verify_readonly_access():
    verify_environment()
    digest = verify_policy(json.loads(POLICY_PATH.read_text(encoding="utf-8")))
    token = os.environ.get("BROKER_APP_TOKEN")
    if not isinstance(token, str) or len(token) < 20:
        raise Blocked("PROTECTED_APP_TOKEN_NOT_CONFIGURED")
    http_req = request.Request(
        INSTALLATION_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "pinehaven-broker-scope-proof",
        },
        method="GET",
    )
    try:
        with request.urlopen(http_req, timeout=20) as response:
            raw = response.read(200000)
    except (OSError, error.HTTPError, error.URLError) as exc:
        raise Blocked("INSTALLATION_READONLY_API_UNAVAILABLE") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise Blocked("INSTALLATION_RESPONSE_NOT_JSON") from exc
    verify_installation(data, digest)
    print("PASS: ONE PINNED PRIVATE INSTALLATION VERIFIED (READ ONLY). NO MERGE OR ASSET PASS.")

if __name__ == "__main__":
    try:
        verify_readonly_access()
    except (Blocked, ValueError, OSError, KeyError, TypeError) as err:
        # Failure reasons are codes only; never echo secret material or private names.
        print("BLOCKED: " + (str(err) if isinstance(err, Blocked) else type(err).__name__), file=sys.stderr)
        raise SystemExit(1)

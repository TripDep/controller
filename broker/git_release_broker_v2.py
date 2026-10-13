#!/usr/bin/env python3
"""Owner-gated GitHub PR merge broker, NOT a ChatGPT work/3D-asset broker.

This is a CANDIDATE. It is permanently fail-closed until the policy in the
protected public repository is explicitly armed by its owner, and an external
Ed25519 reviewer public key is enrolled. GitHub App installation credentials
must ONLY exist in a separately reviewed/protected GitHub environment, never
in this repository, a chat session, or the producer's CI.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib import request, error

from workflow_provenance_gate import (
    Blocked as ProvenanceBlocked,
    checked_same_trusted_run,
    prohibit_workflow_mutations,
)

PUBLIC_REPO = "TripDep/controller"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_CHECKS = ("guard-tests", "phase-guard", "public-controller")
ASSET_SUFFIXES = (".blend", ".blend1", ".blend2", ".glb", ".gltf", ".fbx", ".obj",
                  ".ydr", ".ytd", ".ybn", ".ymap", ".ytyp", ".ydd", ".dds",
                  ".png", ".jpg", ".jpeg", ".webp", ".psd", ".zip", ".7z", ".rar")
ALLOWED_ROOTS = ("governance/", ".github/workflows/")
ALLOWED_FILES = {"README.md", "README_IT.md", "test_event_controller.py", "gg_event_controller.py"}
POLICY_FILE = Path(__file__).with_name("broker_policy.json")


class Blocked(Exception):
    pass


def strict_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            stop("JSON_DUPLICATE_KEY")
        obj[key] = value
    return obj


def strict_json_file(path, maximum=8192):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        stop("BROKER_CONFIG_FILE_UNSAFE")
    data = p.read_bytes()
    if len(data) > maximum:
        stop("BROKER_CONFIG_FILE_TOO_LARGE")
    def reject_constant(_value):
        stop("BROKER_JSON_NONFINITE_NUMBER")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=strict_pairs,
                          parse_constant=reject_constant)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Blocked("BROKER_JSON_INVALID") from exc


def stop(reason: str):
    raise Blocked(reason)


def sha256(data: bytes):
    return hashlib.sha256(data).hexdigest()


def canonical(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def read_policy(path=POLICY_FILE):
    policy = strict_json_file(path)
    if set(policy) != {"schema", "enabled", "repository_sha256", "base_branch", "master_sha256",
                       "public_controller_sha", "reviewer_public_key_sha256", "required_checks"}:
        stop("BROKER_POLICY_SCHEMA_INVALID")
    if policy["schema"] != "gg-git-broker-v1" or policy["base_branch"] != "main":
        stop("BROKER_POLICY_SCOPE_INVALID")
    if not isinstance(policy["repository_sha256"], str) or not HEX64.fullmatch(policy["repository_sha256"]):
        stop("BROKER_REPOSITORY_PIN_MISSING")
    if policy["enabled"] is not True:  # bool, rather than truthy string
        stop("BROKER_NOT_ARMED")
    if policy["required_checks"] != list(REQUIRED_CHECKS):
        stop("BROKER_REQUIRED_CHECKS_MISMATCH")
    if not isinstance(policy["master_sha256"], str) or not HEX64.fullmatch(policy["master_sha256"]):
        stop("BROKER_MASTER_PIN_MISSING")
    if not isinstance(policy["public_controller_sha"], str) or not HEX40.fullmatch(policy["public_controller_sha"]):
        stop("BROKER_CONTROLLER_PIN_MISSING")
    if not isinstance(policy["reviewer_public_key_sha256"], str) or not HEX64.fullmatch(policy["reviewer_public_key_sha256"]):
        stop("REVIEWER_NOT_ENROLLED")
    return policy


def read_request(path):
    envelope = strict_json_file(path)
    if not isinstance(envelope, dict) or set(envelope) != {"authorization", "signature_base64"}:
        stop("BROKER_REQUEST_SCHEMA_INVALID")
    auth = envelope["authorization"]
    if not isinstance(auth, dict) or set(auth) != {"schema", "repository", "pr_number", "head_sha",
                                                      "base_sha", "master_sha256", "public_controller_sha",
                                                      "decision", "expires_at", "nonce"}:
        stop("BROKER_AUTHORIZATION_FIELDS_INVALID")
    if auth["schema"] != "gg-owner-reviewed-pr-v1" or auth["decision"] != "APPROVE_MERGE":
        stop("BROKER_AUTHORIZATION_SCOPE_INVALID")
    if not isinstance(auth["repository"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", auth["repository"]):
        stop("BROKER_REPOSITORY_INVALID")
    if type(auth["pr_number"]) is not int or not (1 <= auth["pr_number"] <= 100000000):
        stop("BROKER_PR_NUMBER_INVALID")
    for name in ("head_sha", "base_sha", "public_controller_sha"):
        if not isinstance(auth[name], str) or not HEX40.fullmatch(auth[name]):
            stop("BROKER_COMMIT_ID_INVALID:" + name)
    if not isinstance(auth["master_sha256"], str) or not HEX64.fullmatch(auth["master_sha256"]):
        stop("BROKER_MASTER_ID_INVALID")
    if not isinstance(auth["nonce"], str) or not re.fullmatch(r"[a-zA-Z0-9_-]{16,80}", auth["nonce"]):
        stop("BROKER_NONCE_INVALID")
    if not isinstance(auth["expires_at"], str) or not auth["expires_at"].endswith("Z"):
        stop("BROKER_EXPIRY_INVALID")
    try:
        expires = datetime.fromisoformat(auth["expires_at"].replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise Blocked("BROKER_EXPIRY_INVALID") from exc
    if not datetime.now(timezone.utc) < expires or (expires - datetime.now(timezone.utc)).total_seconds() > 86400:
        stop("BROKER_APPROVAL_EXPIRED_OR_TOO_LONG")
    signature = envelope["signature_base64"]
    if not isinstance(signature, str) or len(signature) > 500:
        stop("BROKER_SIGNATURE_INVALID")
    try:
        value = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Blocked("BROKER_SIGNATURE_INVALID") from exc
    if len(value) != 64:
        stop("BROKER_SIGNATURE_INVALID")
    return auth, value


def verify_owner_signature(auth, signature, public_key_path, expected_key_hash):
    key = Path(public_key_path)
    if key.is_symlink() or not key.is_file():
        stop("REVIEWER_PUBLIC_KEY_MISSING")
    key_data = key.read_bytes()
    if sha256(key_data) != expected_key_hash:
        stop("REVIEWER_KEY_PIN_MISMATCH")
    with tempfile.TemporaryDirectory(prefix="gg-git-review-") as temp:
        payload = Path(temp) / "reviewed.json"
        sigfile = Path(temp) / "signature.bin"
        payload.write_bytes(canonical(auth))
        sigfile.write_bytes(signature)
        try:
            outcome = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                                      "-inkey", str(key.resolve()), "-rawin", "-in", str(payload),
                                      "-sigfile", str(sigfile)], capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise Blocked("REVIEWER_VERIFIER_UNAVAILABLE") from exc
        if outcome.returncode != 0:
            stop("REVIEWER_SIGNATURE_NOT_AUTHENTIC")
    return True


def path_allowed(name):
    if not isinstance(name, str) or not name or "\\" in name or name.startswith("/"):
        stop("PATH_INVALID")
    from pathlib import PurePosixPath
    if any(part in ("..", ".") for part in name.split("/")) or not PurePosixPath(name).parts:
        stop("PATH_TRAVERSAL")
    lower = name.lower()
    if lower.startswith(("assets/", "models/", "textures/", "renders/", "previews/")) or lower.endswith(ASSET_SUFFIXES):
        stop("ASSET_DELIVERY_IN_CHAT_ONLY:" + name)
    if not (name.startswith(ALLOWED_ROOTS) or name in ALLOWED_FILES):
        stop("NON_GOVERNANCE_MUTATION:" + name)
    return True


def validate_snapshot(policy, auth, pr, base, files, check_runs):
    if sha256(auth["repository"].encode("utf-8")) != policy["repository_sha256"]:
        stop("SIGNED_REPOSITORY_NOT_AUTHORIZED")
    if auth["master_sha256"] != policy["master_sha256"] or auth["public_controller_sha"] != policy["public_controller_sha"]:
        stop("SIGNED_SOURCE_PINS_MISMATCH")
    if pr.get("number") != auth["pr_number"] or pr.get("state") != "open" or pr.get("draft") is not False:
        stop("PR_NOT_MERGEABLE_STATE")
    if pr.get("head", {}).get("sha") != auth["head_sha"] or pr.get("base", {}).get("sha") != auth["base_sha"]:
        stop("SIGNED_PR_HEAD_OR_BASE_CHANGED")
    if pr.get("head", {}).get("repo", {}).get("full_name") != auth["repository"] or pr.get("base", {}).get("repo", {}).get("full_name") != auth["repository"]:
        stop("CROSS_REPO_PR_NOT_AUTHORIZED")
    if pr.get("base", {}).get("ref") != policy["base_branch"] or base.get("commit", {}).get("sha") != auth["base_sha"]:
        stop("DEFAULT_BRANCH_MOVED")
    if pr.get("mergeable") is not True:
        stop("PR_MERGEABILITY_NOT_CONFIRMED")
    if pr.get("changed_files") != len(files):
        stop("PR_FILE_COUNT_INCOMPLETE")
    if not isinstance(files, list) or not files or len(files) > 100:
        stop("PR_FILE_SET_INVALID_OR_INCOMPLETE")
    for file in files:
        path_allowed(file.get("filename"))
        if "previous_filename" in file:
            path_allowed(file["previous_filename"])
    if not isinstance(check_runs, dict) or check_runs.get("total_count") != len(check_runs.get("check_runs", [])):
        stop("CHECK_RUNS_INCOMPLETE")
    completed = check_runs["check_runs"]
    for name in REQUIRED_CHECKS:
        candidates = [x for x in completed if x.get("name") == name]
        if len(candidates) != 1:
            stop("CHECK_NOT_UNIQUE_OR_MISSING:" + name)
        item = candidates[0]
        if (item.get("head_sha") != auth["head_sha"] or item.get("status") != "completed" or
                item.get("conclusion") != "success" or item.get("app", {}).get("slug") != "github-actions"):
            stop("CHECK_NOT_TRUSTED_PASS:" + name)
    return True


class GitHubAPI:
    """Single-repository fixed-URL client. Token never printed or written to disk."""
    def __init__(self, token, repository):
        if not isinstance(token, str) or len(token.strip()) < 20:
            stop("BROKER_GITHUB_APP_TOKEN_MISSING")
        self.token = token
        if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            stop("BROKER_REPOSITORY_INVALID")
        self.repository = repository

    def call(self, method, route, payload=None):
        url = "https://api.github.com/repos/" + self.repository + route
        headers = {"Accept": "application/vnd.github+json", "Authorization": "Bearer " + self.token,
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "pinehaven-protected-broker"}
        data = canonical(payload) if payload is not None else None
        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=20) as response:
                return json.loads(response.read(500000))
        except (error.HTTPError, error.URLError, ValueError) as exc:
            raise Blocked("GITHUB_API_FAILED:" + type(exc).__name__) from exc

    def snapshot(self, number, head):
        pr = self.call("GET", f"/pulls/{number}")
        base = self.call("GET", "/branches/main")
        files_data = self.call("GET", f"/pulls/{number}/files?per_page=100")
        checks = self.call("GET", f"/commits/{head}/check-runs?per_page=100")
        return pr, base, files_data, checks

    def merge(self, number, head):
        return self.call("PUT", f"/pulls/{number}/merge", {"sha": head, "merge_method": "squash"})


def approve_and_merge(policy, auth, signature, key_path, api):
    verify_owner_signature(auth, signature, key_path, policy["reviewer_public_key_sha256"])
    pr, base, files, checks = api.snapshot(auth["pr_number"], auth["head_sha"])
    validate_snapshot(policy, auth, pr, base, files, checks)
    # A forged green job from another workflow must never authorize a merge.
    # This is a read-only cross-check against the authenticated GitHub API.
    try:
        prohibit_workflow_mutations(files)
        checked_same_trusted_run(api, auth["repository"], auth["head_sha"], auth["pr_number"], checks)
    except ProvenanceBlocked as exc:
        raise Blocked("TRUSTED_ACTIONS_PROVENANCE_FAILED:" + str(exc)) from exc
    result = api.merge(auth["pr_number"], auth["head_sha"])
    if result.get("merged") is not True:
        stop("MERGE_NOT_CONFIRMED")
    # Never print a token, a signed manifest, a private file or an asset.
    return {"status": "MERGED", "pr_number": auth["pr_number"], "merge_sha": result.get("sha")}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=POLICY_FILE)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--reviewer-public-key", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        policy = read_policy(args.policy)
        auth, sig = read_request(args.request)
        if not args.execute:
            stop("BROKER_DRY_RUN_ONLY_NO_NETWORK_OR_MERGE")
        if os.environ.get("GITHUB_REPOSITORY") != PUBLIC_REPO or os.environ.get("GITHUB_REF") != "refs/heads/main":
            stop("BROKER_NOT_IN_PROTECTED_PUBLIC_MAIN")
        token = os.environ.get("BROKER_GITHUB_APP_TOKEN")
        api = GitHubAPI(token, auth["repository"])
        outcome = approve_and_merge(policy, auth, sig, args.reviewer_public_key, api)
        print(json.dumps(outcome, sort_keys=True))
        return 0
    except (Blocked, KeyError, ValueError, TypeError, OSError) as exc:
        print("BROKER_BLOCKED:" + (str(exc) if isinstance(exc, Blocked) else type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

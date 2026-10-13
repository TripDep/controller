#!/usr/bin/env python3
"""Offline fail-closed Ed25519 authorization verifier; NEVER merges or writes GitHub.

This is a contract verifier ONLY. It does not enroll a signer, generate its key,
read the private GitHub App token, attest the MASTER in Library, or enforce
anti-replay. Those are separate mandatory operational boundaries.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
NONCE = re.compile(r"[A-Za-z0-9_-]{16,80}\Z")
FIELDS = {
    "schema", "repository", "pr_number", "head_sha", "base_sha",
    "master_sha256", "public_controller_sha", "decision", "expires_at", "nonce"
}
POLICY_FIELDS = {
    "schema", "enabled", "repository_sha256", "base_branch", "master_sha256",
    "public_controller_sha", "reviewer_public_key_sha256", "required_checks"
}


class Blocked(Exception):
    """A missing or failed security condition. Never output private values."""


def block(code: str) -> None:
    raise Blocked(code)


def no_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            block("DUPLICATE_JSON_KEY")
        result[name] = value
    return result


def parse_json_bytes(raw: bytes) -> object:
    if len(raw) > 8192:
        block("REQUEST_TOO_LARGE")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_pairs)
    except (ValueError, UnicodeError) as exc:
        raise Blocked("INVALID_JSON") from exc


def canonical_authorization(auth: dict) -> bytes:
    return json.dumps(auth, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def exact_hex(value: object, regex: re.Pattern) -> bool:
    return isinstance(value, str) and regex.fullmatch(value) is not None


def checked_policy(policy: object) -> dict:
    if not isinstance(policy, dict) or set(policy) != POLICY_FIELDS:
        block("POLICY_SCHEMA_INVALID")
    if policy["schema"] != "gg-git-broker-v1" or policy["base_branch"] != "main":
        block("POLICY_SCOPE_INVALID")
    if policy["enabled"] is not True:
        block("BROKER_NOT_ARMED")
    if policy["required_checks"] != ["guard-tests", "phase-guard", "public-controller"]:
        block("POLICY_CHECKS_INVALID")
    if any(not exact_hex(policy[field], HEX64) for field in ("repository_sha256", "master_sha256", "reviewer_public_key_sha256")):
        block("POLICY_SHA256_INVALID")
    if not exact_hex(policy["public_controller_sha"], HEX40):
        block("POLICY_CONTROLLER_SHA_INVALID")
    return policy


def checked_authorization(envelope: object, policy: dict, *, now: datetime | None = None) -> tuple[dict, bytes]:
    if not isinstance(envelope, dict) or set(envelope) != {"authorization", "signature_base64"}:
        block("REQUEST_SCHEMA_INVALID")
    auth = envelope["authorization"]
    if not isinstance(auth, dict) or set(auth) != FIELDS:
        block("AUTH_FIELDS_INVALID")
    if auth["schema"] != "gg-owner-reviewed-pr-v1" or auth["decision"] != "APPROVE_MERGE":
        block("AUTH_DECISION_INVALID")
    if not exact_hex(auth["head_sha"], HEX40) or not exact_hex(auth["base_sha"], HEX40):
        block("AUTH_PR_SHA_INVALID")
    if not exact_hex(auth["master_sha256"], HEX64) or not exact_hex(auth["public_controller_sha"], HEX40):
        block("AUTH_SOURCE_SHA_INVALID")
    if not isinstance(auth["repository"], str) or not REPOSITORY.fullmatch(auth["repository"]):
        block("AUTH_REPOSITORY_INVALID")
    if type(auth["pr_number"]) is not int or not 1 <= auth["pr_number"] <= 100000000:
        block("AUTH_PR_NUMBER_INVALID")
    if not isinstance(auth["nonce"], str) or not NONCE.fullmatch(auth["nonce"]):
        block("AUTH_NONCE_INVALID")
    if not isinstance(auth["expires_at"], str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", auth["expires_at"]):
        block("AUTH_EXPIRY_INVALID")
    try:
        expiry = datetime.fromisoformat(auth["expires_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise Blocked("AUTH_EXPIRY_INVALID") from exc
    now = now if now is not None else datetime.now(timezone.utc)
    if now.tzinfo is None:
        block("NOW_NOT_TIMEZONE_AWARE")
    remaining = (expiry - now).total_seconds()
    if not (0 < remaining <= 86400):
        block("AUTH_EXPIRED_OR_OVER24H")
    if hashlib.sha256(auth["repository"].encode("utf-8")).hexdigest() != policy["repository_sha256"]:
        block("REPOSITORY_PIN_MISMATCH")
    if auth["master_sha256"] != policy["master_sha256"] or auth["public_controller_sha"] != policy["public_controller_sha"]:
        block("SOURCE_PIN_MISMATCH")
    text = envelope["signature_base64"]
    if not isinstance(text, str) or len(text) > 500:
        block("SIGNATURE_INVALID")
    try:
        signature = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Blocked("SIGNATURE_INVALID") from exc
    if len(signature) != 64:
        block("SIGNATURE_INVALID")
    return auth, signature


def verify_detached(auth: dict, signature: bytes, pubkey_path: Path, pinned_key_sha256: str) -> bool:
    if not exact_hex(pinned_key_sha256, HEX64):
        block("REVIEWER_KEY_NOT_PINNED")
    if pubkey_path.is_symlink() or not pubkey_path.is_file():
        block("REVIEWER_PUBLIC_KEY_MISSING")
    if pubkey_path.stat().st_size > 8192:
        block("REVIEWER_PUBLIC_KEY_TOO_LARGE")
    pubkey_data = pubkey_path.read_bytes()
    if hashlib.sha256(pubkey_data).hexdigest() != pinned_key_sha256:
        block("REVIEWER_PUBLIC_KEY_PIN_MISMATCH")
    if len(signature) != 64:
        block("SIGNATURE_INVALID")
    with tempfile.TemporaryDirectory(prefix="ph-review-verification-") as temp:
        body = Path(temp) / "authorization.json"
        sig = Path(temp) / "detached.sig"
        body.write_bytes(canonical_authorization(auth))
        sig.write_bytes(signature)
        try:
            outcome = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pubkey_path.resolve()),
                 "-rawin", "-in", str(body), "-sigfile", str(sig)],
                check=False, capture_output=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise Blocked("OPENSSL_VERIFIER_UNAVAILABLE") from exc
    if outcome.returncode != 0:
        block("ED25519_SIGNATURE_INVALID")
    return True


def verify_files(policy_path: Path, envelope_path: Path, public_key_path: Path) -> bool:
    for p in (policy_path, envelope_path):
        if p.is_symlink() or not p.is_file():
            block("INPUT_FILE_MISSING_OR_SYMLINK")
    policy = checked_policy(parse_json_bytes(policy_path.read_bytes()))
    auth, sig = checked_authorization(parse_json_bytes(envelope_path.read_bytes()), policy)
    return verify_detached(auth, sig, public_key_path, policy["reviewer_public_key_sha256"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline Ed25519 gate; never writes to GitHub")
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--reviewer-public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify_files(args.policy, args.authorization, args.reviewer_public_key)
    except (Blocked, OSError, ValueError, TypeError) as exc:
        code = str(exc) if isinstance(exc, Blocked) else type(exc).__name__
        print("SIGNATURE_GATE_BLOCKED:" + code, file=sys.stderr)
        return 1
    print("SIGNATURE_FORMAT_PASS_ONLY; NO MERGE; NO INDEPENDENT REVIEW ATTESTATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

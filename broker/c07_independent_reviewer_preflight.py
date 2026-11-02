"""C07 independent MG0 reviewer trust-anchor preflight.

This is a read-only enrollment CHECK, not enrollment by the producer.
Only the authorized owner/reviewer may select an independent public key and
approve its fingerprint out-of-band. Never generate or enroll signing secrets
inside this tool or interpret a successful preflight as rule/MG0 certification.
"""
import argparse
import hashlib
import json
import re
import stat
import subprocess
from pathlib import Path

TRUST_PATH = "governance/trust/independent_review_ed25519.pub.pem"
SHA = re.compile(r"[0-9a-f]{64}\Z")
SCHEMA = "gg-c07-independent-reviewer-readonly-preflight-v1"

class ReviewerNotEnrolled(ValueError):
    pass

def need(value, message):
    if not value:
        raise ReviewerNotEnrolled(message)

def check(workspace, *, reviewer_identity, owner_authorized_sha256):
    """Fail closed until a real owner-authorized reviewer and key exist.

    The expected SHA is supplied out-of-band by the person authorizing the
    reviewer. Reading it from the public key file itself would permit a
    producer-controlled replacement key to become silently trusted.
    """
    need(type(reviewer_identity) is str and bool(reviewer_identity.strip()),
         "REVIEWER_IDENTITY_NOT_AUTHORIZED")
    need(type(owner_authorized_sha256) is str and
         SHA.fullmatch(owner_authorized_sha256) is not None,
         "OWNER_AUTHORIZED_KEY_FINGERPRINT_REQUIRED")
    root = Path(workspace).resolve(strict=True)
    need(root.is_dir(), "TRUST_WORKSPACE_NOT_FOUND")
    target = root
    for part in TRUST_PATH.split("/"):
        target = target / part
        need(not target.is_symlink(), "TRUSTED_REVIEWER_KEY_SYMLINK_FORBIDDEN")
    need(target.is_file(), "INDEPENDENT_REVIEWER_PUBLIC_KEY_NOT_ENROLLED")
    resolved = target.resolve(strict=True)
    need(resolved.is_relative_to(root), "INDEPENDENT_REVIEWER_KEY_ESCAPES_WORKSPACE")
    meta = resolved.stat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_size <= 8192,
         "INVALID_REVIEWER_PUBLIC_KEY_SIZE_OR_TYPE")
    pem = resolved.read_bytes()
    observed = hashlib.sha256(pem).hexdigest()
    need(observed == owner_authorized_sha256,
         "REVIEWER_PUBLIC_KEY_NOT_OWNER_AUTHORIZED")
    need(pem.startswith(b"-----BEGIN PUBLIC KEY-----"),
         "INVALID_REVIEWER_PUBLIC_PEM")
    try:
        r = subprocess.run(
            ["openssl", "pkey", "-pubin", "-text_pub", "-noout",
             "-in", str(resolved)],
            capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReviewerNotEnrolled("REVIEWER_OPENSSL_UNAVAILABLE") from exc
    need(r.returncode == 0 and b"ED25519" in r.stdout.upper(),
         "REVIEWER_KEY_MUST_BE_VALID_ED25519")
    return {
        "schema": SCHEMA,
        "reviewer_identity": reviewer_identity.strip(),
        "trusted_public_key_path": TRUST_PATH,
        "owner_authorized_public_key_sha256": observed,
        "public_key_syntax": "VALID_ED25519",
        "key_preflight_passed": True,
        "independent_review_performed": False,
        "signed_rules_certified": 0,
        "individual_mg0_certified": 0,
        "production_work_authorized": False,
    }

def main():
    parser = argparse.ArgumentParser(
        description="Read-only check of an OUTSIDE-AUTHORIZED C07 MG0 reviewer key")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--reviewer-id", required=True)
    parser.add_argument("--owner-approved-key-sha256", required=True)
    args = parser.parse_args()
    try:
        report = check(args.workspace, reviewer_identity=args.reviewer_id,
                       owner_authorized_sha256=args.owner_approved_key_sha256)
    except (ReviewerNotEnrolled, OSError) as exc:
        parser.exit(2, "BLOCKED: " + str(exc) + "\n")
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))

if __name__ == "__main__":
    main()

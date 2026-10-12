#!/usr/bin/env python3
"""Public read-only supervisor, executed inside a private repository CI runner.

No private document or user asset is uploaded to the public repository.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

POLICY_PATH = Path(__file__).with_name("policy.json")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
ASSET_SUFFIXES = (
    ".blend", ".blend1", ".blend2", ".glb", ".gltf", ".fbx", ".obj",
    ".ydr", ".ytd", ".ybn", ".ymap", ".ytyp", ".ydd", ".dds",
    ".tga", ".exr", ".hdr", ".png", ".jpg", ".jpeg", ".webp",
    ".psd", ".zip", ".7z", ".rar"
)
ASSET_ROOTS = ("assets/", "models/", "textures/", "renders/", "previews/")

class Blocked(Exception):
    pass

def file_sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def validate_repository_path(raw):
    name = raw.replace("\\", "/").lower().lstrip("./")
    if any(name.startswith(prefix) for prefix in ASSET_ROOTS):
        raise Blocked("ASSET_CHAT_ONLY:" + raw)
    if name.endswith(ASSET_SUFFIXES):
        raise Blocked("ASSET_CHAT_ONLY:" + raw)

def safe_private_file(root, relative):
    if relative.startswith("/") or ".." in Path(relative).parts:
        raise Blocked("UNSAFE_PATH:" + relative)
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise Blocked("SYMLINK_FORBIDDEN:" + relative)
    if not current.is_file():
        raise Blocked("MISSING_PRIVATE_SOURCE:" + relative)
    return current

def counted_rules(data):
    families = data.get("families")
    if not isinstance(families, list) or not families:
        raise Blocked("RULE_FAMILIES_INVALID")
    seen = set()
    for family in families:
        values = family.get("required") if isinstance(family, dict) else None
        if not isinstance(values, list) or not values:
            raise Blocked("RULE_FAMILY_INVALID")
        for identifier in values:
            if not isinstance(identifier, str) or not identifier.strip():
                raise Blocked("RULE_ID_INVALID")
            if identifier in seen:
                raise Blocked("DUPLICATE_RULE_ID:" + identifier)
            seen.add(identifier)
    if "Q" not in seen or "MG0" not in seen:
        raise Blocked("CRITICAL_RULE_MISSING")
    return len(seen)

def behavior_ids(content):
    matches = re.findall(r"(?m)^(\d{3})\.\s+", content)
    if len(matches) != len(set(matches)):
        raise Blocked("DUPLICATE_BEHAVIOR_RULE")
    return set(matches)

def pinned_public_action(workflow):
    """Require an immutable 40-hex public action in a named OR unnamed step."""
    return re.search(r"(?m)^\s*(?:-\s*)?uses:\s*TripDep/controller@[0-9a-f]{40}\s*$", workflow) is not None

def verify_sources(root, policy):
    paths = {
        "master": "governance/sources/GOLDEN_GARDEN_MASTER_RULES_AND_STATE.md",
        "registry": "governance/rule_family_registry.json",
        "catalog": "governance/sources/AAA_200_CANONICAL_CATALOG.json",
        "mapping": "governance/aaa_namespace_policy.json",
        "behavior": "governance/sources/ISTRUZIONI_PROGETTO_GUARD_ASSISTENTE.txt",
        "instructions": "governance/sources/ISTRUZIONI_V2_INTEGRALI_CON_110_ERRORI.txt",
        "phase_guard": "governance/gg_phase_guard.py",
        "executor": "governance/gg_controlled_executor.py",
        "workflow": ".github/workflows/gg-phase-guard.yml",
    }
    sources = {key: safe_private_file(root, path) for key, path in paths.items()}
    if file_sha256(sources["master"]) != policy["canonical_master_sha256"]:
        raise Blocked("LIBRARY_MASTER_PIN_MISMATCH")
    master = sources["master"].read_text(encoding="utf-8")
    if "## 0.0H — LOCK ASSOLUTO: GITHUB SUPERVISORE DEL PROCESSO;" not in master:
        raise Blocked("MOTHER_RULE_CHAT_ONLY_MISSING")
    if "## 0.0Q — NUOVA REGOLA MADRE:" not in master:
        raise Blocked("MOTHER_RULE_CLARIFY_MISSING")
    registry = json.loads(sources["registry"].read_text(encoding="utf-8"))
    if counted_rules(registry) != policy["non_aaa_id_count"]:
        raise Blocked("RULE_ID_COUNT_MISMATCH")
    behavior = behavior_ids(sources["behavior"].read_text(encoding="utf-8"))
    if behavior != {f"{i:03d}" for i in range(1, policy["behavior_110_count"] + 1)}:
        raise Blocked("BEHAVIOR_110_INCOMPLETE")
    if "110 ERRORI" not in sources["instructions"].read_text(encoding="utf-8"):
        raise Blocked("BEHAVIOR_INSTRUCTIONS_MISSING")
    catalog = json.loads(sources["catalog"].read_text(encoding="utf-8"))
    mapping = json.loads(sources["mapping"].read_text(encoding="utf-8"))
    entries, rows = catalog.get("catalog", []), mapping.get("mapping", [])
    if len(entries) != policy["aaa_count"] or len(rows) != policy["aaa_count"]:
        raise Blocked("AAA_200_INCOMPLETE")
    if file_sha256(sources["catalog"]) != mapping.get("catalog_sha256"):
        raise Blocked("AAA_CANONICAL_CATALOG_CHANGED")
    for i, (item, row) in enumerate(zip(entries, rows), 1):
        if (row.get("catalog_number"), row.get("catalog_section"), row.get("catalog_phase")) != (
                item.get("id"), item.get("section"), item.get("phase")):
            raise Blocked("AAA_MAPPING_MISMATCH:" + str(i))
    guard = sources["phase_guard"].read_text(encoding="utf-8")
    for required in ("INDEPENDENT_REVIEW_REQUIRED", "NO_EXPLICIT_USER_AUTHORIZATION",
                     "MG0_NOT_PASS_FOR_ID", "ASSET_DELIVERY_CHAT_ONLY"):
        if required not in guard:
            raise Blocked("PRIVATE_GUARD_WEAKENED:" + required)
    workflow = sources["workflow"].read_text(encoding="utf-8")
    if not pinned_public_action(workflow):
        raise Blocked("PUBLIC_SUPERVISOR_NOT_PINNED")
    if "needs: [guard-tests, phase-guard]" not in workflow:
        raise Blocked("PUBLIC_SUPERVISOR_DEPENDENCIES_MISSING")

def git_lines(root, *args):
    try:
        result = subprocess.run(["git", *args], cwd=root, check=True,
                                capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Blocked("GIT_VERIFICATION_FAILED") from exc
    return [raw.decode("utf-8", "strict") for raw in result.stdout.split(b"\0") if raw]

def verify_paths(root, base, head):
    if not HEX40.fullmatch(base or "") or not HEX40.fullmatch(head or ""):
        raise Blocked("GIT_BASE_HEAD_UNVERIFIED")
    for path in git_lines(root, "ls-files", "-z"):
        validate_repository_path(path)
    for path in git_lines(root, "diff", "-z", "--name-only", base, head):
        validate_repository_path(path)

def invoke_private_guard(root, base, head):
    env = dict(os.environ, GG_BASE_SHA=base, GG_HEAD_SHA=head)
    try:
        result = subprocess.run([sys.executable, "governance/gg_phase_guard.py", "--ci"],
                                cwd=root, env=env, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Blocked("PRIVATE_GUARD_UNAVAILABLE") from exc
    if result.returncode:
        raise Blocked("PRIVATE_PHASE_GUARD_FAILED")

def run(root, base, head):
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    if policy.get("schema") != "public-process-supervisor-v1":
        raise Blocked("PUBLIC_POLICY_INVALID")
    verify_sources(root, policy)
    verify_paths(root, base, head)
    invoke_private_guard(root, base, head)
    print("PASS: PUBLIC CONTROLLER + PRIVATE PHASE GUARD; process CI only; NO ASSET VALIDATED")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    try:
        run(args.repo.resolve(), args.base, args.head)
    except (Blocked, ValueError, KeyError, UnicodeError) as exc:
        print("BLOCKED:", str(exc), file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

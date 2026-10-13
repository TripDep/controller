#!/usr/bin/env python3
"""Fail-closed synthetic/operational provenance verifier for GitHub Actions jobs.

Pure *read-only* verification; callers inject an authenticated GitHub API client.
It cannot authorize a merge by itself or fix the unprotected private branch.
Existing check-run status alone is NOT trustworthy provenance. The trusted
workflow source/branch still requires a separately protected policy boundary.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

REQUIRED_CHECKS = ('guard-tests', 'phase-guard', 'public-controller')
PINNED_WORKFLOW_PATH = '.github/workflows/gg-phase-guard.yml'
REPO_PATTERN = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')


class Blocked(Exception):
    pass


def block(code: str):
    raise Blocked(code)


def require_records(data, field: str, maximum: int = 100):
    if not isinstance(data, dict) or type(data.get('total_count')) is not int:
        block('PROVENANCE_LIST_MALFORMED')
    rows = data.get(field)
    if not isinstance(rows, list) or len(rows) > maximum or len(rows) != data['total_count']:
        block('PROVENANCE_PAGINATION_INCOMPLETE')
    return rows


def parse_check_job_url(value: object, repo: str) -> tuple[int, int]:
    if not isinstance(value, str) or not REPO_PATTERN.fullmatch(repo):
        block('CHECK_JOB_URL_INVALID')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.netloc != 'github.com' or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        block('CHECK_JOB_URL_UNTRUSTED_HOST')
    m = re.fullmatch(r'/' + re.escape(repo) + r'/actions/runs/([1-9][0-9]*)/job/([1-9][0-9]*)', parsed.path)
    if not m:
        block('CHECK_JOB_URL_INVALID')
    return int(m.group(1)), int(m.group(2))


def checked_same_trusted_run(api, repository: str, head_sha: str, pr_number: int, checks: dict) -> bool:
    """Cross-link each required check-run to actual jobs in the same Actions PR run.

    API is the GitHub App's authenticated read client, scoped to repository.
    No HTTP request is made outside of this explicit, caller-supplied client.
    """
    if not isinstance(repository, str) or not REPO_PATTERN.fullmatch(repository):
        block('PROVENANCE_REPOSITORY_INVALID')
    if not isinstance(head_sha, str) or not re.fullmatch(r'[0-9a-f]{40}', head_sha):
        block('PROVENANCE_HEAD_INVALID')
    if type(pr_number) is not int or pr_number <= 0:
        block('PROVENANCE_PR_INVALID')
    run_id = None
    checked_jobs: dict[int, tuple[str, dict]] = {}
    check_rows = require_records(checks, 'check_runs')
    for name in REQUIRED_CHECKS:
        candidates = [c for c in check_rows if isinstance(c, dict) and c.get('name') == name]
        if len(candidates) != 1:
            block('CHECK_MISSING_OR_DUPLICATE:' + name)
        check = candidates[0]
        if (check.get('head_sha') != head_sha or check.get('status') != 'completed' or
                check.get('conclusion') != 'success' or check.get('app', {}).get('slug') != 'github-actions'):
            block('CHECK_NOT_PASS:' + name)
        candidate_run_id, job_id = parse_check_job_url(check.get('details_url'), repository)
        if run_id is None:
            run_id = candidate_run_id
        if candidate_run_id != run_id:
            block('CHECKS_FROM_MULTIPLE_RUNS')
        if job_id != check.get('id') or job_id in checked_jobs:
            block('JOB_CHECK_RUN_ID_MISMATCH')
        checked_jobs[job_id] = name, check
    if run_id is None:
        block('CHECK_RUN_ID_MISSING')
    run = api.call('GET', f'/actions/runs/{run_id}')
    if not isinstance(run, dict):
        block('WORKFLOW_RUN_INVALID')
    if (run.get('id') != run_id or run.get('path') != PINNED_WORKFLOW_PATH or
            run.get('event') != 'pull_request' or run.get('head_sha') != head_sha or
            run.get('status') != 'completed' or run.get('conclusion') != 'success' or
            run.get('head_repository', {}).get('full_name') != repository):
        block('WORKFLOW_RUN_NOT_TRUSTED')
    prs = run.get('pull_requests')
    if not isinstance(prs, list) or pr_number not in [p.get('number') for p in prs if isinstance(p, dict)]:
        block('WORKFLOW_RUN_PR_MISMATCH')
    jobs_payload = api.call('GET', f'/actions/runs/{run_id}/jobs?per_page=100')
    jobs = require_records(jobs_payload, 'jobs')
    for job_id, (name, check) in checked_jobs.items():
        matches = [j for j in jobs if isinstance(j, dict) and j.get('id') == job_id]
        if len(matches) != 1:
            block('WORKFLOW_JOB_NOT_FOUND:' + name)
        job = matches[0]
        expected_check_url = f'https://api.github.com/repos/{repository}/check-runs/{job_id}'
        if (job.get('name') != name or job.get('run_id') != run_id or
                job.get('check_run_url') != expected_check_url or
                job.get('head_sha') not in (None, head_sha) or
                job.get('status') != 'completed' or job.get('conclusion') != 'success'):
            block('WORKFLOW_JOB_NOT_TRUSTED:' + name)
        if job.get('html_url') != check['details_url']:
            block('WORKFLOW_JOB_DETAILS_MISMATCH:' + name)
    return True


def prohibit_workflow_mutations(files: list[dict]) -> bool:
    if not isinstance(files, list) or not files:
        block('FILE_LIST_EMPTY')
    for file in files:
        if not isinstance(file, dict):
            block('FILE_ENTRY_INVALID')
        for name in ('filename', 'previous_filename'):
            if name in file:
                path = file[name]
                if not isinstance(path, str):
                    block('FILE_PATH_INVALID')
                if path == '.github' or path.startswith('.github/'):
                    block('WORKFLOW_OR_GITHUB_POLICY_MUTATION_FORBIDDEN')
    return True

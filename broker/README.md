# Pine Haven – Git release broker staging (not active)

This directory contains **configuration and harmless environment-preflight tests only**. It does **not** contain the operational merge broker; publication of that executable was blocked and has not been retried through another upload path. All live repository writes, asset releases, and owner approvals remain disabled.

## Controls already available

- The protected public `main` ruleset requires `selftests` to pass.
- The existing private GitHub Actions workflow calls the public controller pinned to an immutable commit, running within its own private runner.
- The `broker-approval` GitHub Environment is intended to require an owner review, restrict to `main`, and deny admin bypass. GitHub environment settings could not be read from the current connector; only the owner's UI screenshots support that configuration.
- The GitHub App `PineHaven-Controlled-Broker` was created and installed on the private repository by its owner (UI screenshots). **No key, token, App ID secret or PEM is included here.**

## Probe, not activation

Manually dispatch `.github/workflows/broker-approval-preflight.yml` on `main` to test the GitHub **environment approval**. This workflow has read-only repository permission and no access to the private repository or broker credentials. Its final status cannot be used to claim the broker is active.

The private repository has no enforceable `main` branch protection via GitHub Free; its current connection still has write permission. An independently controlled reviewer and trusted signing key remain unconfigured. The candidate executable and test fixtures are held in the ChatGPT Library `_CONTROL/GITHUB_BROKER_R140_CANDIDATE` (NOT a trusted production deployment).

## Next necessary steps

A security-reviewed deployment path for the original executable, App identity/token issuance exclusively in a protected environment, independently attested signature, controlled actual negative+positive GitHub test, and only then removal of direct producer write paths. No private key should be transmitted in chat or committed to any repo.

**Three separate statuses:** `CI_SELFTEST_PASS`, `ENVIRONMENT_PROBE_PASS`, and `BROKER_ACTIVE`. The former two are *not* the latter. Owner remains final judge for 3D assets in chat; assets never go to GitHub.

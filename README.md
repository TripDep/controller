# Public Process Controller

**Purpose:** executable public supervisor for professional development process controls, **not** a repository for models, textures, renders or 3D deliverables.

The existing private repository invokes the public composite action by an immutable, full 40-character Git commit SHA. The action executes *inside the private GitHub Actions runner*, with read-only permissions. It checks a fixed SHA-256 of the canonical MASTER snapshot, 551 non-AAA identifiers, the full mapping of 200 AAA records, 110 behavior safeguards, private phase checks and the absolute ban on putting user assets on GitHub. It cannot read ChatGPT Library directly.

**No confidential sources are included here:** the MASTER, catalog text, private project state, signatures, approvals and production evidence remain in private Library/private repo. The only persistent authority evidence in this public project is a SHA-256 pin and rule counts. No paid services or secrets are required for the generic tests.

This repo includes synthetic negative tests and GitHub Actions selftests. A passed selftest is **not** an asset quality PASS, independent human approval, or proof the assistant follows chat instructions. Production has a separate human review gate; do not generate an agent-controlled signing key.

**Security limits:** protect this public main branch in GitHub Settings with the required `selftests` check; the API connection may not configure that setting. Public protection does not extend to private main on GitHub Free. Private direct-push bypass and chat actions remain outside this Git check unless a separately controlled execution boundary is proven.

**Owner delivery rule:** all finished 3D assets are delivered in the ChatGPT conversation, not on GitHub. Public and private GitHub supervise the *work process*.

**Updates to canonical MASTER:** verify the real current Library file first; intentionally update `supervisor/policy.json`, approve and test the public controller revision, then pin the new immutable SHA in the private caller. An outdated source must FAIL closed rather than being assumed valid.

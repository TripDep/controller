# C05 — Rescue / Guardian context transport

This bridge carries governance metadata only. Never publish assets, renders,
textures, source documents, research prose or production packages. The public
repository stores code and synthetic tests; actual observations stay private.

Private paths are `governance/supervisor/context/rescue.json` and `guardian.json`.
Each receipt has schema `gg-supervisor-context-v1`; read `supervisor_context.py`
for the exact allowlist. Library refs retain actual IDs, versions (null only
when the provider omits an immutable checkpoint version) and SHA256. MASTER
and WORK_STATE versions must be known. `observation_id` is SHA256 of sorted,
compact JSON excluding that field. Never put free-form asset data in the receipt.

Capture the current Library MASTER, WORK_STATE, R112 graph and relevant reports
through authorized Library tools. Compare checkpoint and verification report
hashes; distinguish the last durable checkpoint from newer pending work.
`CLOSED_VERIFIED_OPERATOR_READBACK` means an operator performed Library readback;
Git has NOT independently read those Library contents. Use PENDING/UNVERIFIED
with null source, verification and run hash if no complete proof was obtained.
Never upgrade a provider launch timestamp to completed work or diagnostics.
Guardian without a durable verified diagnostic report remains UNVERIFIED.

Build dependency fingerprints from current canonical data, not a producer waiver:
token = SHA256 of UTF-8 `state:<top-level-key>`, `asset:<work-item-id>` or
`graph:<canonical-node-id>`; value = digest() of the full corresponding JSON.
Ignore no canonical work rows. Dependency IDs needed by a work item and whether
Guardian is required MUST be determined from its canonical locks and graph in
C06; the modeling assistant cannot choose an empty dependency set to advance.
Include relevant UNKNOWN/FAIL/REGRESSION/PENDING signals by opaque dependency
token, or GLOBAL for an actually global blocker. Signal details remain Library.

Existing hourly Rescue and Guardian publish a context observation after their
authorized analysis, including pending/unknown when applicable. Preserve their
existing schedules and permissions. Read the latest public module pinned by the
private workflow; validate the receipt locally before publication. Use the
existing private repo and a unique `supervisor/context/<role>/<observation_id>`
branch, updating only that role's receipt. Open a draft PR titled
`SUPERVISOR_CONTEXT_<ROLE>_<observation_id>`; do NOT use GG_RUN_DONE or trigger a
production successor. An identical observation is not republished. Git receives
and validates the exact PR head after the existing CI. No automatic merge is
required or authorized by the bridge. Publication failures remain visible;
never substitute an invented successful run. Select the latest successfully
ingested observation, not main alone, and preserve the prior verified checkpoint
when the new observation is pending. Reject overlapping/conflicting observations.

Native workflow step reads both receipts at the upstream immutable head, binds
path/role/ref/digests, and prints C05_CONTEXT_INGESTED. Hash/shape validity is
context transport only, never a signed work PASS or evidence semantic validation.
Reconcile missing/invalid receipts; do not silently keep a fake latest context.

assess(previous,current,canonical_work_dependencies,guardian_required) rejects
replay, authority/version substitutions and same-version digest tampering.
Relevant changes -> RECHECK_AFFECTED_CONTROLS; relevant unknown/missing/failed
context -> STOP_RELEVANT_CONTEXT_UNKNOWN. An unrelated update or an hour without
a new checkpoint does not restart an independent task. MASTER content changes
always require rechecking. No elapsed-time-based global work prohibition is added.
All results keep advancement_authorized=false. C06/C07 must bind actual evidence,
enroll the context issuer, retrieve latest observations and enforce these results
before any real work advancement. C08/C09 prove the full operational cycle.

Current integration basis: Rescue R161 closed snapshot; Guardian provider launch
observed but durable diagnostics UNVERIFIED. This bridge does not resolve the
historical monitoring gaps, notifications or independent watchdog deployment.

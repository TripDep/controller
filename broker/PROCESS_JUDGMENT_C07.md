# C07 — judgment core, operational enrollment still incomplete

The core preserves every canonical family and ID and produces per-rule outcomes.
FAIL, UNKNOWN, missing native rule/MG0 evidence, relevant context changes or
unverified asset-specific extensions prohibit advancement. N_A and future IDs
remain present; they are never asset PASS or permission for final closure.

NativeRuleBackend authenticates actual workflow/run/job/attempt/content and
requires an exact enrolled validator, canonical clause hash, criterion set,
individual MG0 assessment and exact work/phase/attempt/operation/dependencies.
C03B PR success, C04 coverage, C05 context ingestion and C06 linkage scope do NOT
qualify as semantic per-rule validators. A returned local dictionary is not
native evidence. Unit fixture readiness cannot authorize operational work.

consume_native retrieves the native decision and recomputes a fresh judgment.
controlled_judgment.py now provides a durable Golden Controller begin/close
adapter and CLI (request/enroll/begin/close). Its controller implementation is
the unchanged canonical 1.2.0-AAA200 code, also installed as golden_controller.py.
Trusted plans must be enrolled during an authorized STATUS step and that step
must close PASS before use. The full inventory digest, source, precise action,
phase, locks, profiles, dependency file paths and enrolled issuers are retained
in the Controller hash-chain. Work/attempt/operation bindings are derived from
that plan, actual Controller position and current private dependency bytes.
No caller-provided work dict, previous PASS list or local decision is accepted
by this operational adapter. Previous failures are retrieved again from their
native Git run and checked against the persisted record, including after plan
changes. STOP decisions remain recorded and do not open a controlled step.

The adapter serializes participating calls, reloads canonical state, checks the
audit chain, reserves an eligible exact operation durably BEFORE Controller.begin,
and closes it through Controller.close. This is a fail-closed ordered protocol,
not an atomic transaction across multiple files: a crash after reservation,
incomplete audit/state write, or ambiguous closure blocks replay and requires
explicit reconciliation. It never automatically retries an uncertain action.
Close rechecks Master, dependencies and relevant Rescue/Guardian changes; an
unrelated verified context update does not force a restart. The low-level
consume_native helper remains available; durable operational callers use the
Controller adapter rather than an in-memory used set. This adapter does not
intercept unrelated writers or direct calls to the legacy Controller API.

Current installation is PARTIAL C07. No actual asset semantic validator is
enrolled. The native diagnostic therefore correctly returns UNKNOWN for every
ID, with no advancement. Its diagnostic P8/vegetation template is explicitly NOT
a real asset state. MASTER164 is the current source. Rescue PR33 and Guardian
PR32 context metadata on MASTER164 were imported in private PR34. Historical
receipts on162 remain historical; each operation reads its canonical current
local context files and checks the bound work dependencies.

Remaining C07 work: implement and enroll appropriate source-bound validators
for the real rule obligations, reconcile asset-specific locks/applicability,
enroll the appropriate actual work plan and use the durable adapter in the real
execution path; prove a genuine eligible advance and a corrected resubmission.
The adapter's integration tests use real Controller files with synthetic Git
API/semantic fixtures, including STOP/correction, restart, uncertain transaction,
tampering, concurrency and post-operation dependency checks. Their positive
cases prove the wiring only; no actual asset semantics or MG0 is certified.
Historical phase/
asset applicability is conservative until reconciled; it is not a producer
waiver. No new host, service, key purchase or asset upload is introduced.

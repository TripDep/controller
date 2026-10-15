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

Current installation is PARTIAL C07. The initial native diagnostic returns
UNKNOWN for every ID, with no advancement. Its P8/vegetation template is NOT a
real asset state. Current Master identity is checked from actual Library bytes
and the hash-only public policy, rather than a version number in this document.
Rescue36 metadata on Master165/state230 was imported in private PR37; Guardian32
remains on164 and cannot clear current-Master work. Historical receipts remain
historical; each operation checks its actual current private context files.

planning_semantics.py implements a first source-reading documentary predicate
for AAA-200-B-012: verify the documented destination engine in both actual
historical/current Master contents, the full work audit hash-chain, preflight
chronology and the individual preflight record before generation. It does not
certify a model or other planning rules. Its individual MG0 remains UNKNOWN:
the function emits no invented corrective lineage, so even a positive engine
predicate is an overall UNKNOWN in NativeRuleBackend. The pilot is strictly
DIAGNOSTIC_ONLY retrospective review; it cannot authorize a production action.
Native verification retrieves the actual semantic packet and rejects reusing
it for another attempt, while retaining the full canonical family/ID matrix.

The pilot reads actual R165 state/audit and report metadata only. Availability
qualifies all200 AAA entries but does not promote source PASS labels. P0 report
QA/P0_PREFLIGHT_EVIDENCE.md is referenced by40 PASS entries and was not found
in the retrieved R165 archive; it has NOT been established absent everywhere.
Other report bytes are distinguished from asset payloads deliberately withheld
from Git. Retrieved report bytes do not alone certify any rule or MG0. No model,
image, asset generator or source geometry is uploaded for this pilot.

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

## C07 typed-question polarity foundation (partial, 15 October 2026)

The reviewed source-bound `c07_answer_semantics.py` contract distinguishes:
- `CONTROL_PERFORMED`: NO admits an unperformed required check -> FAIL.
- `DEFECT_PRESENT`: YES admits a remaining problem -> FAIL; NO by itself is UNKNOWN.
- `REQUIREMENT_SATISFIED`: NO admits an unmet requirement -> FAIL.
- `OPEN_ANALYSIS`: demands a substantive narrative, not a forced YES/NO.

The first five reviewed canonical IDs are AAA-200-G-067, Q-075, Q-021,
Q-001 and Q-280. All other 758 of the 763 receive a *neutral* mandatory
`CONTROL_PERFORMED` meta-question (whether the canonical requirement was
checked) while their source-specific answer polarity remains
`GENERIC_CHECK_REVIEW_PENDING`. This is full question *coverage*, not full
question *semantic verification*; no keyword-inferred polarity or YES can
turn them into PASS. Source text,
requirement hash, exact attempt and operation bindings are checked. Duplicate,
inconsistent, stale or malformed answer packets are rejected.

Evidence references supplied by the producer do NOT establish independent
proof, asset quality or native-origin authentication. This pure contract
returns FAIL/UNKNOWN, never operational PASS, and does not itself intercept
ChatGPT messages or run the Controller begin/close lifecycle. This stage is
not C07 completion, C08 positive correction or C09 full acceptance.

## C07 Library-reviewed 758 yes/no wording integration candidate (15 October 2026)

Source of truth for this *wording review*: Library
`/Pine Haven/Golden Garden/_CONTROL/C07_758_QUESTION_REVIEW_20261015/C07_758_CHECKLIST_REVISIONATA.json`,
pinned to Master SHA256
`b5f33d4ea13f888e87bdf698169af68fbeeeab6429f8868f77c6c6ad451df165`.

Two checked-in JSON partitions contain **only** each question, canonical rule/source
digests and a flag for the 72 composite rule questions; they contain no 3D assets.
There are exactly 758 unique remaining rule IDs, no conflicting overlaps and no
remaining generic fallback for a complete canonical 763-rule inventory. The five
already-reviewed specific rules retain their specialized controls, including
DEFECT_PRESENT and OPEN_ANALYSIS. The 758 new prompts use a positive YES/NO
requirement-satisfaction polarity: NO admits a failure, YES remains an unverified
self-declaration. Every rule continues to require *independent* source-bound
semantic verification, MG0 and the authorized Controller phase protocol.

**Important limit:** the 72 composite questions are wording-reviewed, not
independently verified at the per-subclause level. Their composite flag stays
open, and no single YES certifies every constituent requirement. The separate
question contract and full obligation ledger use one shared source-validated
question mapping. No automatic PASS, asset approval, phase close or live
conversation interception is added by this release.

Operational promotion requires actual native work answers, native individual
proof validators, a healthy broker with the canonical Master pin and a
fail-closed enforceable process. C07 therefore remains PARTIAL.

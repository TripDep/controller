# C06 — per-attempt evidence binding and retrieval

Every canonical ID requires its own evidence link and individual MG0 binding.
Records carry work item, attempt number/ID, previous attempt when corrected,
phase, family, rule ID, MASTER/source/clause digests, both context observations,
and canonical work dependency fingerprints. Omitting or changing any binding
rejects the record. A shared MG0 from a different rule/phase/attempt is refused.
No producer-written PASS, reference-only hash or PR success authorizes work.

rule_evidence.py uses the existing authenticated GET-only client and reads
actual completed run/job/attempt metadata, enrolled immutable workflow bytes,
its public code pin and timestamped native result contents. Duplicate results,
failed/pending/skipped jobs, foreign repos, missing content, tampering, changed
attempt/source/context or a rerun during acquisition are refused. Log storage
redirects reuse the established client that never forwards GitHub credentials.
Trusted issuers and expected bindings come from reviewed consumer configuration,
not from the modeling producer. C07 must enroll issuers by exact scope and rule
semantics; no arbitrary new workflow can declare itself trusted.

The initial real test is explicitly GOVERNANCE_EVIDENCE_LINKAGE_TEST_ONLY. A
native emitter reads the immutable private case and current source inventory,
then independently retrieves the earlier C05 native logs AND both context
receipt bytes. It checks source hashes, context/dependency matches and the real
context-transition test results. It emits a new native record bound to the C06
governance attempt and EXEC-003, with its individual MG0 proof-binding assessment.
A later native run retrieves that completed record and rejects a different
attempt. This is real content retrieval; the underlying transition scenarios
remain declared synthetic and are never an asset QA or full MG0 execution PASS.

MG0 retains the canonical trigger semantics: record trigger assessment/evidence
for each relevant rule; execute the full process-falsification loop when its
canonical conditions are present. BINDING_CHECKED_NOT_MG0_PASS never satisfies
the final MG0 verdict. Failed attempts and corrective lineage remain append-only.
The initial interface requires corrective links structurally; verifying the
prior attempt's real failure and the successful correction is a C07/C08 consumer
requirement. Exact bytes/digests cannot substitute for that semantic judgment.

The schema connects global763 IDs to evidence without falsely claiming763 work
passes. C07 must bind all IDs and asset-specific locks/profiles, choose trusted
canonical dependencies/phase/attempt, retrieve current C05 observations, check
evidence applicability and each rule's full sub-obligations, judge MG0 and
enforce FAIL/UNKNOWN->correction. No stage advance is authorized by C06.

Assets, textures, renders and production packages stay in Library/chat. Asset
visual evidence is inspected in the authorized private workspace, and its
reported findings remain operator evidence until a trusted, appropriate QA
issuer and actual content-verification path are enrolled. Do not upload images
to Git merely to make validation easier. An inaccessible/unverified Library
proof remains UNKNOWN, never promoted into authenticated Git PASS. This module
enrolls only the initial governance linkage test, not visual/asset-rule QA.

Evidence output exposes native_content_retrieved=true separately from
rule_semantics_verified=false, mg0_execution_pass=false, asset_execution_passes=0
and advancement_authorized=false. C08/C09 retain full operational verification.

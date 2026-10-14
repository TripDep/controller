# C08/C09 acceptance, C07 intentionally left open

Owner instruction14 October2026: leave C07 open, move to C08 and C09, then
return to C07. This changes work priority; it does not waive rule/MG0 evidence
or authorize an asset action with an UNKNOWN verdict.

supervision_acceptance.py runs against actual native R165 source evidence,
using the canonical inventory and actual authenticated Git run/job/log/issuer.
It reads current Master contents and exact historical review inputs. No asset
bytes or producer state are changed. Adversarial requests mutate copies only;
the report labels each input mutation and never calls it an actual asset FAIL.

C08 checks missing family, missing rule, missing individual MG0, missing proof,
an actually computed FAIL under an inconsistent test expectation, relevant
context change, old proof requested for another attempt, corrected native proof
retrieval and an unrelated context update. Each negative test asserts its
specific failure reason or affected blocker, so existing unrelated UNKNOWNs
cannot make an omission test trivially pass. Native request recovery restores
authenticated retrieval only: individual MG0 remains UNKNOWN and an eligible
corrected work action is NOT proven. C08 therefore remains partial until that
positive operational correction is proved; negative tests can be marked done.

C09 authenticates the existing native full judgment from run38552856566,
recomputes the decision from actual sources/proof and attempts the low-level
exact-operation consumption gate. UNKNOWN denies consumption and leaves the
used-operation set untouched. This proves readiness denial only; it does NOT
run the durable Controller begin/close path or a full asset production cycle.
The report must mark C09 BLOCKED, not complete, while C07 is missing semantics,
individual MG0, current work context and an eligible operational judgment.

The test commands return success when the test itself behaves as expected.
That workflow SUCCESS is neither work authorization nor C08/C09 completion.
Public unit fixtures are labelled separately from native acceptance outputs.
No new service, host, key, purchase or asset upload is introduced.

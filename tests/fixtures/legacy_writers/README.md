# Audited legacy writer fixtures

These are exact, unmodified `src/security_runtime/task_risk_ledger.py` Git blobs
from this repository's supported historical builds. `provenance.json` records
full commit IDs, Git blob IDs and SHA-256 digests. The test independently pins
the SHA-256 constants, executes the actual archived class in a separate process,
and checks both its locked reader and its cached bare save against the new
filesystem fence.

The fixtures were compared byte for byte with `git show <ref>:<path>` when
created. They remain available in shallow offline CI checkouts; the test never
downloads historical code or depends on tags/history being fetched. These
historical modules are evidence fixtures, not importable production modules or
alternative protocol implementations.

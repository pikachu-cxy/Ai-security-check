# Functional Verification

Functional verification is an explicit Deep Verification flow. It is not part
of the default Core Hook because builds and tests are project-specific,
potentially expensive, and may have side effects.

Core security conclusions therefore come from the real scanner, normalized
Finding/Family/Episode state, policy, and bounded remediation proof. A missing
functional-verification capability keeps the result unknown or inconclusive;
it never becomes a safe result.

Use the existing Runtime/MCP functional-verification interface when a user
explicitly requests it and the host supplies the required capability. Keep
build/test commands, environment prerequisites, and outputs outside `docs/`
unless they are a maintained contract.

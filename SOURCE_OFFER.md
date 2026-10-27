# Scanner source availability

The default SAST engine is the unmodified OpenGrep 1.32.0 executable, invoked as a separate subprocess.
Its corresponding source is https://github.com/opengrep/opengrep/tree/v1.32.0 and
https://github.com/opengrep/opengrep/archive/refs/tags/v1.32.0.tar.gz . LGPL-2.1 text and attribution
are included in `security_runtime/licenses/opengrep/`.

The bundled rule source is https://github.com/opengrep/opengrep-rules/tree/f1d2b562b414783763fd02a6ed2736eaed622efa .
Unmodified execution YAML and the upstream LGPL-2.1 plus Commons Clause notice are retained in
`security_runtime/rules/`; the import receipt is `security_runtime/opengrep_rules.json`.
This free personal distribution does not assert unrestricted commercial or hosted-service rights to those rules.

## Historical, explicitly selected engine

AI Security Runtime invokes Semgrep OSS 1.178.0 as a separate Python package and subprocess. The corresponding upstream source for that pinned engine is available at https://github.com/semgrep/semgrep/tree/v1.178.0 and from the release archive at https://github.com/semgrep/semgrep/archive/refs/tags/v1.178.0.tar.gz . The full LGPL-2.1 license text shipped with this Runtime is in the `security_runtime/licenses/semgrep/LICENSE` package directory.

Distributors must review the LGPL obligations for their actual delivery format and provide the corresponding source and notices required by that format. This document records the pinned upstream source; it does not replace those obligations.

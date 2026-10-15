# Rule source review — Java / JavaScript / TypeScript foundation

Reviewed on 2026-10-10. Public source availability is not redistribution
permission. Engine licensing and rule licensing are separate decisions.

| Candidate | Fixed source | License evidence | Decision for this build |
| --- | --- | --- | --- |
| Legacy OpenGrep rule repository | `opengrep/opengrep-rules`, commit `f1d2b562b414783763fd02a6ed2736eaed622efa` | [Root LICENSE](https://github.com/opengrep/opengrep-rules/blob/f1d2b562b414783763fd02a6ed2736eaed622efa/LICENSE): LGPL 2.1 plus Commons Clause; [README](https://github.com/opengrep/opengrep-rules/blob/f1d2b562b414783763fd02a6ed2736eaed622efa/README.md) describes research/testing/benchmarking; archived | No rules or fixtures imported. Individual grants are not established by a YAML metadata string. |
| Aikido OpenGrep rules | `AikidoSec/opengrep-rules`, commit `7ac79affecf709eb7263a243b518a417cd7e0ab2` | [MIT LICENSE](https://github.com/AikidoSec/opengrep-rules/blob/7ac79affecf709eb7263a243b518a417cd7e0ab2/LICENSE) | Two workflow YAML rules, not Java/JS/TS source analysis. No import for this milestone. |
| Endor private/product rule collection | No publicly verified complete source and redistribution grant | Endor supporting OpenGrep is not permission to copy its product rules | Not obtained, not imported, not treated as an open rule pack. |

No third-party Java/JS/TS subset has been approved for bundling in this change.
The new rules and synthetic fixtures are independently authored FIRST_PARTY
definitions under the existing rule pack Apache-2.0 license. Their per-rule
provenance cites public CWE descriptions and the relevant official API contracts;
it does not claim derivation from the candidate repositories above. Restricted
patterns, comments, messages and fixtures are not translated or renamed into
the first-party pack.

Future imports must record upstream URL, commit, path, content SHA256, original
author, applicable root/directory/file and upstream grants, obligations, and an
explicit import/reject decision. Ambiguous or conflicting grants remain
UNKNOWN/RESTRICTED. MIT/Apache/BSD names alone are not a review of a particular
file; copyright, LICENSE, modification notices and applicable NOTICE must be
retained. Imported third-party definitions belong in their own reviewed pack,
not disguised as FIRST_PARTY or passed through relaxed provenance checks.

## Independent implementation inputs

- [CWE-89 SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-78 OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-918 SSRF](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-22 Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Spring JDBC API](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/jdbc/core/namedparam/NamedParameterJdbcTemplate.html)
- [Jakarta Persistence API](https://jakarta.ee/specifications/persistence/3.2/apidocs/jakarta.persistence/jakarta/persistence/entitymanager)
- [Apache Commons Exec API](https://commons.apache.org/proper/commons-exec/apidocs/org/apache/commons/exec/CommandLine.html)
- [Node child_process](https://nodejs.org/api/child_process.html)
- [Node filesystem](https://nodejs.org/api/fs.html)
- [Node HTTP](https://nodejs.org/api/http.html)
- [Express request/response API](https://expressjs.com/en/5x/api.html)
- [node-postgres query binding](https://node-postgres.com/features/queries)
- [mysql2 prepared statements](https://sidorares.github.io/node-mysql2/docs/documentation/prepared-statements)

These references describe vulnerability mechanisms or API behavior. They are
not claims of independent real-project ground truth. Positive and negative
fixtures are synthetic; production precision and recall remain unestablished.

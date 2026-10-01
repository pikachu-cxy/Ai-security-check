# Actual rule coverage

Generated from `src/security_runtime/rules/catalog.json`, cross-checked against local YAML.
Pack: **ai-security-core 1.1.0**, FIRST_PARTY, Apache-2.0. All default rules are BETA.
22 Java rules (21 Java AST rules plus one generic MyBatis mapper XML rule), two existing Python rules.
No JS/TS/Go/PHP rules are included. The XML rule is associated with Java only when Java is in scope.

| Category | Java | Python | JS/TS | Go |
|---|---|---|---|---|
| code-injection | — | BETA (1) | — | — |
| command-injection | BETA (2) | BETA (1) | — | — |
| insecure-random | BETA (1) | — | — | — |
| jndi-injection | BETA (1) | — | — | — |
| ldap-injection | BETA (1) | — | — | — |
| open-redirect | BETA (1) | — | — | — |
| path-traversal | BETA (1) | — | — | — |
| sql-injection | BETA (4) | — | — | — |
| ssrf | BETA (2) | — | — | — |
| trust-all-tls | BETA (2) | — | — | — |
| unsafe-deserialization | BETA (2) | — | — | — |
| weak-cryptography | BETA (2) | — | — | — |
| xxe | BETA (3) | — | — | — |

Planning resolves the catalog before engine preparation. Zero applicable rules means NOT_COVERED
and no Semgrep installation or invocation. Only matching rule/file extensions enter SAST scope.
EXPERIMENTAL rules are excluded from the default pack; explicit user packs remain user-controlled.

Execution counts use the selected rule IDs, Semgrep `time.rules`, `paths.scanned` and error/skip evidence.
Counts are distinct rules, not rules × files and not matching findings. Missing execution evidence
does not qualify as EXECUTED. Parse errors or skipped targets lower language coverage.
Mixed Java + uncovered JavaScript reports CODE_SAST PARTIAL even if the engine exits successfully.

Use `python scripts/test_rules.py` for catalog lint, Semgrep load validation, and positive/negative fixtures.
The gate rejects duplicate IDs, missing metadata/provenance, invalid languages and catalog drift.
No registry or community rules are downloaded. API behavior and vulnerability definitions are the references.

## Catalog

| Rule | Language | Mode | Framework | CWE | Confidence |
|---|---|---|---|---|---|
| ai-security.java.runtime-exec | java | taint | JDK | CWE-78 | HIGH |
| ai-security.java.process-builder | java | taint | JDK | CWE-78 | HIGH |
| ai-security.java.jdbc-statement | java | taint | JDK | CWE-89 | HIGH |
| ai-security.java.spring-jdbc | java | taint | Spring | CWE-89 | HIGH |
| ai-security.java.mybatis-annotation | java | search | MyBatis | CWE-89 | HIGH |
| ai-security.java.mybatis-xml | java | search | MyBatis | CWE-89 | HIGH |
| ai-security.java.url-connection | java | taint | JDK | CWE-918 | HIGH |
| ai-security.java.spring-resttemplate | java | taint | Spring | CWE-918 | HIGH |
| ai-security.java.file-access | java | taint | JDK | CWE-22 | HIGH |
| ai-security.java.xxe-document-builder | java | taint | JDK | CWE-611 | HIGH |
| ai-security.java.xxe-sax-parser | java | taint | JDK | CWE-611 | HIGH |
| ai-security.java.xxe-stax | java | taint | JDK | CWE-611 | HIGH |
| ai-security.java.object-deserialization | java | taint | JDK | CWE-502 | HIGH |
| ai-security.java.xml-decoder | java | taint | JDK | CWE-502 | HIGH |
| ai-security.java.jndi-lookup | java | taint | JDK | CWE-74 | HIGH |
| ai-security.java.ldap-search | java | taint | JDK | CWE-90 | HIGH |
| ai-security.java.open-redirect | java | taint | Servlet | CWE-601 | HIGH |
| ai-security.java.trust-all-hostname | java | search | JDK | CWE-295 | HIGH |
| ai-security.java.trust-all-certificates | java | search | JDK | CWE-295 | HIGH |
| ai-security.java.weak-cipher | java | search | JDK | CWE-327 | MEDIUM |
| ai-security.java.weak-digest | java | search | JDK | CWE-328 | MEDIUM |
| ai-security.java.security-random | java | search | JDK | CWE-330 | MEDIUM |
| ai-security.python.command-injection | python | search | Python | CWE-78 | MEDIUM |
| ai-security.python.unsafe-eval | python | search | Python | CWE-95 | MEDIUM |

## Boundaries

These are local structural patterns and intraprocedural taint rules, not complete Java SAST.
CE does not establish Controller → Service → Repository cross-file flow or prove exploitability.
Business logic, authorization/IDOR, financial state machines, comprehensive sanitizers and custom frameworks
remain outside this pack. ScriptEngine/Groovy/SpEL are intentionally omitted from defaults.
XXE currently covers DocumentBuilderFactory, SAXParserFactory and XMLInputFactory; TransformerFactory and
SchemaFactory are not covered. SSRF currently covers URL and RestTemplate; HttpClient/WebClient/OkHttp are not covered.
The security-random rule only covers name-indicated nextInt/Math.random contexts, not every token generator.
MD5/SHA-1 results are MEDIUM/MEDIUM and require purpose review; ordinary checksums are not proven vulnerabilities.
MyBatis substitution rules identify textual interpolation, and require review of any identifier allowlists.
Rule severity and confidence remain distinct from Runtime's overall risk and later validation.
Findings retain original rule metadata plus NOT_VALIDATED; no AI assessment is performed.

Primary API references: [Semgrep taint mechanics](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview),
[MyBatis substitution and binding](https://mybatis.org/mybatis-3/sqlmap-xml.html),
[JDK X509TrustManager](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/net/ssl/X509TrustManager.html),
[JDK DocumentBuilderFactory](https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html).

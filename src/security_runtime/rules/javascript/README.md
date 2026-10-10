Six independently authored Apache-2.0 rules cover selected inline HTTP-handler
flows to SQL, shell execution, outbound HTTP and filesystem sinks. Each execution
definition supports JavaScript and TypeScript; catalog companions exercise both
parsers. These are local taint candidates, not exploitability proof or complete
OWASP coverage. Arbitrary wrappers, separate controller functions and cross-file
flows remain limited. No external registry rules are downloaded or copied.

JSX/TSX extensions use the same source parsers. Vue single-file components are
not included; mixed .js/.vue coverage must retain the uncovered .vue input.

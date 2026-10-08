# R1 Phase 2 detection regressions

71 author-declared synthetic Java cases, motivated by Phase 1 source reviews.
These are regression evidence, not real-project accuracy evidence or independent
human labels. Each file is scanned without executing the Java code.

`cases.json` declares source semantics before scanner comparison. `reference_risk`
always describes the code, including known missed risks and known safe false
positives. `cause-reviews.json` separately records reviewed limitations and their
reasons. Generated findings, case outcomes, before/after metrics and experiments
belong in ignored `artifacts/r1/phase2/`, never in this dataset or `docs/`.

The 45 required regressions cover safe/unsafe counterparts, single-argument JDBC
`Connection.prepareCall`, parameter binding, builder setter/start sequencing,
replacement/reassignment, two starts, repeated tainted commands, fixed-program
data arguments, collection mutation and a bounded local command-list shape.
26 strict pytest xfails expose 8 safe FP characterizations and 18 risky FN
limitations. An unexpected fix becomes XPASS
and requires review; limitations are not converted into successful detections.

## Accepted modeling boundary

- SQL: only `Connection.prepareCall(String)` SQL construction. Binding a value
  afterwards cannot make a tainted procedure name safe. Constant SQL with bound
  values stays safe. Overloads are deferred after a fixed-branch FP was observed
  in an isolated candidate replay.
- Command: local initialized `ProcessBuilder`, `command(...)`, then `start()` on
  the same variable. The command setter is invalidated by subsequent setters or
  builder reassignment. Supports first executable/array argument and explicit
  `sh -c` / `cmd.exe /c` payloads. A local `List<String>.add` propagator is limited
  to an empty ArrayList whose first addition is the executable, or whose literal
  shell prefix identifies the payload. It supports direct shell prefixes and a
  local String-selected cmd/sh branch. It requires a no-argument builder and
  defers element mutation before the setter. Fixed printf plus an explicit `%s`
  format and external data remains safe for both list and array arguments.
  Array setters are deferred because array-wide taint cannot resolve argument
  roles. This is not a general builder or collection analysis engine.

## Retained limitations

- Benchmark 00135/00361/01035/01240/02111/01973: fixed switch, constant helper
  return, inner helper arithmetic and known-safe list-element selection. Unsafe
  counterparts prevent broad suppression of argument-to-return propagation.
- Overloaded `prepareCall`, array setters, alias-based starts and list mutation
  before/after `command` are explicit risky FN characterizations.
- Client Cookie values are untrusted under Servlet semantics. `javax` and
  `jakarta` safe/unsafe pairs retain that truth. Source modeling is deferred:
  the narrowed isolated experiment added four Benchmark TP and two FP. No Cookie
  source rule change is adopted.
- Cross-file/function flow, custom wrappers, DTO propagation, interface/factory
  resolution, global typing and general constant propagation remain unsupported.

API references: [JDBC Connection](https://docs.oracle.com/en/java/javase/21/docs/api/java.sql/java/sql/Connection.html),
[ProcessBuilder](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html),
[Servlet request](https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/httpservletrequest).
In particular ProcessBuilder retains a provided list, so late mutation is a
real risk rather than a safe case. Evidence uses pinned Semgrep 1.178.0 behavior.

Run with the project Python and `PYTHONPATH=src`:

```text
python -m pytest tests/test_rule_program.py tests/test_rule_coverage.py tests/test_r1_evaluation.py tests/test_r1_phase2.py -q
python scripts/test_rules.py --output artifacts/r1/phase2/rule-gate.json
python scripts/r1_phase2.py --tag minimal-final
python scripts/r1_phase2.py --tag refined-candidate --benchmark
python scripts/r1_phase2.py --tag final-corpora --other-projects
```

The before snapshot is immutable. `--snapshot` refuses to overwrite it.
Benchmark labels and source hashes are reused from Phase 1; there is no new
sampling or outcome-based relabeling. Capability maturity remains frozen.

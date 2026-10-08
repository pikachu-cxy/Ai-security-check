# R1 evaluation references

`controls.json` declares source-reviewed labels at exact sinks in the two
existing independently authored `samples/java-benchmarks` files. They are
SYNTHETIC controls, not independently reviewed real-world evidence. They keep
safe parameter binding and fixed endpoints/executables separate from risky
sinks in the same file. Do not derive labels from scanner findings.

The offline evaluator is `scripts/r1_evaluation.py`. Use the project Python
3.12 environment and current `src` on `PYTHONPATH`. Supply `--jeepay`,
`--benchmark` (original testcode layout), and `--benchmark-reference` (an
existing local Benchmark Git checkout). No network access, builds, external
corpus edits, maturity changes or automatic rule changes occur.

The default first round selects 30 risky and 30 safe cases in each of SQLi,
command injection and path traversal, evenly spaced by case ID within each
stratum **before scanning**. This is a small deliberately stratified sample,
not a random estimate of production accuracy. Benchmark contains no SSRF
reference group. Path traversal labels are evaluated once as a combined
Path/File Access group; they do not independently establish read/write
capability precision or recall. Every selected file and CSV label is checked
against the local Benchmark Git HEAD (normalizing CRLF only).

Generated inventory, source hashes, scanner runs, independent reference
labels, case outcomes, taxonomy hints and bounded review windows live under
ignored `artifacts/r1/`. Failed/partial coverage produces UNCERTAIN, never FN
or TN. Unlabelled real-project findings stay GROUND_TRUTH_UNAVAILABLE with
UNREVIEWED review status; their absence cannot establish recall or safety.
Source/sink/sanitizer regex hits are review hints, never observed dataflow or
proof. Runtime does not export source coordinates for these engine matches.

The initial Markdown/JSON queue is capped at 24 representative records.
The complete JSONL dataset remains available for follow-up filtering. Cause
reviews must record evidence and reviewer provenance separately from upstream
risk labels. The standard taxonomy is defined in the evaluator's `TAXONOMY`.
No model result may silently replace independent ground truth.

`cause_reviews.json` records twelve source reviews of contributing failure
boundaries, pinned to the local upstream reference commit. All six initially
observed reference FP cases are included. These Codex reviews do not create
human ground truth and do not prove an isolated engine root cause.

`--analysis-only` can re-evaluate saved scanner outputs only when the original
project root, every scoped source hash, executed coverage and rule-pack checksum
still match. It is offline artifact analysis, not a production scanner cache.

## Reproduce on another machine

Install the repository's Python 3.12 test dependencies and pinned scanner tools.
External corpora are supplied by arguments, not by a developer's home directory.
For the historical source reviews, provide a Benchmark Git reference at the
`benchmark_reference_commit` recorded in `cause_reviews.json`, plus matching
source files in the original `src/main/java/org/owasp/benchmark/testcode` layout.

From the repository root, with `src` on `PYTHONPATH`, run:

```text
python scripts/r1_evaluation.py --jeepay <jeepay-root> --benchmark <benchmark-source-root> --benchmark-reference <benchmark-git-root> --output artifacts/r1
python -m pytest tests/test_r1_evaluation.py tests/test_r1_phase2.py -q
python scripts/r1_phase2.py --tag current-regressions
```

The first command produces a fresh current-rule evaluation; it does not recreate
the historical pre-fix metrics. Those require the original rules and their
separate before observations. Optional `r1_phase2.py --snapshot` freezes the
local evaluation and rules, then `--benchmark` or `--other-projects` can replay
against it. A snapshot made after a fix is not evidence of pre-fix behavior.
Snapshots refuse overwrites. Recreate observations locally rather than copying
an inventory with another machine's absolute roots; root/hash checks intentionally
reject relocated or changed inputs. All generated paths and reports stay ignored.

# Fixed rule acceptance

`rule_acceptance.json` pins the existing BenchmarkPython, NodeGoat, Juice Shop,
DVWA and GoVWA slices by upstream commit and SHA-256. Python helper inputs are
also pinned because the default bounded analyser may resolve them. The repository
contains inventories and labels only; upstream source stays in local `.tools/`
checkouts. No benchmark application or dependency is executed or installed.

`rule_acceptance_expected.json` records the accepted core 1.5.0 finding identities
and the Python case/category labels. The combined Python floor is 27 true
positives and the same 3 known false-positive cases, not a target for production
accuracy. Do not regenerate the baseline simply to make a failing run pass.

Run from the repository root, with dependencies already installed:

```powershell
$env:PYTHONPATH = 'src'
python scripts/run_rule_acceptance.py --output-dir .tools/acceptance-candidate --repeat 5
```

Every output directory must be new. A missing checkout, different Git revision,
changed source/helper bytes, incomplete engine execution, lost prior true
positive or new false-positive case fails the gate. An unlabelled project's new
finding needs deliberate review. A resolved known false positive may disappear.
Native Go's existing partial scope is retained explicitly; zero findings cannot
stand in for an unavailable scanner. Every run stores its real receipt.

For a source comparison, first run the same command with `PYTHONPATH` pointing
to an immutable baseline source tree; then run the candidate with
`--compare .tools/acceptance-baseline/summary.json`. Both sides use the same
manifest and default 40-file batches, fresh scanners and no cached results.
Use at least five serial repetitions per side, without concurrent scanning.
The report keeps cold starts, ranges and engine versions. A median increase of
both more than 10% and more than one second requests investigation; fewer than
five samples require further review even when apparently faster. This is scanner-entry wall time, not a
full application latency or a promise for other machines.

The fast gates remain `scripts/test_rules.py`,
`scripts/test_python_rule_product.py`, `scripts/test_javascript_rule_product.py`
and `scripts/test_vue_rule_product.py`. Vue fixtures verify partial script
coverage and original coordinates; they do not constitute a real Vue-project
accuracy benchmark. Java's rule fixtures likewise do not replace a real labelled
Java project. Those evidence gaps must remain visible when describing results.

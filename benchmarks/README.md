# Reviewed external-source benchmark

This benchmark selects four files from the operator-supplied DVWA checkout. It uses independently authored application code rather than the scanner's generated development fixtures. It is a **provided, already available corpus**, not an unseen holdout.

The hash-pinned answer key covers eight manually inspected operation anchors: four vulnerable SQL/command sinks and four closely related protected sinks. SQL controls use bound parameters; command controls reconstruct the address from numeric octets. The two OS branches count as separate source operations. Only CWE-89 and CWE-78 in these selected files are scored. The raw scan report is saved alongside the scoped evaluation, including any excluded findings.

```sh
PYTHONPATH=. .venv/bin/python benchmarks/run_source.py \
  --source /path/to/DVWA \
  --output artifacts/dvwa-source-benchmark
```

The runner verifies file hashes, copies those files to a temporary source directory and performs a source-only native scan with AI disabled. It never sends target requests or supplies answer-key anchors to the scanner. A changed file requires renewed review of both anchors and hashes before scoring.

This run measures source precision/recall only. Runtime verification, authenticated workflows, exact source links, XSS and other CWE families need additional truth sets and capable live targets. The regression suite tests those correlation contracts separately. Neither result establishes accuracy on arbitrary applications.

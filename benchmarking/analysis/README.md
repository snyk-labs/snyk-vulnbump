# Analysis scripts

These scripts recompute the paper's results tables and figures from the published reports in `benchmarking/reports/`. Most of them assert that their numbers match the values printed in the paper. Run them from the repository root:

```bash
(cd benchmarking/scripts && uv sync --group analysis)
PY="uv run --project benchmarking/scripts --group analysis python"
$PY benchmarking/analysis/extract_results.py
```

## Scripts

| Script | Reads | Writes | Paper |
|---|---|---|---|
| `extract_results.py` | reports, `cases.yaml` | `outputs/results.json` | Tables 2 and 3 |
| `failure_causes.py` | reports, raw scans | `outputs/failure_causes.json` | Table 4 |
| `pm_bump_baseline.py` | reports, raw scans | `outputs/pm_bump_baseline.json` | the package manager bump's column in Tables 2–4 and Figure 4 |
| `extract_overlap.py` | `results.json`, `failure_causes.json`, reports, `cases.yaml`, raw scans | `outputs/results_overlap.json` | PASS overlap between the agents, source-edit PASSes |
| `figure1_dataset.py` | (hard-coded counts) | `figures/dataset-sankey.pdf` | Figure 1 |
| `figure2_distributions.py` | reports and `cases.yaml` (panel d) | `figures/distribution-comparison.pdf` | Figure 2 |
| `figure4_failures.py` | `pm_bump_baseline.json` | `figures/failure-first-gate.pdf` | Figure 4 |
| `figure5_pass_rate_by_jump.py` | reports | `figures/pass-rate-by-jump.pdf` | Figure 5 |
| `figure6_vuln_fix_by_difficulty.py` | `results.json`, reports | `figures/vuln-fix-by-difficulty.pdf` | Figure 6 |

**How the scripts depend on each other:**
- `pm_bump_baseline.py` imports `failure_causes.py` and reuses its cause rules.
- `extract_overlap.py` needs `results.json` and `failure_causes.json`.
- `figure4_failures.py` needs `pm_bump_baseline.json`.
- `figure6_vuln_fix_by_difficulty.py` needs `results.json`.
- The scripts that read raw scans import `harness.scans` from `benchmarking/scripts/`.

Figure 3, the pipeline diagram, is TikZ in `paper/source/vulnbump.tex`.

## Outputs

- `outputs/` holds the JSON outputs, committed.
- `figures/` holds the regenerated figures. It is gitignored; the paper's copies are in `paper/source/figures/`, under the same names.

## Unpublished inputs

Three scripts need data that isn't published:

- **Raw run artefacts.** `failure_causes.py`, `pm_bump_baseline.py` and `extract_overlap.py` read the per-attempt artefacts under `benchmarking/data/scans/<run_id>/`: `agent.diff`, the verifier logs and the post-fix scans. Those aren't published (about 1 GB per run). Their outputs are committed in `outputs/`, so every figure and number can be checked without them.
- **Candidate mining (Figure 1).** The candidate counts are hard-coded.
- **Snyk Open Source production statistics (Figure 2).** The production numbers and the VulnBump panels (a)–(c) and (e) are hard-coded. Panel (d) is computed from the reports.

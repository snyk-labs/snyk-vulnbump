# Reproducing the paper's numbers and figures

The paper's results come from the published single-upgrade reports in `benchmarking/reports/`:

| Harness | Report |
|---|---|
| Evo Remediation Agent | `evo-remediation-agent/benchmark.json` |
| Claude Code + Snyk scan | `claude-code-snyk-scan/benchmark.json` |
| Claude Code unaided | `claude-code-unaided/benchmark.json` |
| package manager bump | `package-manager-bump/benchmark.json` |
| package manager bump with `>=` Python pins | `package-manager-bump-min/benchmark.json` |

The reports keep their run provenance: `git_sha`, `cli.cli_commit` and the suffix of `cli.snyk_version` refer to Snyk's internal repository and the pre-release CLI build the runs used. They can't be resolved publicly.

The scripts in [`benchmarking/analysis/`](../benchmarking/analysis/README.md) recompute every results table and every figure except Figure 3, the TikZ pipeline diagram. Most of them assert that their numbers match the values printed in the paper. From the repository root:

```bash
(cd benchmarking/scripts && uv sync --group analysis)
PY="uv run --project benchmarking/scripts --group analysis python"
for s in extract_results figure1_dataset figure2_distributions figure4_failures \
         figure5_pass_rate_by_jump figure6_vuln_fix_by_difficulty; do
  $PY benchmarking/analysis/$s.py
done
```

Three scripts (`failure_causes.py`, `pm_bump_baseline.py`, `extract_overlap.py`) also need the raw run artefacts, which aren't published. Their outputs are committed in `benchmarking/analysis/outputs/`.

Some inputs are hard-coded:
- Figure 1's candidate counts, from candidate mining.
- Figure 2's production statistics and its VulnBump panels (a)–(c) and (e).

The [analysis README](../benchmarking/analysis/README.md) has the dependency graph and the details.

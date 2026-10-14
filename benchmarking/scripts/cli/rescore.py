"""Re-score a report under the current collateral rules, without re-running agents.

Collateral is recomputed from the run's preserved scans (data/scans/<run_id>)
and no longer fails an attempt; totals, txt and PDF are rebuilt. A merged report
takes several run ids; each case reads the latest run that has its scans.

    uv run python -m cli.rescore ../reports/<run_id> \\
        ../reports/<run_id>-no-collateral --run-id <run_id>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from harness.collateral import unrelated_bumps
from harness.fix_plan import FixPlan
from harness.outcome import DepChange
from harness.scans import SCANS_DIR, after_dir
from harness.snyk import load_json, scope_to_manifests, split_new_projects
from harness.verdict import REASON_UNEXPECTED_COLLATERAL

from .merge_reports import merge
from .pdf_report import CASES_YAML, generate_pdf
from .report import render_table, write_report


def _manifests(cases_yaml: Path) -> dict[str, list[str]]:
    cases = yaml.safe_load(cases_yaml.read_text())["cases"]
    return {c["inputs"]["name"]: c["inputs"].get("manifests") or [] for c in cases}


def rescore(report: dict, runs: list[Path], manifests: dict[str, list[str]]) -> dict:
    for name, case in report["cases"].items():
        scans = next((r for r in reversed(runs) if (r / name).is_dir()), None)
        if scans is None:
            raise SystemExit(f"{name}: no scans in any of {[r.name for r in runs]}")
        repeats = len(case.get("baselines") or [case["baseline"]])
        before: dict[int, tuple] = {}
        for a in case["attempts"]:
            r = a.get("repeat") or 0
            scan_dir = scans / (name if repeats < 2 else f"{name}/repeat-{r + 1}")
            if r not in before:
                cli = scope_to_manifests(
                    load_json(scan_dir / "before" / "snyk-test-before.json"), manifests.get(name)
                )
                before[r] = (cli, FixPlan.from_scan(cli))
            cli_before, plan = before[r]
            if plan is None:
                raise SystemExit(f"{name}: no baseline scan under {scan_dir}")

            group = next((g for g in plan.groups if g.label == a["label"]), None)
            if group is None:
                raise SystemExit(f"{name}: no plan group {a['label']!r}")
            after = after_dir(scan_dir, a["agent"], a["label"])
            cli_after, _ = split_new_projects(cli_before, scope_to_manifests(
                load_json(after / "snyk-test-after.json"), manifests.get(name)
            ))

            a["unexpected_collateral"] = list(unrelated_bumps(
                cli_before, cli_after, [DepChange(**c) for c in a["deps_changed"]],
                plan, group, group,
            ))
            a["reasons"] = [x for x in a["reasons"] if x != REASON_UNEXPECTED_COLLATERAL]
            a["verified"] = not a["reasons"]

    report["fairness"]["strict_collateral"] = False
    return merge([report])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cli.rescore")
    p.add_argument("src", type=Path, help="report directory holding benchmark.json")
    p.add_argument("out", type=Path, help="directory to write the rescored report to")
    p.add_argument("--run-id", required=True, nargs="+",
                   help="run(s) whose scans are under data/scans; later wins")
    p.add_argument("--cases-yaml", type=Path, default=CASES_YAML)
    args = p.parse_args(argv)

    report = json.loads((args.src / "benchmark.json").read_text())
    rescored = rescore(report, [SCANS_DIR / r for r in args.run_id], _manifests(args.cases_yaml))

    out_json = args.out / "benchmark.json"
    write_report(out_json, rescored)
    (args.out / "benchmark.txt").write_text(render_table(rescored))
    generate_pdf(out_json, args.out / "benchmark.pdf", args.cases_yaml)
    print(render_table(rescored))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

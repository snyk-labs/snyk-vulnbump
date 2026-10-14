"""Validate baselines for all cases in parallel.

Runs install → build → test → scan for each case using the same Docker
entrypoint as the benchmark harness, but processes multiple cases concurrently
to cut wall-clock time from hours to ~1 hour.

Usage:
    uv run python validate_baselines.py --workers 5
    uv run python validate_baselines.py --workers 5 --case reactivex-rxjava
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import yaml

from harness.benchmark import run_baseline
from harness.cli_binary import default_snyk_binary, fetch_preview_cli, pin_binary
from harness.images import apply_scenario_image
from harness.scans import generate_run_id, preserve_scan
from harness.scenario import HarnessConfig, Scenario

SCRIPTS_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = SCRIPTS_DIR.parent
CASES_DIR = BENCHMARK_DIR / "cases"
REPOS_DIR = BENCHMARK_DIR / "data" / "repos"
REPORT_DIR = BENCHMARK_DIR / "data" / "baseline-validation"


def load_scenarios(only: list[str] | None = None) -> list[Scenario]:
    data = yaml.safe_load((CASES_DIR / "cases.yaml").read_text())
    scenarios = []
    for case in data["cases"]:
        s = Scenario(**case["inputs"])
        if only and s.name not in only:
            continue
        scenarios.append(apply_scenario_image(s, mode="local"))
    return scenarios


def validate_one(scenario: Scenario, cfg: HarnessConfig, run_id: str) -> dict:
    try:
        result, plan, work, out = run_baseline(scenario, cfg, REPOS_DIR)
        preserve_scan(run_id, scenario.name, out, phase="before")
        summary = {
            "name": scenario.name,
            "valid": result.valid,
            "build_ok": result.build_ok,
            "tests_exit": result.tests_exit,
            "tests_passed_count": result.tests_passed_count,
            "tests_identified": result.tests_identified,
            "scan_ok": result.scan_ok,
            "plan_present": result.plan_present,
            "plan_groups": result.plan_groups,
            "vulns": result.vulns,
            "invalid_reasons": result.invalid_reasons,
        }
        subprocess.run(["sudo", "rm", "-rf", str(work), str(out)],
                       capture_output=True)
    except Exception as e:
        summary = {
            "name": scenario.name,
            "valid": False,
            "invalid_reasons": [f"exception: {e}"],
        }
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--workers", type=int, default=5)
    p.add_argument("--case", action="append", default=None)
    p.add_argument("--timeout-multiplier", type=float, default=1.5)

    p.add_argument("--local", action="store_true",
                   help="use the build at build/snyk-local instead of the preview CLI")
    args = p.parse_args()

    mode = "local" if args.local else "preview"
    cfg = HarnessConfig(
        mode=mode,
        snyk_binary=default_snyk_binary(mode),
        timeout_multiplier=args.timeout_multiplier,
    )
    if mode == "preview":
        fetch_preview_cli()
    cfg.validate(needs_llm=False)
    cfg.snyk_binary, _ = pin_binary(cfg.snyk_binary)

    scenarios = load_scenarios(args.case)
    if not scenarios:
        print("no cases selected", file=sys.stderr)
        return 1

    run_id = generate_run_id()
    print(f"[validate] {len(scenarios)} cases, {args.workers} workers (run {run_id})", file=sys.stderr)

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(validate_one, s, cfg, run_id): s.name
            for s in scenarios
        }
        for future in as_completed(futures):
            name = futures[future]
            r = future.result()
            results.append(r)
            status = "OK" if r["valid"] else f"INVALID ({', '.join(r.get('invalid_reasons', []))})"
            print(f"[validate] [{len(results)}/{len(scenarios)}] {name}: {status}",
                  file=sys.stderr, flush=True)

    report_path = REPORT_DIR / f"{run_id}.json"
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "valid": sum(1 for r in results if r["valid"]),
        "invalid": sum(1 for r in results if not r["valid"]),
        "results": sorted(results, key=lambda r: r["name"]),
    }
    report_path.write_text(json.dumps(report, indent=2))
    print(f"\n[validate] Done: {report['valid']}/{report['total']} valid", file=sys.stderr)
    print(f"[validate] Report: {report_path}", file=sys.stderr)

    invalid = [r for r in results if not r["valid"]]
    if invalid:
        print(f"\n[validate] {len(invalid)} invalid cases:", file=sys.stderr)
        for r in sorted(invalid, key=lambda x: x["name"]):
            print(f"  {r['name']}: {', '.join(r.get('invalid_reasons', []))}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""CLI entry point for the verified-fix benchmark.

    uv run python -m cli.benchmark --harness evo-remediation-agent
    uv run python -m cli.benchmark --harness evo-remediation-agent,claude-code-snyk-scan,claude-code-unaided

Loads cases.yaml directly rather than through pydantic-evals: the scored unit
here is a case carrying N attempts across several agents, not one output per case,
so the framework's per-case evaluator model does not fit.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import yaml

from harness.agents import (
    AGENT_FOR, ALL_AGENTS, HARNESSES, MODES,
    PM_BUMP_AGENTS,
)
from harness.benchmark import run_case
from harness.outcome import CaseResult
from harness.images import apply_scenario_image
from harness.extra_certs import CERT_ENV_VARS, cert_source, host_cert
from harness.maven_mirror import check_mirror
from harness.scans import generate_run_id, preserve_scan
from harness.scenario import HarnessConfig, Scenario
from harness.cli_binary import cli_commit, default_snyk_binary, fetch_preview_cli, pin_binary
from harness.mode import mount_snyk_binary

from .pdf_report import generate_pdf
from .report import build_report, render_table, write_report

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
BENCHMARK_DIR = SCRIPTS_DIR.parent
CASES_DIR = BENCHMARK_DIR / "cases"
REPOS_DIR = BENCHMARK_DIR / "data" / "repos"


def snyk_binary_version(binary: Path) -> str:
    try:
        out = subprocess.run([str(binary), "--version"], capture_output=True,
                             text=True, timeout=30, check=True)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def load_scenarios(
    mode: str,
    only: list[str] | None,
    cases_dir: Path = CASES_DIR,
    skip_no_safe_fix: bool = False,
) -> list[Scenario]:
    data = yaml.safe_load((cases_dir / "cases.yaml").read_text())
    scenarios = []
    for case in data["cases"]:
        s = Scenario(**case["inputs"])
        if only and s.name not in only:
            continue
        # `expected_outcome: no_safe_fix` means the correct answer is to decline.
        # There is no fix to verify, so this harness scores such a case 0 and it
        # reads as a failure. Dropping it is more honest than reporting it.
        meta = case.get("metadata") or {}
        if skip_no_safe_fix and meta.get("expected_outcome") == "no_safe_fix":
            continue
        scenarios.append(apply_scenario_image(s, mode=mode))
    return scenarios


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="cli.benchmark")
    m = p.add_mutually_exclusive_group()
    m.add_argument("--release", action="store_const", const="release", dest="cli_mode")
    m.add_argument("--preview", action="store_const", const="preview", dest="cli_mode")
    m.add_argument("--local", action="store_const", const="local", dest="cli_mode")
    p.add_argument("--case", action="append", default=None,
                   help="run only this case (repeatable)")
    p.add_argument("--harness", default="evo-remediation-agent",
                   help=f"comma-separated harnesses to evaluate: {','.join(HARNESSES)}")
    p.add_argument("--mode", default="single-upgrade",
                   help="single-upgrade (one upgrade per fresh repo, --issue-ids scoped to "
                        "that package), the only mode")
    p.add_argument("--agents", default=None,
                   help="advanced: explicit agent list, overrides --harness/--mode. "
                        f"Any of: {','.join(ALL_AGENTS)}")
    p.add_argument("--model", default="",
                   help="one model for EVERY agent; leave unset to use each tool's default")
    p.add_argument("--max-turns", type=int, default=0,
                   help="shared agent budget: Evo --agent-max-iterations and "
                        "claude --max-turns both take this. 0 = Evo's default "
                        "(100 + 10 for breakability) and claude --max-turns 110")
    p.add_argument("--concurrency", type=int, default=1,
                   help="attempts to run in parallel within a case. Isolation "
                        "makes this safe; the binding limit is the LLM "
                        "provider's rate limit, not CPU.")
    p.add_argument("--parallel-repos", type=int, default=4,
                   help="repos to run at once. Each repo has its own containers "
                        "and temp dirs; the limits are RAM, disk on / and the "
                        "LLM provider's rate limit. Use 1 for serial runs.")
    p.add_argument("--timeout-multiplier", type=float, default=1.0,
                   help="scale every case's timeout_s. Raise it when running "
                        "under emulation or with --concurrency or --parallel-repos "
                        "> 1, where the per-case defaults are too tight.")
    p.add_argument("--repeats", type=int, default=1,
                   help="every agent is stochastic; use >=3 for a publishable number")
    p.add_argument("--price-in", type=float, default=0.0,
                   help="USD per million input tokens, to cost Evo runs")
    p.add_argument("--price-out", type=float, default=0.0,
                   help="USD per million output tokens, to cost Evo runs")
    p.add_argument("--strict-collateral", action="store_true",
                   help="fail single-upgrade attempts that bump a direct dependency "
                        "outside the fix's lane (always recorded either way)")
    p.add_argument("--cases-dir", default=None,
                   help="directory holding cases.yaml. Defaults to benchmarking/cases.")
    p.add_argument("--repos-dir", default=None,
                   help="directory holding pre-cloned repos. Defaults to benchmarking/data/repos.")
    p.add_argument("--skip-no-safe-fix", action="store_true",
                   help="drop cases whose contract expects a decline. This "
                        "harness scores verified fixes and has no way to "
                        "express 'correctly declined', so those cases read as "
                        "failures rather than as a result.")
    p.add_argument("--report", default=None, help="path for the JSON report")
    p.add_argument("--keep-artifacts", action="store_true")
    p.set_defaults(cli_mode="preview")
    return p.parse_args(argv)


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def select_agents(args: argparse.Namespace) -> tuple[str, ...]:
    """Explicit --agents wins; otherwise every --harness x --mode combination."""
    if args.agents:
        agents = _split(args.agents)
        unknown = [a for a in agents if a not in ALL_AGENTS]
        if unknown:
            raise ValueError(f"unknown agent(s): {', '.join(unknown)}")
        return tuple(agents)
    harnesses = _split(args.harness)
    modes = _split(args.mode)
    bad = [h for h in harnesses if h not in HARNESSES] + [m for m in modes if m not in MODES]
    if bad or not harnesses or not modes:
        raise ValueError(
            f"invalid --harness/--mode: {', '.join(bad) or '(empty)'}; "
            f"harness in {HARNESSES}, mode in {MODES}"
        )
    missing = [f"{h}/{m}" for h in harnesses for m in modes if (h, m) not in AGENT_FOR]
    if missing:
        raise ValueError(f"no agent for --harness/--mode: {', '.join(missing)}")
    return tuple(AGENT_FOR[(h, m)] for h in harnesses for m in modes)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        agents = select_agents(args)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2

    cfg = HarnessConfig(
        mode=args.cli_mode,
        snyk_binary=default_snyk_binary(args.cli_mode),
        model=args.model,
        agent_max_iterations=args.max_turns,
        strict_collateral=args.strict_collateral,
        timeout_multiplier=args.timeout_multiplier,
        price_in_per_mtok=args.price_in,
        price_out_per_mtok=args.price_out,
    )
    if args.cli_mode == "preview":
        fetch_preview_cli()
    try:
        cfg.validate(needs_llm=any(a not in PM_BUMP_AGENTS for a in agents))
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    binary_sha256 = commit = None
    if mount_snyk_binary(cfg.mode):
        # Read the commit before pinning: it needs the binary's home checkout.
        if cfg.mode == "local":
            commit = cli_commit(cfg.snyk_binary)
        cfg.snyk_binary, binary_sha256 = pin_binary(cfg.snyk_binary)
        cfg.snyk_version = snyk_binary_version(cfg.snyk_binary)
        print(f"[benchmark] cli commit {commit or '-'}, binary sha256 {binary_sha256[:16]}, "
              f"snyk {cfg.snyk_version or '-'}", file=sys.stderr)

    # State the TLS posture before spending an hour on containers. A missing CA
    # on an intercepted network does not raise — it produces partial installs
    # behind a zero exit code, and every case then reports as an invalid
    # fixture. Saying which cert is in play makes that failure self-evident
    # instead of a debugging session.
    cert, source = host_cert(), cert_source()
    if cert:
        print(f"[benchmark] extra CA: {cert} (from ${source})", file=sys.stderr)
    else:
        print(
            "[benchmark] WARNING: no extra CA certificate configured "
            f"(checked {', '.join('$' + v for v in CERT_ENV_VARS)}). On a "
            "TLS-intercepting network installs will silently half-complete and "
            "every case will report as an invalid fixture.",
            file=sys.stderr,
        )

    # A mirror serving corrupt POMs fails nothing; it silently changes every
    # Java result. Refuse to start rather than discover it from the reports.
    if mirror := os.environ.get("MAVEN_MIRROR_URL"):
        if mirror_problems := check_mirror(mirror):
            print(f"[benchmark] Maven mirror {mirror} is unhealthy:", file=sys.stderr)
            for problem in mirror_problems:
                print(f"  - {problem}", file=sys.stderr)
            return 2
        print(f"[benchmark] Maven mirror: {mirror} (canary OK)", file=sys.stderr)

    cases_dir = Path(args.cases_dir) if args.cases_dir else CASES_DIR
    repos_dir = Path(args.repos_dir) if args.repos_dir else REPOS_DIR
    if not (cases_dir / "cases.yaml").exists():
        print(f"no cases.yaml under {cases_dir}", file=sys.stderr)
        return 2
    if not repos_dir.is_dir():
        print(f"repos directory not found: {repos_dir}. Run prepare_data.py first.", file=sys.stderr)
        return 2
    scenarios = load_scenarios(
        args.cli_mode, args.case, cases_dir, skip_no_safe_fix=args.skip_no_safe_fix
    )
    if not scenarios:
        print("no cases selected", file=sys.stderr)
        return 2

    if args.repeats > 1:
        print(f"note: --repeats {args.repeats} runs the whole suite that many "
              "times; results are appended per repeat", file=sys.stderr)

    run_id = generate_run_id()
    # Same run id as data/scans/<run_id>/, so a report and its artefacts pair up.
    out_path = Path(args.report) if args.report else (
        BENCHMARK_DIR / "reports" / run_id / "benchmark.json"
    )

    def snapshot(cases_so_far: list, complete: bool) -> dict:
        rep = build_report(
            cases_so_far,
            mode=args.cli_mode,
            snyk_version=cfg.snyk_version,
            binary_sha256=binary_sha256,
            cli_commit=commit,
            provider="anthropic",
            model=args.model,
            repeats=args.repeats,
            generated_at=datetime.now(timezone.utc).isoformat(),
            strict_collateral=cfg.strict_collateral,
            agent_max_iterations=args.max_turns,
            price_in_per_mtok=args.price_in,
            price_out_per_mtok=args.price_out,
        )
        # A partial file must say so. Someone opening it mid-run should not
        # read "Evo 2/2" as the final answer for a ten-case sweep.
        rep["complete"] = complete
        rep["cases_expected"] = len(scenarios) * args.repeats
        rep["cases_done"] = len(cases_so_far)
        return rep

    print(f"[benchmark] run {run_id}", file=sys.stderr, flush=True)

    jobs = [(rep, s) for rep in range(args.repeats) for s in scenarios]
    done: dict[int, CaseResult] = {}
    reap: list[tuple[Path, Path]] = []
    lock = threading.Lock()

    def run_job(index: int) -> None:
        rep, s = jobs[index]
        suffix = f" (repeat {rep + 1})" if args.repeats > 1 else ""

        def say(msg: str) -> None:
            # Lines from parallel repos interleave, so each names its repo.
            if args.parallel_repos > 1 and not msg.startswith(s.name):
                msg = f"{s.name}: {msg.strip()}"
            print(f"[benchmark] {msg}{suffix}", file=sys.stderr, flush=True)

        case_result, dirs = run_case(
            s, cfg, repos_dir, agents=agents,
            concurrency=args.concurrency, progress=say,
        )

        # Preserve scan JSONs before cleanup. dirs[0..baseline_count-1]
        # are baseline attempts; the last successful one has snyk-test-before.json.
        # Remaining dirs are fix attempts aligned with case_result.attempts.
        baseline_count = len(dirs) - len(case_result.attempts)
        scan_case = s.name if args.repeats == 1 else f"{s.name}/repeat-{rep + 1}"
        if baseline_count > 0:
            preserve_scan(run_id, scan_case, dirs[baseline_count - 1][1], phase="before")
        for attempt, (_, attempt_out) in zip(
            case_result.attempts, dirs[baseline_count:]
        ):
            preserve_scan(
                run_id, scan_case, attempt_out,
                phase="after", agent=attempt.agent, group_label=attempt.label,
            )

        if args.keep_artifacts:
            with lock:
                reap.extend(dirs)
        else:
            for work_dir, out_dir in dirs:
                shutil.rmtree(work_dir, ignore_errors=True)
                shutil.rmtree(out_dir, ignore_errors=True)
        if not case_result.baseline.valid:
            say(f"{s.name}: INVALID ({', '.join(case_result.baseline.invalid_reasons)})")

        # Write after every case. A multi-hour sweep that dies at case 8
        # should still hand back the first seven, and someone watching
        # should be able to read partial results without waiting.
        with lock:
            done[index] = case_result
            write_report(out_path, snapshot([done[k] for k in sorted(done)], complete=False))
            print(f"[benchmark] wrote partial results "
                  f"({len(done)}/{len(jobs)} cases) -> {out_path}",
                  file=sys.stderr, flush=True)

    with ThreadPoolExecutor(max_workers=max(1, args.parallel_repos)) as pool:
        for f in [pool.submit(run_job, i) for i in range(len(jobs))]:
            f.result()
    results = [done[k] for k in sorted(done)]

    report = snapshot(results, complete=True)
    write_report(out_path, report)

    table = render_table(report)
    table_path = out_path.with_suffix(".txt")
    table_path.write_text(table + "\n")

    print()
    print(table)
    print()
    print(f"report: {out_path}")
    print(f"table:  {table_path}")
    print(f"pdf:    {generate_pdf(out_path)}")

    if not args.keep_artifacts:
        for work, out in reap:
            shutil.rmtree(work, ignore_errors=True)
            shutil.rmtree(out, ignore_errors=True)
    else:
        print(f"artefacts kept in {len(reap)} temp dirs (--keep-artifacts)")

    # Exit 1 only when nothing could be measured. A losing agent is a result,
    # not an error.
    measurable = any(c.baseline.valid for c in results)
    return 0 if measurable else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Merge benchmark reports.

A full sweep is hours long, so re-running everything to pick up two fixed cases
is wasteful. This merges a follow-up run's cases into a base report, recomputing
the totals so the result is indistinguishable from one complete run.

    uv run python -m cli.merge_reports base.json extra.json -o merged.json

Later files win on case-name collisions, which is what you want when the
follow-up run is the corrected one.

Reports from different setups (model, snyk CLI build, collateral mode, or an
agent given different inputs) are refused unless --allow-mismatch is passed,
in which case the differences are kept as warnings.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness.agents import ALL_AGENTS
from harness.outcome import AgentAttempt, BaselineResult, CaseResult

from .report import agent_access, agent_totals


def _baseline(b: dict) -> BaselineResult:
    # `valid` and `invalid_reasons` are computed, not stored.
    return BaselineResult(**{k: v for k, v in b.items() if k not in ("valid", "invalid_reasons")})


def _to_case_results(report: dict) -> list[CaseResult]:
    """One CaseResult per (case, repeat), so each attempt meets its own baseline
    and attempts are only paired within a repeat."""
    out = []
    for name, c in report.get("cases", {}).items():
        baselines = c.get("baselines") or [c["baseline"]]
        by_repeat: dict[int, list[AgentAttempt]] = {i: [] for i in range(len(baselines))}
        for a in c.get("attempts", []):
            r = a.get("repeat") or 0
            by_repeat.setdefault(r if r < len(baselines) else 0, []).append(AgentAttempt(**a))
        for r, attempts in sorted(by_repeat.items()):
            out.append(CaseResult(name=name, baseline=_baseline(baselines[r]), attempts=attempts))
    return out


# Baseline fields that define the exam. Attempts graded against baselines that
# differ in these were not sitting the same test.
_EXAM_KEYS = ("plan_groups", "vulns", "tests_passed_count")


def _exam(case: dict) -> list[tuple]:
    return [tuple(b.get(k) for k in _EXAM_KEYS) for b in case.get("baselines") or [case["baseline"]]
            if b.get("valid")]


def baseline_warnings(reports: list[dict]) -> list[str]:
    """Cases whose valid baselines differ across the merged reports."""
    seen: dict[str, set[tuple]] = {}
    for r in reports:
        for name, c in r.get("cases", {}).items():
            seen.setdefault(name, set()).update(_exam(c))
    return [
        f"{name}: baselines differ across merged reports "
        f"({', '.join(_EXAM_KEYS)}: {', '.join(map(str, sorted(exams, key=str)))})"
        for name, exams in sorted(seen.items()) if len(exams) > 1
    ]


# Run settings every merged report must share.
_RUN_KEYS = (("llm", "model"), ("cli", "snyk_version"), ("cli", "binary_sha256"),
             ("fairness", "strict_collateral"),
             ("fairness", "agent_max_iterations"), ("fairness", "claude_turns_per_upgrade"))


class MergeMismatch(ValueError):
    pass


def config_mismatches(reports: list[dict]) -> tuple[list[str], list[str]]:
    """(settings that differ across reports, agents whose inputs can't be checked)."""
    problems, unchecked = [], []
    for section, key in _RUN_KEYS:
        values = [(r.get(section) or {}).get(key) for r in reports]
        if len({repr(v) for v in values}) > 1:
            problems.append(f"{section}.{key} differs: " + ", ".join(
                f"report {i}: {v!r}" for i, v in enumerate(values, 1)))
    # One agent id must mean one setup. "n/m" (target only where one exists)
    # is compatible with either; True in one report and False in another isn't.
    seen: dict[tuple[str, str], dict[bool, list[int]]] = {}
    for i, r in enumerate(reports, 1):
        access = (r.get("fairness") or {}).get("agent_access") or {}
        missing = []
        for agent in sorted({a["agent"] for c in r.get("cases", {}).values()
                             for a in c.get("attempts", [])}):
            fields = access.get(agent) or {}
            if not any(v is not None for v in fields.values()):
                missing.append(agent)
            for field, v in fields.items():
                if isinstance(v, bool):
                    seen.setdefault((agent, field), {}).setdefault(v, []).append(i)
        if missing:
            unchecked.append(f"report {i}: inputs not recorded for {', '.join(missing)}; "
                             "cannot check they match the other reports")
    for (agent, field), by_value in sorted(seen.items()):
        if len(by_value) > 1:
            problems.append(f"{agent}: {field} differs: " + ", ".join(
                f"{v} in report(s) {', '.join(map(str, ids))}" for v, ids in by_value.items()))
    return problems, unchecked


def _baseline_valid(case: dict) -> bool:
    return bool((case.get("baseline") or {}).get("valid"))


def _merge_by_agent(reports: list[dict]) -> dict[str, dict]:
    """Union attempts within a case, replacing per AGENT rather than per case.

    Whole-case replacement cannot express either of the two merges we actually
    need:

      * Adding a new agent to an existing sweep. Replacing the case wholesale
        drops every agent the follow-up run did not include — merging a
        claude-code-unaided-only report into a Evo + claude-code-snyk-scan one would
        silently delete Evo and claude-code-snyk-scan.
      * Re-running one agent on one case. The corrected attempts should displace
        the broken ones for that agent and leave the rest alone.

    One rule covers both: a later report's agent replaces that agent's attempts,
    and agents it does not mention are untouched.

    The baseline is taken from whichever report has a VALID one, because the
    reason for a re-run is usually that the baseline failed the first time.
    """
    cases: dict[str, dict] = {}
    for r in reports:
        for name, incoming in r.get("cases", {}).items():
            if name not in cases:
                cases[name] = json.loads(json.dumps(incoming))
                continue
            base = cases[name]
            incoming_agents = {a["agent"] for a in incoming.get("attempts", [])}
            base["attempts"] = [
                a for a in base.get("attempts", [])
                if a["agent"] not in incoming_agents
            ] + list(incoming.get("attempts", []))
            base["runs"] = max(base.get("runs", 1), incoming.get("runs", 1))
            if not _baseline_valid(base) and _baseline_valid(incoming):
                base["baseline"] = incoming["baseline"]
            # Same rule per repeat, so each attempt still meets a baseline.
            mine, theirs = base.get("baselines") or [], incoming.get("baselines") or []
            for i, b in enumerate(theirs):
                if i >= len(mine):
                    mine.append(b)
                elif not mine[i].get("valid") and b.get("valid"):
                    mine[i] = b
            if mine:
                base["baselines"] = mine
                base["valid_runs"] = sum(1 for b in mine if b.get("valid"))
                base["invalid_runs"] = len(mine) - base["valid_runs"]
    return cases


def merge(reports: list[dict], by_agent: bool = False, allow_mismatch: bool = False) -> dict:
    problems, unchecked = config_mismatches(reports)
    if problems and not allow_mismatch:
        raise MergeMismatch("reports were run with different setups:\n  "
                            + "\n  ".join(problems))
    merged = dict(reports[0])
    if by_agent:
        cases = _merge_by_agent(reports)
    else:
        cases: dict[str, dict] = {}
        for r in reports:
            cases.update(r.get("cases", {}))  # later wins
    merged["cases"] = cases

    results = _to_case_results({"cases": cases})
    merged["totals"] = {agent: agent_totals(results, agent) for agent in ALL_AGENTS}
    # A case is invalid only if none of its repeats had a valid baseline.
    valid_names = {c.name for c in results if c.baseline.valid}
    merged["invalid_cases"] = {
        c.name: c.baseline.invalid_reasons for c in results if c.name not in valid_names
    }
    merged["invalid_count"] = len(merged["invalid_cases"])
    merged["cases_done"] = len(cases)
    merged["complete"] = all(r.get("complete", False) for r in reports)
    merged["merged_from"] = len(reports)
    merged["fairness"] = {**(merged.get("fairness") or {}), "agent_access": agent_access(results)}
    merged["warnings"] = (
        problems + unchecked + (baseline_warnings(reports) if by_agent else [])
    )
    for w in merged["warnings"]:
        print(f"warning: {w}", file=sys.stderr)
    return merged


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cli.merge_reports")
    p.add_argument("reports", nargs="+", help="report JSONs; later files win on collision")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--by-agent", action="store_true",
                   help="union attempts within a case, replacing per agent rather "
                        "than per case. Use when adding an agent to an existing "
                        "sweep, or re-running one agent on one case.")
    p.add_argument("--allow-mismatch", action="store_true",
                   help="merge reports whose model, snyk CLI, collateral mode "
                        "or agent inputs differ, recording the differences as "
                        "warnings instead of refusing")
    args = p.parse_args(argv)

    loaded = [json.loads(Path(f).read_text()) for f in args.reports]
    try:
        merged = merge(loaded, by_agent=args.by_agent, allow_mismatch=args.allow_mismatch)
    except MergeMismatch as exc:
        print(f"{exc}\npass --allow-mismatch to merge anyway", file=sys.stderr)
        return 2
    Path(args.out).write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")

    from .report import render_table
    print(render_table(merged))
    print(f"\nmerged {len(loaded)} reports -> {args.out} ({merged['cases_done']} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

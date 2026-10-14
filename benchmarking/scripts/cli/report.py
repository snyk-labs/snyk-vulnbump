"""The benchmark's output: a comparison, not a regression snapshot.

The headline is one table — agent x case x verified/total — plus the two things
that make it defensible: what each agent cost, and the fairness terms it ran
under. A verified-fix win that costs 10x is a different claim from one that
does not, so cost is published next to the score rather than in an appendix.

`claimed_not_fixed` is reported separately because it is not the inverse of
verified. It counts attempts where an agent asserted a fix the harness's own
rescan contradicts, which is the diagnostic the whole benchmark grew out of.
"""

from __future__ import annotations

import json
import random
import subprocess
from pathlib import Path

from harness.agents import (
    ALL_AGENTS,
    CLAUDE_DEFAULT_MAX_TURNS,
    HARNESS_MODE_FOR,
    agent_display,
)
from harness.claude_image import CLAUDE_CODE_VERSION
from harness.outcome import AgentAttempt, CaseResult
from harness.verdict import REASON_RESCAN_FAILED

SCHEMA_VERSION = 5

SEVERITIES = ("critical", "high", "medium", "low")

HARNESS_ERROR = "harness-error"
BOOTSTRAP_SEED = 0
BOOTSTRAP_RESAMPLES = 1000


def _get(a, key: str, default=None):
    """Field access for both AgentAttempt models and their JSON dicts."""
    return a.get(key, default) if isinstance(a, dict) else getattr(a, key, default)


def is_harness_error(a) -> bool:
    """The harness, not the agent, failed (e.g. auth/startup): excluded from every rate."""
    return bool(_get(a, "harness_error", False)) or HARNESS_ERROR in (_get(a, "reasons") or [])


def fixable_counts(attempts) -> tuple[int, int]:
    """(fixable, cleared) instances for one agent's attempts against one baseline.

    An instance shared by several single-upgrade attempts is fixable once, and only
    fully cleared if every group covering it cleared its own path. Older
    results without `instances` fall back to summing the per-attempt counts.
    """
    if not any(_get(a, "instances") for a in attempts):
        return (
            sum(_get(a, "fixable_total") or 0 for a in attempts),
            sum(_get(a, "fixable_cleared") or 0 for a in attempts),
        )
    total = {tuple(k) for a in attempts for k in _get(a, "instances") or []}
    return len(total), len(total - _missed(attempts))


def _missed(attempts) -> set[tuple[str, str]]:
    """Target instances some attempt left uncleared (all of them on a failed rescan)."""
    out: set[tuple[str, str]] = set()
    for a in attempts:
        out |= {tuple(k) for k in _get(a, "instances") or []} - {
            tuple(k) for k in _get(a, "instances_cleared") or []
        }
    return out


def rescan_failed(a) -> bool:
    return REASON_RESCAN_FAILED in (_get(a, "reasons") or [])


def remaining_counts(attempts, vuln_facts: list[dict]) -> tuple[dict[str, int], int]:
    """Remaining fixable instances by severity for one agent against one
    baseline, and how many of those only a failed rescan vouches for.

    The union of uncleared targets, so a single-upgrade attempt does not count
    other groups' or unfixable vulns. Older results without `instances` fall
    back to summing the per-attempt counts.
    """
    if not any(_get(a, "instances") for a in attempts):
        out: dict[str, int] = {}
        for a in attempts:
            _add_counts(out, _get(a, "remaining_by_severity") or {})
        return out, 0
    severity = {(f["manifest"], f["id"]): f.get("severity") for f in vuln_facts}
    missed = _missed(attempts)
    unverified = missed - _missed([a for a in attempts if not rescan_failed(a)])
    counts: dict[str, int] = {}
    for k in missed:
        _add_counts(counts, {severity.get(k) or "unknown": 1})
    return counts, len(unverified)


def cluster_stats(per_repo: dict[str, tuple[int, int]]) -> tuple[float | None, list[float] | None]:
    """Macro rate (mean of per-repo rates) and a percentile-bootstrap 95% CI of
    that same macro, resampling repos, since units within a repo correlate."""
    rates = [n / d for n, d in per_repo.values() if d]
    if not rates:
        return None, None
    macro = round(sum(rates) / len(rates), 3)
    if len(rates) < 2:
        return macro, None
    rng = random.Random(BOOTSTRAP_SEED)
    samples = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        samples.append(sum(rng.choice(rates) for _ in rates) / len(rates))
    samples.sort()
    lo = samples[int(0.025 * BOOTSTRAP_RESAMPLES)]
    hi = samples[int(0.975 * BOOTSTRAP_RESAMPLES) - 1]
    return macro, [round(lo, 3), round(hi, 3)]


def _green(a) -> bool:
    """Deps still resolve, the repo builds, keeps its baseline tests, and boots."""
    return a.deps_ok is not False and a.build_ok is not False and a.tests_ok is True and a.boots is not False


def _add_counts(into: dict[str, int], counts: dict[str, int]) -> None:
    for k, v in counts.items():
        into[k] = into.get(k, 0) + v


def _sev(counts: dict[str, int]) -> str:
    return "/".join(str(counts.get(s, 0)) for s in SEVERITIES)


def _ktok(n: int) -> str:
    return f"{n / 1000:,.1f}K"



def _macro_cell(rate: float | None, ci: list[float] | None) -> str:
    if rate is None:
        return "-"
    return f"{rate:.2f}" + (f" [{ci[0]:.2f},{ci[1]:.2f}]" if ci else "")


def _git_sha() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5, check=True,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


def agent_totals(cases: list[CaseResult], agent: str) -> dict:
    """Aggregate one agent across every valid case.

    Invalid cases contribute nothing to either side of the ratio: a fixture
    that was already broken is not evidence about any agent. Neither do
    harness errors, which are counted separately.
    """
    verified = groups = claimed_not_fixed = harness_errors = 0
    tests_modified = policy_modified = unrelated_bumps = 0
    per_repo_pass: dict[str, tuple[int, int]] = {}
    per_repo_cleared: dict[str, tuple[int, int]] = {}
    tokens = in_tok = out_tok = 0
    latency = cost = 0.0
    fixable_total = fixable_cleared = introduced = green = deps_ok = build_ok = tests_kept = 0
    rescans_failed = remaining_unverified = new_projects = moved = scans_without_wrapper = 0
    remaining: dict[str, int] = {}
    failure_categories: dict[str, int] = {}
    introduced_sev: dict[str, int] = {}
    for case in cases:
        if not case.baseline.valid:
            continue
        attempts = case.attempts_for(agent)
        harness_errors += sum(1 for a in attempts if is_harness_error(a))
        attempts = [a for a in attempts if not is_harness_error(a)]
        if not attempts:
            continue
        v = sum(1 for a in attempts if a.verified)
        verified += v
        groups += len(attempts)
        claimed_not_fixed += sum(1 for a in attempts if a.claimed_not_fixed)
        fx, cl = fixable_counts(attempts)
        fixable_total += fx
        fixable_cleared += cl
        n, d = per_repo_pass.get(case.name, (0, 0))
        per_repo_pass[case.name] = (n + v, d + len(attempts))
        n, d = per_repo_cleared.get(case.name, (0, 0))
        per_repo_cleared[case.name] = (n + cl, d + fx)
        rem, unverified = remaining_counts(attempts, case.baseline.vuln_facts)
        _add_counts(remaining, rem)
        remaining_unverified += unverified
        # Unioned like remaining: single-upgrade attempts can share an instance.
        moved += len({tuple(k) for a in attempts for k in _get(a, "instances_moved") or []})
        for a in attempts:
            tokens += a.total_tokens
            in_tok += a.input_tokens
            out_tok += a.output_tokens
            latency += a.latency_s
            cost += a.cost_usd
            tests_modified += bool(_get(a, "tests_modified", False))
            policy_modified += bool(_get(a, "snyk_policy_modified", False))
            unrelated_bumps += bool(_get(a, "unexpected_collateral"))
            # A failed rescan's new vulns are unknown, counted in rescans_failed.
            introduced += a.introduced_count or 0
            rescans_failed += rescan_failed(a)
            new_projects += bool(a.new_projects)
            scans_without_wrapper += bool(_get(a, "scan_without_wrapper", False))
            green += _green(a)
            deps_ok += a.deps_ok is not False
            build_ok += a.build_ok is not False
            tests_kept += a.tests_ok is True
            if a.failure:
                _add_counts(failure_categories, {a.failure["category"]: 1})
            _add_counts(introduced_sev, a.introduced_by_severity)
    macro_rate, rate_ci = cluster_stats(per_repo_pass)
    macro_cleared, cleared_ci = cluster_stats(per_repo_cleared)
    return {
        "verified": verified,
        "attempts": groups,
        "harness_errors": harness_errors,
        "repos": len(per_repo_pass),
        "rate": round(verified / groups, 3) if groups else None,
        # Macro = mean of per-repo rates; CI = repo-clustered bootstrap of the macro.
        "macro_rate": macro_rate,
        "rate_ci95": rate_ci,
        "claimed_not_fixed": claimed_not_fixed,
        "tests_modified": tests_modified,
        "snyk_policy_modified": policy_modified,
        # Attempts that bumped a direct dependency outside the fix's lane.
        "unrelated_bumps": unrelated_bumps,
        "fixable_total": fixable_total,
        "fixable_cleared": fixable_cleared,
        "cleared_rate": round(fixable_cleared / fixable_total, 3) if fixable_total else None,
        "macro_cleared_rate": macro_cleared,
        "cleared_rate_ci95": cleared_ci,
        # Fixable instances not cleared, failed rescans included; of those,
        # remaining_unverified only a failed rescan reports.
        "remaining_by_severity": remaining,
        "remaining_unverified": remaining_unverified,
        # Of the remaining, instances the agent moved onto a new direct dependency.
        "moved": moved,
        "failure_categories": failure_categories,
        "introduced_count": introduced,
        "introduced_by_severity": introduced_sev,
        # Attempts whose new vulns are unknown, and attempts that left new
        # projects (scratch manifests) the counts above leave out.
        "rescans_failed": rescans_failed,
        "new_projects": new_projects,
        # Rescans retried without the Maven wrapper (see AgentAttempt).
        "scans_without_wrapper": scans_without_wrapper,
        "green": green,
        "green_rate": round(green / groups, 3) if groups else None,
        "deps_ok_rate": round(deps_ok / groups, 3) if groups else None,
        "build_ok_rate": round(build_ok / groups, 3) if groups else None,
        "tests_kept_rate": round(tests_kept / groups, 3) if groups else None,
        "tokens": tokens,
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "cost_usd": round(cost, 4),
        "wall_clock_s": round(latency, 1),
    }


def _merge_case_runs(cases: list[CaseResult]) -> dict:
    """Collapse repeated runs of the same case into one entry, concatenating
    their attempts.

    Aggregate figures then cover every pass, and per-attempt variance stays
    visible because the individual attempts are all still there. Each attempt
    carries `repeat`, an index into `baselines`, so it is judged against its own
    repeat's baseline; `baseline` is the first valid one (or the first).
    """
    out: dict[str, dict] = {}
    for c in cases:
        entry = out.setdefault(c.name, {"baselines": [], "attempts": [], "runs": 0})
        repeat = len(entry["baselines"])
        entry["baselines"].append(c.baseline.model_dump())
        entry["attempts"].extend({**a.model_dump(), "repeat": repeat} for a in c.attempts)
        entry["runs"] += 1
    for entry in out.values():
        valid = [b for b in entry["baselines"] if b["valid"]]
        entry["baseline"] = (valid or entry["baselines"])[0]
        entry["valid_runs"] = len(valid)
        entry["invalid_runs"] = entry["runs"] - len(valid)
    return out


def attempt_baseline_valid(case: dict, attempt: dict) -> bool:
    """Whether the baseline this attempt was graded against was valid."""
    baselines, r = case.get("baselines") or [], attempt.get("repeat")
    if r is not None and r < len(baselines):
        return bool(baselines[r].get("valid"))
    return bool(case["baseline"].get("valid"))


def case_valid_runs(case: dict) -> int:
    baselines = case.get("baselines")
    if baselines:
        return sum(1 for b in baselines if b.get("valid"))
    return int(bool(case["baseline"].get("valid")))


def turn_budget(max_iterations: int) -> str:
    evo = f"{max_iterations}/fix" if max_iterations else "100/fix (+10 breakability)"
    claude = max_iterations or CLAUDE_DEFAULT_MAX_TURNS
    return (f"evo-remediation-agent: {evo}, fresh per retry round, own setup budget; "
            f"claude: {claude} x upgrades, pooled")


def _all_some_none(values: list[bool | None]) -> bool | str | None:
    """True/False when every recorded attempt agrees, "n/m" when they don't,
    None when nothing was recorded."""
    known = [v for v in values if v is not None]
    if not known:
        return None
    if all(known) or not any(known):
        return known[0]
    return f"{sum(known)}/{len(known)}"


def agent_access(cases: list[CaseResult]) -> dict[str, dict]:
    """Per agent, whether it could run snyk, from what its attempts recorded."""
    attempts: dict[str, list[AgentAttempt]] = {}
    for c in cases:
        for a in c.attempts:
            attempts.setdefault(a.agent, []).append(a)
    return {
        agent: {
            "snyk_access": _all_some_none([a.snyk_access for a in atts]),
        }
        for agent, atts in sorted(attempts.items())
    }


def build_report(
    cases: list[CaseResult],
    *,
    mode: str,
    snyk_version: str,
    provider: str,
    model: str,
    repeats: int,
    generated_at: str,
    strict_collateral: bool,
    agent_max_iterations: int,
    price_in_per_mtok: float = 0.0,
    price_out_per_mtok: float = 0.0,
    binary_sha256: str | None = None,
    cli_commit: str | None = None,
) -> dict:
    valid_names = {c.name for c in cases if c.baseline.valid}
    invalid = {c.name for c in cases if c.name not in valid_names}
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "git_sha": _git_sha(),
        "repeats": repeats,
        "cli": {"mode": mode, "snyk_version": snyk_version,
                "binary_sha256": binary_sha256, "cli_commit": cli_commit},
        "llm": {
            "provider": provider,
            "model": model,
            "price_in_per_mtok": price_in_per_mtok,
            "price_out_per_mtok": price_out_per_mtok,
        },
        # The fairness terms travel with the numbers. A reader should not have
        # to go find out whether the control was handicapped. Each is derived
        # from the run config or the attempts, never asserted.
        "fairness": {
            "control": f"claude-code@{CLAUDE_CODE_VERSION}",
            # Every agent gets --model; with none, each tool uses its own default.
            "same_model_all_agents": bool(model),
            "agent_max_iterations": agent_max_iterations,
            "turn_budget": turn_budget(agent_max_iterations),
            "claude_turns_per_upgrade": agent_max_iterations or CLAUDE_DEFAULT_MAX_TURNS,
            # Claude Code's input count includes cache reads and cache creation;
            # Evo's is whatever its analytics report. Compare cost, not tokens.
            "claude_input_tokens_include_cache": True,
            "agent_access": agent_access(cases),
            "strict_collateral": strict_collateral,
        },
        # A case is invalid only if no repeat had a valid baseline.
        "invalid_cases": {
            c.name: c.baseline.invalid_reasons for c in cases if c.name in invalid
        },
        "agents": {
            agent: {"harness": hm[0], "mode": hm[1]}
            for agent, hm in HARNESS_MODE_FOR.items()
        },
        "totals": {agent: agent_totals(cases, agent) for agent in ALL_AGENTS},
        # Keyed by case name, with attempts ACCUMULATED across repeats rather
        # than overwritten. --repeats runs the whole suite N times, so a plain
        # dict comprehension keeps only the last pass and silently discards
        # every earlier one — which makes the repeats produce nothing while
        # still costing the hours. `runs` records how many passes contributed.
        "cases": _merge_case_runs(cases),
        "invalid_count": len(invalid),
    }


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def render_table(report: dict) -> str:
    """The thing that gets shown to people."""
    cases = report["cases"]
    agents = [a for a in ALL_AGENTS if report["totals"].get(a, {}).get("attempts")]
    if not agents:
        return "no attempts recorded"

    name_w = max([len("case"), len("cleared macro [95% CI]")] + [len(n) for n in cases])
    col_w = max(max(len(agent_display(a)) for a in agents) + 4, 19)

    multi_run = any(c.get("runs", 1) > 1 for c in cases.values())
    lines = []
    header = "case".ljust(name_w) + "".join(agent_display(a).rjust(col_w) for a in agents)
    if multi_run:
        header += "valid runs".rjust(12)
    lines.append(header)
    lines.append("-" * len(header))

    for name, case in cases.items():
        valid_runs = case_valid_runs(case)
        if not valid_runs:
            reasons = ", ".join(case["baseline"]["invalid_reasons"])
            lines.append(name.ljust(name_w) + f"  INVALID ({reasons})")
            continue
        row = name.ljust(name_w)
        for agent in agents:
            attempts = [
                a for a in case["attempts"]
                if a["agent"] == agent and attempt_baseline_valid(case, a)
            ]
            attempts = [a for a in attempts if not is_harness_error(a)]
            v = sum(1 for a in attempts if a["verified"])
            row += f"{v}/{len(attempts)}".rjust(col_w)
        if multi_run:
            row += f"{valid_runs}/{case.get('runs', 1)}".rjust(12)
        lines.append(row)

    lines.append("-" * len(header))
    verified_row = "PASS".ljust(name_w)
    cleared_row = "vulns cleared".ljust(name_w)
    claims_row = "claimed not fixed".ljust(name_w)
    macro_row = "PASS macro [95% CI]".ljust(name_w)
    cleared_macro_row = "cleared macro [95% CI]".ljust(name_w)
    flagged_rows = {
        "tests modified": "tests_modified",
        ".snyk modified": "snyk_policy_modified",
        "unrelated bumps": "unrelated_bumps",
        "vulns moved": "moved",
        "harness errors": "harness_errors",
        "rescan failed": "rescans_failed",
        "new projects": "new_projects",
    }
    flag_lines = {label: label.ljust(name_w) for label in flagged_rows}
    remaining_row = "remaining c/h/m/l".ljust(name_w)
    new_row = "new vulns".ljust(name_w)
    tokens_row = "tokens".ljust(name_w)
    for agent in agents:
        t = report["totals"][agent]
        verified_row += f"{t['verified']}/{t['attempts']}".rjust(col_w)
        cleared_row += f"{t['fixable_cleared']}/{t['fixable_total']}".rjust(col_w)
        claims_row += str(t["claimed_not_fixed"]).rjust(col_w)
        remaining_row += _sev(t.get("remaining_by_severity") or {}).rjust(col_w)
        new_row += str(t.get("introduced_count", 0)).rjust(col_w)
        macro_row += _macro_cell(t.get("macro_rate"), t.get("rate_ci95")).rjust(col_w)
        cleared_macro_row += _macro_cell(
            t.get("macro_cleared_rate"), t.get("cleared_rate_ci95")
        ).rjust(col_w)
        for label, key in flagged_rows.items():
            flag_lines[label] += str(t.get(key, 0)).rjust(col_w)
        star = "*" if HARNESS_MODE_FOR.get(agent, ("",))[0].startswith("claude") else ""
        tokens_row += (_ktok(t["tokens"]) + star).rjust(col_w)
    lines += [verified_row, cleared_row, remaining_row, new_row, claims_row]
    if any("macro_rate" in report["totals"][a] for a in agents):
        lines += [macro_row, cleared_macro_row]
    lines += list(flag_lines.values()) + [tokens_row]
    lines.append("(PASS = deps resolve, snyk test OK, vulns cleared, build OK, baseline-passing tests still pass; TIME_OUT = hit the case budget; "
                 "one attempt per upgrade)")
    lines.append("(remaining = fixable vulns not cleared, failed rescans included; "
                 "new = vulns in baseline projects the rescan added, unknown for failed rescans; "
                 "moved = remaining vulns the agent moved onto a new direct dependency)")
    lines.append("(macro = mean of per-repo rates; CI = 95% percentile bootstrap, clustered by repo; "
                 "harness errors are excluded from every rate)")
    if any(HARNESS_MODE_FOR.get(a, ("",))[0].startswith("claude") for a in agents):
        lines.append("(* Claude Code input tokens incl. cache reads and cache creation; compare cost, not tokens)")

    f = report["fairness"]
    lines.append("")
    lines.append(
        f"control: {f['control']}  |  model: {report['llm']['model'] or '(tool default)'}"
        f"  |  turn budget: {f.get('turn_budget') or turn_budget(f['agent_max_iterations'])}"
        f"  |  strict collateral: {f['strict_collateral']}"
    )
    for agent, acc in (f.get("agent_access") or {}).items():
        if all(v is None for v in acc.values()):
            continue  # not recorded (older run)
        lines.append(f"  {agent_display(agent)}: snyk {acc['snyk_access']}")
    if report["invalid_count"]:
        lines.append(
            f"{report['invalid_count']} case(s) excluded as invalid "
            "(baseline not green; see invalid_cases)"
        )
    return "\n".join(lines)

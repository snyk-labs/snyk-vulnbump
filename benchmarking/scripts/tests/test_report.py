import json
from pathlib import Path

import pytest

from cli.merge_reports import MergeMismatch, _to_case_results, merge
from cli.pdf_report import generate_pdf
from cli.report import (
    agent_totals,
    build_report,
    cluster_stats,
    fixable_counts,
    render_table,
)
from harness.agents import (
    AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE,
    AGENT_EVO_SINGLE_UPGRADE as AGENT_EVO,
    AGENT_CLAUDE_SNYK_SINGLE_UPGRADE,
    ALL_AGENTS,
)
from harness.outcome import AgentAttempt, BaselineResult, CaseResult

REPORTS = sorted((Path(__file__).resolve().parents[2] / "reports").glob("*/benchmark.json"))

GOOD = dict(tests_exit=0, tests_passed_count=10, scan_ok=True, plan_present=True, plan_groups=2)
BAD = dict(tests_exit=None, tests_passed_count=None, scan_ok=True, plan_present=True)


def _green(**kw) -> dict:
    return dict(deps_ok=True, build_ok=True, tests_ok=True, boots=None, **kw)


def _report(cases: list[CaseResult], repeats: int = 1, **kw) -> dict:
    return build_report(
        cases, **{**dict(mode="local", snyk_version="x", provider="p", model="m", repeats=repeats,
                         generated_at="t", strict_collateral=True, agent_max_iterations=0), **kw},
    )


def test_fixable_counts_dedupes_shared_instances():
    shared = ["package.json", "SNYK-JS-UUID-1"]
    a = AgentAttempt(agent=AGENT_EVO, label="g1", fixable_total=2, fixable_cleared=2,
                     instances=[shared, ["package.json", "A"]],
                     instances_cleared=[shared, ["package.json", "A"]])
    b = AgentAttempt(agent=AGENT_EVO, label="g2", fixable_total=1, fixable_cleared=0,
                     instances=[shared], instances_cleared=[])
    # Shared instance counted once, and not cleared because g2 missed its path.
    assert fixable_counts([a, b]) == (2, 1)
    # Old results without instances fall back to summing.
    old = [AgentAttempt(agent=AGENT_EVO, label="g", fixable_total=3, fixable_cleared=1)] * 2
    assert fixable_counts(old) == (6, 2)


def test_remaining_is_union_of_uncleared_targets():
    facts = [{"manifest": "package.json", "id": i, "severity": s}
             for i, s in (("A", "high"), ("B", "low"), ("C", "medium"))]
    # Each single-upgrade attempt's own remaining also counts other groups' leftovers;
    # the total must not add those up.
    a = AgentAttempt(agent=AGENT_EVO, label="g1", instances=[["package.json", "A"]],
                     instances_cleared=[["package.json", "A"]],
                     remaining_by_severity={"low": 1, "medium": 1}, introduced_count=0)
    b = AgentAttempt(agent=AGENT_EVO, label="g2", instances=[["package.json", "B"]],
                     remaining_by_severity={"low": 1, "medium": 1}, introduced_count=2)
    # A failed rescan clears nothing: its targets remain, unverified, and its
    # new vulns are unknown rather than 0.
    c = AgentAttempt(agent=AGENT_EVO, label="g3", instances=[["package.json", "C"]],
                     reasons=["verification-scan-failed"])
    case = CaseResult(name="c", baseline=BaselineResult(**GOOD, vuln_facts=facts),
                      attempts=[a, b, c])
    t = agent_totals([case], AGENT_EVO)
    assert t["remaining_by_severity"] == {"low": 1, "medium": 1}
    assert (t["remaining_unverified"], t["rescans_failed"], t["introduced_count"]) == (1, 1, 2)


def test_cluster_stats_macro_and_deterministic_ci():
    per_repo = {"a": (1, 1), "b": (0, 4), "c": (3, 5)}
    macro, ci = cluster_stats(per_repo)
    assert macro == round((1 + 0 + 0.6) / 3, 3)
    assert ci == cluster_stats(per_repo)[1]
    assert 0 <= ci[0] <= 0.4 <= ci[1] <= 1
    assert cluster_stats({"a": (1, 2)}) == (0.5, None)
    assert cluster_stats({}) == (None, None)


def test_cluster_stats_ci_brackets_macro_not_pooled_rate():
    # One big failing repo drags the pooled rate to ~0.05; the macro is 0.8.
    per_repo = {"big": (0, 100), **{f"r{i}": (1, 1) for i in range(4)}}
    macro, (lo, hi) = cluster_stats(per_repo)
    assert macro == 0.8 and lo <= macro <= hi


def test_harness_errors_excluded_from_rates():
    ok = AgentAttempt(agent=AGENT_EVO, label="g1", verified=True, **_green())
    err = AgentAttempt(agent=AGENT_EVO, label="g2", reasons=["harness-error"])
    case = CaseResult(name="c", baseline=BaselineResult(**GOOD), attempts=[ok, err])
    t = agent_totals([case], AGENT_EVO)
    assert (t["verified"], t["attempts"], t["harness_errors"]) == (1, 1, 1)
    assert "1/1" in render_table(_report([case]))


def test_repeats_judged_against_own_baseline():
    r1 = CaseResult(name="c", baseline=BaselineResult(**BAD),
                    attempts=[AgentAttempt(agent=AGENT_EVO, label="g1", verified=True)])
    r2 = CaseResult(name="c", baseline=BaselineResult(**GOOD),
                    attempts=[AgentAttempt(agent=AGENT_EVO, label="g1", verified=False)])
    report = _report([r1, r2], repeats=2)
    case = report["cases"]["c"]
    assert case["valid_runs"] == 1 and case["baseline"]["valid"]
    assert report["invalid_count"] == 0
    table = render_table(report)
    assert "INVALID" not in table
    row = next(line for line in table.splitlines() if line.startswith("c "))
    assert row.split()[1:] == ["0/1", "1/2"]  # repeat-1 attempt excluded; 1 of 2 runs valid
    assert report["totals"][AGENT_EVO]["attempts"] == 1
    # A merge round-trip splits the case back into repeats with their own baselines.
    merged = merge([report])
    assert merged["totals"][AGENT_EVO]["attempts"] == 1
    assert merged["invalid_count"] == 0


def test_merge_by_agent_warns_when_baselines_differ(capsys):
    def rep(agent: str, tests: int) -> dict:
        return _report([CaseResult(
            name="c", baseline=BaselineResult(**{**GOOD, "tests_passed_count": tests}),
            attempts=[AgentAttempt(agent=agent, label="g1", snyk_access=True)],
        )])
    same = merge([rep(AGENT_EVO, 10), rep(AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, 10)], by_agent=True)
    assert same["warnings"] == []
    diff = merge([rep(AGENT_EVO, 10), rep(AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, 12)], by_agent=True)
    assert len(diff["warnings"]) == 1 and diff["warnings"][0].startswith("c:")
    assert "warning: c:" in capsys.readouterr().err


def _one(agent: str, **attempt) -> list[CaseResult]:
    return [CaseResult(name="c", baseline=BaselineResult(**GOOD),
                       attempts=[AgentAttempt(agent=agent, label="g1", **attempt)])]


def test_fairness_is_derived_from_attempts_and_config():
    cases = [CaseResult(name="c", baseline=BaselineResult(**GOOD), attempts=[
        AgentAttempt(agent=AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE, label=g, snyk_access=False)
        for g in ("g1", "g2")
    ] + [AgentAttempt(agent=AGENT_EVO, label="g1", snyk_access=True)])]
    f = _report(cases)["fairness"]
    assert f["same_model_all_agents"] is True
    assert f["agent_access"] == {
        AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE: {"snyk_access": False},
        AGENT_EVO: {"snyk_access": True},
    }
    assert _report(cases, model="")["fairness"]["same_model_all_agents"] is False
    mixed = _one(AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE, snyk_access=True)
    mixed[0].attempts.append(AgentAttempt(agent=AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE, label="g2",
                                          snyk_access=False))
    assert _report(mixed)["fairness"]["agent_access"][AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE][
        "snyk_access"] == "1/2"


@pytest.mark.parametrize("kw", [{"model": "other"}, {"snyk_version": "y"}, {"binary_sha256": "y"},
                                {"strict_collateral": False}, {"agent_max_iterations": 50}])
def test_merge_refuses_different_run_settings(kw):
    a = _report(_one(AGENT_EVO, snyk_access=True))
    b = _report(_one(AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, snyk_access=True), **kw)
    with pytest.raises(MergeMismatch):
        merge([a, b], by_agent=True)
    merged = merge([a, b], by_agent=True, allow_mismatch=True)
    assert any("differs" in w for w in merged["warnings"])


def test_report_identifies_cli_build():
    cli = _report([], binary_sha256="abc", cli_commit="d8c489a")["cli"]
    assert cli == {"mode": "local", "snyk_version": "x", "binary_sha256": "abc",
                   "cli_commit": "d8c489a"}


def test_merge_refuses_one_agent_id_with_two_setups():
    with_snyk = _report(_one(AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE, snyk_access=True))
    without = _report(_one(AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE, snyk_access=False))
    with pytest.raises(MergeMismatch, match="snyk_access"):
        merge([with_snyk, without], by_agent=True)
    assert merge([without, without], by_agent=True)["warnings"] == []


def test_merge_warns_when_agent_inputs_were_not_recorded():
    old = _report(_one(AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE))
    merged = merge([old], by_agent=True)
    assert merged["warnings"] and "not recorded" in merged["warnings"][0]


def test_fairness_states_turn_budget():
    report = _report([CaseResult(name="c", baseline=BaselineResult(**GOOD))])
    assert report["fairness"]["turn_budget"] == (
        "evo-remediation-agent: 100/fix (+10 breakability), fresh per retry round, own setup budget; "
        "claude: 110 x upgrades, pooled")
    assert report["fairness"]["claude_turns_per_upgrade"] == 110
    fifty = _report([], agent_max_iterations=50)["fairness"]
    assert fifty["turn_budget"] == (
        "evo-remediation-agent: 50/fix, fresh per retry round, own setup budget; claude: 50 x upgrades, pooled")
    assert fifty["claude_turns_per_upgrade"] == 50


def test_merge_refuses_reports_without_the_turn_budget():
    new = _report(_one(AGENT_EVO, snyk_access=True))
    old = _report(_one(AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, snyk_access=True))
    del old["fairness"]["claude_turns_per_upgrade"]
    with pytest.raises(MergeMismatch, match="claude_turns_per_upgrade"):
        merge([new, old], by_agent=True)


@pytest.mark.parametrize("path", REPORTS, ids=lambda p: p.parent.name)
def test_existing_reports_still_render(path, tmp_path):
    report = json.loads(path.read_text())
    assert render_table(report)
    rebuilt = _report(_to_case_results(report))
    assert render_table(rebuilt)
    for agent in ALL_AGENTS:
        if agent in report["totals"]:
            assert rebuilt["totals"][agent]["verified"] == report["totals"][agent]["verified"]
    assert render_table(merge([report, report], by_agent=True))
    rebuilt_path = tmp_path / "benchmark.json"
    rebuilt_path.write_text(json.dumps(rebuilt))
    assert generate_pdf(path, tmp_path / "orig.pdf").exists()
    assert generate_pdf(rebuilt_path, tmp_path / "rebuilt.pdf").exists()

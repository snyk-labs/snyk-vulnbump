"""The outcome objects of a benchmark run: baselines, agent attempts and cases.

An agent is not a prompt-in/text-out model — it edits files and runs commands,
then re-scans. So the unit the benchmark scores is not a string but a structured
*outcome*: did the vulnerability get fixed, did the build survive, what did it
cost, and how did it get there.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, PrivateAttr, computed_field


class DepChange(BaseModel):
    """One dependency that differs between the before- and after-remediation
    Snyk depGraphs. `before is None` → newly added; `after is None` → removed."""

    name: str
    before: str | None = None
    after: str | None = None


class BaselineResult(BaseModel):
    """The pristine fixture's state, measured before any agent touches it.

    This is a gate, not a score. If the fixture does not already build, pass
    its tests and start, then no fix verdict derived from it means anything,
    and the case is reported `invalid` — distinct from failed, and excluded
    from every agent's denominator.
    """

    deps_ok: bool | None = None           # install step; None = fixture has none
    build_ok: bool | None = None          # diagnostic; absent for non-compiled ecosystems
    tests_passed_count: int | None = None
    tests_identified: int | None = None   # tests with per-test reports; None = log count only
    tests_exit: int | None = None
    boots: bool | None = None             # None = library fixture, not applicable
    vulns: int | None = None
    scan_ok: bool = False
    plan_groups: int = 0
    plan_present: bool = False
    oom_killed: bool = False              # hit the container memory cap
    corrupt_artifact: bool = False        # the Maven mirror served a corrupt file
    # One entry per baseline (manifest, vuln id), for the report's breakdowns.
    vuln_facts: list[dict] = Field(default_factory=list)

    # Per-test statuses from the baseline's reports. In memory only: attempts
    # gate against it, and the report JSON stays lean.
    _test_results: dict[str, str] | None = PrivateAttr(default=None)

    @computed_field
    @property
    def valid(self) -> bool:
        """Green enough to hang a benchmark off.

        `boots is False` and `build_ok is False` fail; None passes, because
        None means the check does not apply to this fixture rather than that
        it failed.

        Real-world repos were selected with >85% test pass rate, so a non-zero
        exit code is acceptable as long as enough tests ran. Exit 127 (command
        not found) still fails — the test runner itself is missing.
        """
        return (
            self.tests_exit not in (None, 127)
            and self.tests_passed_count not in (0, None)
            and self.boots is not False
            and self.deps_ok is not False
            and self.build_ok is not False
            and self.scan_ok
            and self.plan_present
            and not self.oom_killed
            and not self.corrupt_artifact
        )

    @computed_field
    @property
    def invalid_reasons(self) -> list[str]:
        reasons = []
        if self.tests_exit == 127:
            reasons.append("baseline-test-runner-not-found")
        elif self.tests_exit is None or self.tests_passed_count in (0, None):
            reasons.append("baseline-runs-no-tests")
        if self.boots is False:
            reasons.append("baseline-does-not-boot")
        if self.deps_ok is False:
            reasons.append("baseline-deps-do-not-resolve")
        if self.build_ok is False:
            reasons.append("baseline-does-not-compile")
        if not self.scan_ok:
            reasons.append("baseline-scan-failed")
        if not self.plan_present:
            reasons.append("no-fix-plan")
        if self.oom_killed:
            reasons.append("baseline-oom-killed")
        if self.corrupt_artifact:
            reasons.append("baseline-corrupt-artifact")
        return reasons


class AgentAttempt(BaseModel):
    """One agent's attempt at one fix group, applied in isolation on a fresh
    copy of the pristine fixture and then verified independently."""

    agent: str
    label: str
    group_index: int | None = None
    requested_ids: list[str] = Field(default_factory=list)

    # --- what the agent said ---
    agent_exit: int | None = None
    agent_claimed: list[str] = Field(default_factory=list)

    # --- what the harness independently observed ---
    ids_absent: list[str] = Field(default_factory=list)
    deps_ok: bool | None = None           # install step after the fix; None = fixture has none
    build_ok: bool | None = None
    tests_ok: bool | None = None
    tests_passed_count_before: int | None = None
    tests_passed_count_after: int | None = None
    # Baseline-passing tests now failed, skipped or missing; None = no per-test
    # reports, gated on counts. The list is capped; the count is not.
    tests_regressed_count: int | None = None
    tests_regressed: list[str] = Field(default_factory=list)
    # Test source files the agent added, removed or edited (from agent.diff).
    tests_modified: list[str] = Field(default_factory=list)
    boots: bool | None = None
    deps_changed: list[DepChange] = Field(default_factory=list)
    unexpected_collateral: list[str] = Field(default_factory=list)
    vulns_new: int | None = None

    # --- verdict (computed by verdict.judge, stored so the report is static) ---
    verified: bool = False
    claimed_not_fixed: bool = False
    unresolved_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)

    # --- what the risk assessment said, before the outcome was known ---
    # Lets us score the assessment itself: when it said "high", did the app
    # actually break? Empty for agents that never see a breakability verdict.
    breakability_risk: str = ""
    breakability_counts: dict[str, int] = Field(default_factory=dict)
    vuln_breakability: list[dict] = Field(default_factory=list)  # Evo only: {id, files, risk}

    # The agent never produced a result (auth/startup failure: no Claude Code
    # result event, or Evo with neither a fix report nor any LLM tokens). A
    # harness failure, not an agent one: excluded from every rate rather than
    # scored FAIL. Its verdict carries reason `harness-error`.
    harness_error: bool = False

    # --- tamper flags, recorded from agent.diff ---
    # The agent added or edited a .snyk policy file. The harness scans with
    # --ignore-policy so it cannot hide vulns; this records that it tried.
    snyk_policy_modified: bool = False

    # --- cost ---
    input_tokens: int = 0
    output_tokens: int = 0
    # Reported by Claude Code itself. 0.0 for Evo, which does not report it.
    # Tokens stop being comparable across models; dollars do not.
    cost_usd: float = 0.0
    latency_s: float = 0.0
    timed_out: bool = False
    budget_s: int = 0
    # --- turn budget ---
    # Claude Code's --max-turns. None for Evo, which is capped per agent run.
    turn_budget: int | None = None
    # Claude Code's num_turns, setup included; Evo's summary agent_iterations,
    # its fix agents summed, setup excluded. Not like for like.
    turns_used: int | None = None
    result_subtype: str = ""  # Claude Code's result subtype, e.g. error_max_turns
    # Claude Code stopped at --max-turns. For Evo, at least one of its agent
    # runs hit its cap; Evo carries on with the other fixes.
    turn_capped: bool = False
    # Why a failed attempt broke the repo, from its logs (harness.failure_class):
    # {stage, category, detail, culprit}. None when it passed or only the scan failed.
    failure: dict[str, str] | None = None
    # Package manager bump only: its bump pinned a declaration a BOM, parent or Spring's
    # dependency-management plugin manages (pm_bump.BumpResult.managed).
    pm_bump_managed: bool | None = None

    # --- scan deltas, keyed by (manifest, vuln id) from the harness rescan ---
    fixable_total: int = 0                # baseline instances this attempt targeted
    fixable_cleared: int = 0              # ...and how many the rescan no longer finds
    # The (manifest, id) keys behind the two counts. Single-upgrade attempts can share an
    # instance, so totals across groups must union these rather than sum counts.
    instances: list[tuple[str, str]] = Field(default_factory=list)
    instances_cleared: list[tuple[str, str]] = Field(default_factory=list)
    # Single-upgrade mode: targets not cleared because the agent's edit left the vuln on a
    # new direct dependency instead of removing it. A subset of the uncleared ones.
    instances_moved: list[tuple[str, str]] = Field(default_factory=list)
    remaining_by_severity: dict[str, int] = Field(default_factory=dict)  # targets not cleared
    introduced_count: int | None = None   # None when the rescan failed
    introduced_by_severity: dict[str, int] = Field(default_factory=dict)
    # Projects the rescan found that the baseline did not (agent scratch
    # manifests). Left out of every count above and of collateral.
    new_projects: list[str] = Field(default_factory=list)
    # The ./mvnw rescan could not build the Maven tree, so it was retried with
    # the image's mvn: vulns are scored from that, the stale wrapper fails install.
    scan_without_wrapper: bool = False
    # What the agent was given, recorded so the report's fairness terms are
    # derived rather than asserted. None = not recorded or not applicable.
    snyk_access: bool | None = None

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class CaseResult(BaseModel):
    """One fixture, one baseline, every agent's attempts against it."""

    name: str
    baseline: BaselineResult
    attempts: list[AgentAttempt] = Field(default_factory=list)

    def attempts_for(self, agent: str) -> list[AgentAttempt]:
        return [a for a in self.attempts if a.agent == agent]




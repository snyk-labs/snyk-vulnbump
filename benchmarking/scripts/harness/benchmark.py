"""The benchmark loop: one baseline, then every agent against every fix group.

Shape of a case:

    phase 0   baseline + plan      pristine fixture: install, build, test,
                                   boot, scan, and emit the fix plan.
                                   GATE: if this is not green the case is
                                   `invalid` and no agent runs. A verdict
                                   derived from an already-broken fixture
                                   tells you nothing.

    phase k   one (agent, group)     fresh copy of the pristine fixture, one
                                   agent's attempt at one fix group, then
                                   independent verification.

The plan from phase 0 is the shared denominator: every agent is graded on the
same exam. Isolation is by construction — each phase starts from a fresh copy,
so nothing is reverted and fix k+1 cannot inherit fix k's state.

Verification never trusts the agent. `ids_absent` comes from the harness's own
post-fix `snyk test`, and what the agent *claimed* is recorded separately so the
two can be compared (see verdict.judge and the claimed_not_fixed metric).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Callable

from .analytics import analytics_facts, parse_jsonl
from .failure_class import classify, classify_dirs
from .agents import (
    ALL_AGENTS,
    EVO_AGENTS,
    HARNESS_CLAUDE_SNYK,
    HARNESS_MODE_FOR,
    HARNESS_PM_BUMP_MIN,
    PM_BUMP_AGENTS,
    Finding,
    claude_code_command,
    claude_turn_budget,
    evo_command,
    parse_breakability,
    parse_claimed_ids,
    parse_fix_report_claims,
    parse_vuln_breakability,
    pm_bump_command,
    single_upgrade_prompt,
    upgrade_line,
)
from .claude_image import ensure_claude_image
from .docker import (
    OOM_MARKER,
    PHASE_AGENT,
    PHASE_BASELINE,
    PHASE_VERIFY,
    docker_run,
)
from .extra_certs import host_cert
from .collateral import unrelated_bumps
from .fix_plan import FixGroup, FixPlan, split_package_spec
from .pm_bump import bump
from .outcome import AgentAttempt, BaselineResult, CaseResult
from .scenario import HarnessConfig, Scenario
from .snyk import (
    diff_dep_graph,
    load_json,
    manifest_of,
    project_key,
    report_block,
    scope_to_manifests,
    snyk_results,
    split_new_projects,
    strip_targets,
    strip_vuln_links,
    vuln_count,
    vuln_facts,
    vuln_instances,
    vuln_paths,
)
from .test_results import (
    collect_test_results,
    count_passed_tests,
    modified_test_files,
    passed_count,
    regressed_tests,
    report_window,
    resolve_test_framework,
)
from .verdict import judge


# --------------------------------------------------------------------------
# artefact readers
# --------------------------------------------------------------------------

def _read_text(p: Path) -> str:
    try:
        return p.read_text()
    except (FileNotFoundError, NotADirectoryError, UnicodeDecodeError):
        return ""


def _read_int(p: Path) -> int | None:
    try:
        return int(p.read_text().strip())
    except (FileNotFoundError, NotADirectoryError, ValueError):
        return None


def _tri_state_exit(p: Path) -> bool | None:
    """None when the step did not apply (no exit file written), else pass/fail.

    This is how a library fixture's absent boot and a non-compiled ecosystem's
    absent build stay "not applicable" instead of collapsing into "failed".
    """
    code = _read_int(p)
    return None if code is None else code == 0


def _claude_cost(agent_debug_log: str) -> float:
    """Dollar cost of a Claude Code run, from its own result event.

    Claude Code reports total_cost_usd directly, so there is no reason to infer
    spend from token counts and a price list we would have to keep in step with
    Anthropic's. It matters most across models: the same token count costs very
    differently on Opus than on Sonnet, and "tokens per verified fix" silently
    stops being a cost comparison the moment two agents run on different models.

    Sums modelUsage's per-model costUSD when present, so a run that also used
    a subagent or background model is charged for every model it called.

    The figure comes from the CLI's built-in price table, so it is only right
    when the pinned CLAUDE_CODE_VERSION knows the model: 2.0.14 priced Sonnet
    5.x at Sonnet 4.x's $3/$15, overstating cost 1.5x.

    Returns 0.0 when absent — Evo does not report cost, and a missing figure
    must not fail an attempt.
    """
    for line in reversed(agent_debug_log.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("total_cost_usd") is not None:
            try:
                model_usage = obj.get("modelUsage") or {}
                if model_usage:
                    return sum(float(m.get("costUSD", 0) or 0) for m in model_usage.values())
                return float(obj["total_cost_usd"])
            except (TypeError, ValueError, AttributeError):
                return 0.0
    return 0.0


def _claude_tokens(agent_debug_log: str) -> tuple[int, int]:
    """Best-effort token accounting from `claude -p --output-format json`.

    The transcript is not guaranteed to be pure JSON (tool output interleaves),
    so scan for the last decodable object carrying a usage block. Returns
    (0, 0) rather than raising: a missing cost figure must not fail an attempt.
    """
    for line in reversed(agent_debug_log.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        usage = obj.get("usage") or {}
        if usage:
            # Claude Code reports uncached input separately from cache
            # creation and cache reads, and for an agent loop the cache
            # fields carry nearly all of it — a run showing input_tokens=3
            # had 13,849 cache-creation tokens. Counting only input_tokens
            # would understate the control by orders of magnitude and make
            # any cost comparison against Evo meaningless.
            #
            # `usage` covers the main model only; modelUsage has every model
            # the run called. A run with a second model showed usage at 54%
            # of modelUsage's input and 39% of its output.
            model_usage = obj.get("modelUsage") or {}
            if model_usage:
                billed_in = sum(
                    int(m.get("inputTokens", 0) or 0)
                    + int(m.get("cacheCreationInputTokens", 0) or 0)
                    + int(m.get("cacheReadInputTokens", 0) or 0)
                    for m in model_usage.values()
                )
                billed_out = sum(
                    int(m.get("outputTokens", 0) or 0) for m in model_usage.values()
                )
                return billed_in, billed_out
            billed_in = (
                int(usage.get("input_tokens", 0) or 0)
                + int(usage.get("cache_creation_input_tokens", 0) or 0)
                + int(usage.get("cache_read_input_tokens", 0) or 0)
            )
            return billed_in, int(usage.get("output_tokens", 0) or 0)
    return 0, 0


# --------------------------------------------------------------------------
# phases
# --------------------------------------------------------------------------

_COPY_IGNORE = shutil.ignore_patterns(
    ".gradle", "__pycache__", ".pytest_cache", "node_modules",
)


def _fresh_copy(scenario: Scenario, repos_dir: Path) -> tuple[Path, Path]:
    work = Path(tempfile.mkdtemp(prefix=f"vulnbump-{scenario.name}-"))
    out = Path(tempfile.mkdtemp(prefix=f"vulnbump-out-{scenario.name}-"))
    src = repos_dir / scenario.name
    shutil.copytree(src, work, dirs_exist_ok=True, ignore=_COPY_IGNORE, symlinks=True)
    _assert_no_history(work, src)
    return work, out


def _assert_no_history(work: Path, src: Path) -> None:
    """Refuse a copy whose .git exposes commits other than HEAD (e.g. the upstream fix)."""
    if not (work / ".git").exists():
        return
    git = ["git", "-C", str(work)]
    extra = subprocess.run(
        [*git, "rev-list", "-n", "1", "--all", "--reflog", "--not", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    remotes = subprocess.run(
        [*git, "remote"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    if extra or remotes:
        raise RuntimeError(
            f"{src} has git history beyond HEAD or a remote, so the agent could read "
            f"the upstream fix. Run `uv run python clone_repos.py --sanitise --out {src.parent}` "
            f"(check with --check) and retry."
        )


# Excluded from agent.diff even when a fixture has no .gitignore for them.
_DIFF_EXCLUDE = (
    "node_modules/", ".gradle/", "target/", "build/", "dist/", "coverage/", ".nyc_output/",
    "__pycache__/", ".pytest_cache/", ".venv/", "*.pyc", "*.class", ".m2/",
)
# Staged even when the fixture's .gitignore lists them (expressjs-generator
# ignores its package-lock.json), so lockfile and .snyk edits reach agent.diff.
_FORCE_ADD = (
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "poetry.lock", "Pipfile.lock", "gradle.lockfile", ".snyk",
)


def _stage(git: list[str]) -> None:
    subprocess.run([*git, "add", "-A"], check=False, capture_output=True)
    excludes = [f":(top,exclude,glob)**/{d}**" for d in _DIFF_EXCLUDE if d.endswith("/")]
    # One call per name: a pathspec that matches nothing fails the whole add.
    for name in _FORCE_ADD:
        subprocess.run([*git, "add", "-f", "--", f":(top,glob)**/{name}", *excludes],
                       check=False, capture_output=True)


def _snapshot(work: Path) -> tuple[Path, str]:
    """Record the pre-agent tree in a git dir outside /app, invisible to the agent.

    The fixture's own HEAD is no reference: some fixtures carry uncommitted
    changes, which the agent did not make.
    """
    git_dir = Path(tempfile.mkdtemp(prefix="vulnbump-snap-"))
    git = ["git", f"--git-dir={git_dir}", f"--work-tree={work}"]
    subprocess.run([*git, "init", "-q"], check=False, capture_output=True)
    (git_dir / "info").mkdir(exist_ok=True)
    (git_dir / "info" / "exclude").write_text("\n".join(_DIFF_EXCLUDE) + "\n")
    _stage(git)
    tree = subprocess.run([*git, "write-tree"], check=False, capture_output=True, text=True)
    return git_dir, tree.stdout.strip()


def _write_agent_diff(git_dir: Path, tree: str, work: Path, dest: Path) -> None:
    """Diff of the repo after the attempt against the snapshot, .gitignore'd paths excluded (lockfiles and .snyk kept)."""
    git = ["git", f"--git-dir={git_dir}", f"--work-tree={work}"]
    if tree:
        _stage(git)
        diff = subprocess.run([*git, "diff", "--cached", tree], check=False,
                              capture_output=True, text=True, errors="replace")
        dest.write_text(diff.stdout)
    shutil.rmtree(git_dir, ignore_errors=True)


# What the verify container's fresh /out receives from the agent container
# once verification is done: the agent's own record, parsed for claims,
# tokens and cost, and kept by preserve_scan. An allowlist, so an agent-written
# file can never land on a harness artefact's name.
_AGENT_ARTEFACTS = (
    "agent.log", "agent-debug.log", "agent.exit", "agent.seconds", "agent.diff",
    "prompt.txt", "fix-report.json", "analytics.jsonl", "evo-run.log",
    "install-before.log", "install-before.exit", "pm-bump.json", OOM_MARKER,
)


def _collect_agent_artefacts(agent_out: Path, out: Path) -> None:
    for name in _AGENT_ARTEFACTS:
        src = agent_out / name
        if src.is_file() and not src.is_symlink():
            # A container killed at its budget never reaches the entrypoint's
            # chown, so root-only files (analytics.jsonl) stay unreadable.
            try:
                shutil.copy2(src, out / name)
            except PermissionError:
                pass
    shutil.rmtree(agent_out, ignore_errors=True)


_SNYK_POLICY_IN_DIFF = re.compile(r"^\+\+\+ b/(?:.*/)?\.snyk$", re.MULTILINE)


def _touches_snyk_policy(diff: str) -> bool:
    """A .snyk policy file was added or edited (`snyk ignore` writes one)."""
    return bool(_SNYK_POLICY_IN_DIFF.search(diff))


def _claude_result(agent_log: str) -> dict:
    """Claude Code's last result event, or {} when it never wrote one."""
    for line in reversed(agent_log.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") == "result":
            return obj
    return {}


def _claude_api_refused(agent_log: str) -> bool:
    """Claude Code's result event is an error with zero output tokens: the API
    refused it (auth, bad model or region), so no agent run is behind it."""
    obj = _claude_result(agent_log)
    out_tok = int((obj.get("usage") or {}).get("output_tokens", 0) or 0)
    return bool(obj.get("is_error")) and out_tok == 0


# Evo logs this to its own run log (evo-run.log) each time one of its agent
# runs hits --agent-max-iterations.
_EVO_CAP_OUT = re.compile(r'"event":\s*"cap_out"')


def _evo_cap_hits(run_log: str) -> int:
    return len(_EVO_CAP_OUT.findall(run_log))


# The Maven mirror served a corrupt artifact (seen: brotli bodies nginx cached
# for clients that never asked for them). Maven fails its checksum or, on the
# old warn policy, drops the POM's transitive deps; Gradle cannot parse it.
# Either way the result measures the mirror, not the fixture or the agent.
_CORRUPT_ARTIFACT = re.compile(
    r"Checksum validation failed|Could not validate integrity of download|Could not parse POM"
)


def _corrupt_artifact(out: Path, suffix: str) -> bool:
    logs = (f"install-{suffix}.log", "build.log", f"test-{suffix}.log")
    return any(_CORRUPT_ARTIFACT.search(_read_text(out / name)) for name in logs)


# Failures Evo prints that belong to the harness, not to Evo: the shared
# Snyk token throttled or rejected, no route to Snyk, or a fetch the sandbox
# blocks (the Gradle wrapper downloading its distribution), all in its
# pre-flight scan; or LLM credentials refused. Anything else it exits on,
# "Dependencies not installed" included, is Evo's own result and is scored.
_EVO_PREFLIGHT_INFRA_ERRORS = (
    ("snyk-rate-limited", re.compile(r"Error: Snyk rate limit exceeded")),
    ("snyk-auth", re.compile(r"Error: Snyk is not authenticated")),
    ("snyk-unreachable", re.compile(r"Error: Snyk could not reach the internet")),
    ("blocked-fetch", re.compile(
        r"java\.net\.\w+Exception[^\n]*\n(?:[^\n]*\n){0,40}?\s*at org\.gradle\.wrapper\.Install"
        r"|429 Too Many Requests"
    )),
)
_EVO_LLM_AUTH_ERROR = re.compile(
    # Provider config the harness failed to pass (ANTHROPIC_API_KEY, ...).
    r"\b[A-Z][A-Z0-9_]+ is not set in the environment"
    r'|"type":\s*"(?:authentication|permission)_error"'
    r"|anthropic: [^\n]*\b(?:401|403)\b"
)
# Past this line Evo has its scan; a blocked fetch after it is one of its
# own tool results, not a reason it never ran.
_EVO_SCAN_DONE = "Scan complete."


def _harness_error(agent: str, out: Path, *, timed_out: bool) -> str | None:
    """Which infrastructure failure, if any, kept the agent from running.

    Only recognised signatures count: an attempt dropped from the denominator
    must be the harness's fault, for every agent alike. A time-out is not
    one: the agent ran and used its budget.
    """
    if timed_out:
        return None
    # The entrypoint writes agent.exit whenever the agent command returns, so
    # its absence means the container was killed or never started.
    exit_code = _read_int(out / "agent.exit")
    if exit_code is None:
        return "agent-killed"
    if exit_code == 127:
        return "agent-not-launched"
    if agent in PM_BUMP_AGENTS:
        return None
    log = _read_text(out / "agent.log")
    if agent in EVO_AGENTS:
        preflight = log.split(_EVO_SCAN_DONE, 1)[0]
        for name, sig in _EVO_PREFLIGHT_INFRA_ERRORS:
            if sig.search(preflight):
                return name
        return "llm-auth" if _EVO_LLM_AUTH_ERROR.search(log) else None
    # Claude's agent.log is its JSON result alone, so text signatures would
    # match its own summary; a refused API call is its credentials signature.
    return "llm-auth" if _claude_api_refused(log) else None


def run_baseline(
    scenario: Scenario, cfg: HarnessConfig, repos_dir: Path
) -> tuple[BaselineResult, FixPlan | None, Path, Path]:
    """Phase 0. Returns (result, plan, work, out); caller owns the temp dirs."""
    work, out = _fresh_copy(scenario, repos_dir)

    # --disable-trust is required, not a convenience. /app is a fresh copy the
    # CLI has never seen, so it prompts "Trust this folder?" and, with no tty,
    # takes the default (cancel) and exits 0 having done nothing. An exit code
    # of 0 with no plan file is exactly the kind of silent success this
    # benchmark exists to catch, so we remove the prompt rather than parse
    # around it. Safe here: the container is ephemeral and the fixture is ours.
    docker_run(
        scenario, cfg, work, out,
        phase=PHASE_BASELINE,
        timeout_s=max(1, int(scenario.timeout_s * cfg.timeout_multiplier)),
    )

    framework = resolve_test_framework(
        scenario.test_cmd,
        test_framework=scenario.test_framework,
        case_name=scenario.name,
    )
    raw_before = load_json(out / "snyk-test-before.json")
    cli_before = scope_to_manifests(raw_before, scenario.manifests)
    plan = FixPlan.from_scan(cli_before)
    # A listed manifest the scan never reported is a cases.yaml typo; fail
    # loudly rather than score a silently shrunken denominator.
    scanned = {manifest_of(r) for r in snyk_results(raw_before)}
    manifests_ok = set(scenario.manifests) <= scanned

    test_results = _test_results(work, out, "before")
    result = BaselineResult(
        deps_ok=_tri_state_exit(out / "install-before.exit"),
        build_ok=_tri_state_exit(out / "build.exit"),
        tests_passed_count=(
            passed_count(test_results) if test_results is not None
            else count_passed_tests(_read_text(out / "test-before.log"), framework)
        ),
        tests_identified=len(test_results) if test_results is not None else None,
        tests_exit=_read_int(out / "test-before.exit"),
        boots=_tri_state_exit(out / "boot.exit"),
        vulns=vuln_count(cli_before),
        scan_ok=raw_before is not None and manifests_ok,
        plan_groups=plan.total_groups if plan else 0,
        plan_present=plan is not None,
        oom_killed=(out / OOM_MARKER).exists(),
        corrupt_artifact=_corrupt_artifact(out, "before"),
        vuln_facts=vuln_facts(cli_before),
    )
    result._test_results = test_results
    return result, plan, work, out


def _test_results(work: Path, out: Path, suffix: str) -> dict[str, str] | None:
    """Per-test results from this step's reports, also saved to out for inspection."""
    since, until = report_window(out, suffix)
    results = collect_test_results(work, out / "junit", since=since, until=until)
    if results is not None:
        (out / f"test-results-{suffix}.json").write_text(json.dumps(results, sort_keys=True))
    return results


def _findings_for(group: FixGroup, cli_before) -> list[Finding]:
    """The single-upgrade prompt's fallback when the text report has no block for the
    group: a restatement of the scan output for its vulnerabilities."""
    wanted = set(group.vuln_ids)
    findings: list[Finding] = []
    seen: set[str] = set()
    for result in (cli_before if isinstance(cli_before, list) else [cli_before or {}]):
        for v in (result or {}).get("vulnerabilities", []) or []:
            vid = v.get("id")
            if vid in wanted and vid not in seen:
                seen.add(vid)
                findings.append(
                    Finding(
                        id=vid,
                        title=v.get("title", ""),
                        severity=v.get("severity", ""),
                        package=v.get("packageName", ""),
                        version=v.get("version", ""),
                    )
                )
    # Any id the scan JSON did not surface still gets named, so the agent is
    # never told about fewer vulnerabilities than it is scored on.
    for vid in group.vuln_ids:
        if vid not in seen:
            findings.append(Finding(id=vid))
    return findings


def _agent_image(scenario: Scenario, cfg: HarnessConfig) -> str:
    """The fixture image with Claude Code (and so Node) added. Every agent runs
    in it, so Evo and Claude differ in the agent and nothing else."""
    return ensure_claude_image(
        scenario.image,
        platform=cfg.platform,
        extra_ca_cert=str(host_cert()) if host_cert() else None,
    )


def _claude_turns(cfg: HarnessConfig) -> int:
    return claude_turn_budget(cfg.agent_max_iterations)


def _agent_command_and_image(
    agent: str,
    scenario: Scenario,
    cfg: HarnessConfig,
    group: FixGroup | None,
    out: Path,
    cli_before,
    plan: FixPlan,
    scan_report: str = "",
    work: Path | None = None,
) -> tuple[str, str | None, bool | None]:
    """Returns (agent_cmd, image_override, mount_snyk)."""
    image = _agent_image(scenario, cfg)
    if agent in PM_BUMP_AGENTS:
        # The edit is made here, on the host; the container only re-locks.
        root = work / scenario.subdirectory if scenario.subdirectory else work
        exact = HARNESS_MODE_FOR[agent][0] != HARNESS_PM_BUMP_MIN
        result = bump(root, group, exact)
        (out / "pm-bump.json").write_text(json.dumps(asdict(result), indent=2))
        return pm_bump_command(result.relock_cmd, result.applied, result.reason), image, False
    if agent in EVO_AGENTS:
        target = f"/app/{scenario.subdirectory}" if scenario.subdirectory else "/app"
        return (
            evo_command(
                group,
                target=target,
                provider=scenario.provider or cfg.provider,
                model=scenario.model or cfg.model,
                max_iterations=cfg.agent_max_iterations,
            ),
            image,
            None,
        )

    # claude-code-snyk-scan is told the target versions and may re-scan to check its
    # own work. claude-code-unaided gets neither: no versions that fix the vulns,
    # no links to Snyk's vuln pages, and no snyk, which would print them.
    aided = HARNESS_MODE_FOR[agent][0] == HARNESS_CLAUDE_SNYK

    def shown(text: str) -> str:
        return text if aided else strip_vuln_links(strip_targets(text))

    projects = {manifest_of(r): r.get("projectName", "") for r in snyk_results(cli_before)}
    block = report_block(scan_report, projects.get(group.manifest, ""), group.from_dep)
    prompt = single_upgrade_prompt(
        _findings_for(group, cli_before), group.manifest, scenario.test_cmd,
        scan_block=shown(block) if all(v in block for v in group.vuln_ids) else "",
        aided=aided,
        upgrade=shown(upgrade_line(group)),
    )
    mount_snyk = None if aided else False

    # The exact prompt lands in the artefacts, so the fairness contract is
    # auditable after the fact rather than asserted.
    (out / "prompt.txt").write_text(prompt)

    return (
        claude_code_command(
            model=scenario.model or cfg.model,
            max_turns=_claude_turns(cfg),
            deny_snyk=not aided,
        ),
        image,
        mount_snyk,
    )


def run_attempt(
    scenario: Scenario,
    cfg: HarnessConfig,
    repos_dir: Path,
    *,
    agent: str,
    group: FixGroup | None,
    plan: FixPlan,
    baseline: BaselineResult,
    cli_before,
    scan_report: str = "",
) -> tuple[AgentAttempt, Path, Path]:
    """One (agent, group) phase on a fresh copy of the pristine fixture."""
    work, out = _fresh_copy(scenario, repos_dir)
    # The agent container gets its own /out. Verify then starts from an empty
    # one, so nothing the agent wrote there (e.g. a forged
    # snyk-test-after.json) can stand in for the harness's own artefacts.
    agent_out = Path(tempfile.mkdtemp(prefix=f"vulnbump-agent-out-{scenario.name}-"))

    # Before the agent command is composed: the package manager bump edits the work
    # tree on the host there, and its edits belong in agent.diff.
    snap_dir, snap_tree = _snapshot(work)
    agent_cmd, image, mount_snyk = _agent_command_and_image(
        agent, scenario, cfg, group, agent_out, cli_before, plan, scan_report, work=work
    )
    budget = max(1, int(scenario.timeout_s * cfg.timeout_multiplier))

    start = time.monotonic()
    # Two containers over the same /app, for every agent. The agent runs in
    # the same production-like sandbox whichever agent it is (non-root,
    # read-only root filesystem, writable /tmp; see docker.py), without snyk
    # for claude-code-unaided and never with GitHub; then verification
    # runs in a fresh container as root with a fresh /out and the baseline's
    # budget — the same user, HOME and caches the baseline was measured
    # under, and nothing the agent left outside /app (PATH shims, ~/.m2,
    # stray files in /out) can shape its own verdict.
    _, agent_timed_out = docker_run(
        scenario, cfg, work, agent_out,
        phase=PHASE_AGENT,
        image=image,
        agent_cmd=agent_cmd,
        mount_snyk=mount_snyk,
        timeout_s=budget,
    )
    agent_elapsed = time.monotonic() - start
    # Taken before verify re-installs, builds and tests, so it holds the
    # agent's changes only, not lockfile rewrites or generated files.
    _write_agent_diff(snap_dir, snap_tree, work, agent_out / "agent.diff")
    _, verify_timed_out = docker_run(
        scenario, cfg, work, out,
        phase=PHASE_VERIFY,
        timeout_s=budget,
    )
    _collect_agent_artefacts(agent_out, out)
    timed_out = agent_timed_out or verify_timed_out
    # Agent time only. agent.seconds is missing when the container was killed
    # mid-agent, and then the agent ran for the whole container lifetime.
    agent_s = _read_int(out / "agent.seconds")
    latency = agent_s if agent_s is not None else agent_elapsed

    framework = resolve_test_framework(
        scenario.test_cmd,
        test_framework=scenario.test_framework,
        case_name=scenario.name,
    )
    # Only the baseline's projects are scored. A project the rescan finds that
    # the baseline did not is agent scratch picked up by --all-projects (an
    # unpacked jar's pom.xml, a tmp-extract/ dir): flagged, never counted.
    cli_after, new_projects = split_new_projects(
        cli_before,
        scope_to_manifests(load_json(out / "snyk-test-after.json"), scenario.manifests),
    )
    agent_debug_log = _read_text(out / "agent-debug.log")

    # Which of this attempt's target ids the harness's OWN rescan no longer
    # finds. This, not the agent's report, is the evidence.
    scored_group = group
    before_inst = vuln_instances(cli_before)
    targets = _target_instances(before_inst, [group])
    # A manifest missing from the rescan failed to resolve (e.g. the edit broke
    # it); its vulns are unknown, not cleared.
    rescan_ok = cli_after is not None and {m for m, _ in targets} <= {
        project_key(manifest_of(r)) for r in snyk_results(cli_after)
    }
    after_inst = vuln_instances(cli_after) if rescan_ok else {}
    after_ids = {k[1] for k in after_inst}
    before_paths = vuln_paths(cli_before)
    after_paths = vuln_paths(cli_after) if rescan_ok else {}

    def instance_gone(k: tuple[str, str]) -> bool:
        if not rescan_ok:
            return False
        # Scored per path: the same id can sit under several groups
        # (uuid under both @tryghost/errors and @tryghost/validator), and paths
        # through another group's dependency are that group's job, not this one's.
        return _paths_cleared(group, before_paths.get(k, []), after_paths.get(k, []))

    gone = {k for k in targets if instance_gone(k)}
    moved = {
        k for k in targets - gone
        if group is not None and rescan_ok
        and _paths_moved(group, before_paths.get(k, []), after_paths.get(k, []))
    }

    def cleared(vid: str, scope: set[tuple[str, str]]) -> bool:
        # Every targeted manifest's instance of the id must be gone.
        mine = [k for k in scope if k[1] == vid]
        if not mine:
            return vid not in after_ids
        return all(instance_gone(k) for k in mine)

    ids_absent = [
        vid for vid in scored_group.vuln_ids if rescan_ok and cleared(vid, targets)
    ]
    # Targets only, so it reads against cleared/fixable. Totals union these
    # across single-upgrade attempts rather than summing them.
    remaining_by_severity = (
        _by_severity(before_inst[k] for k in targets - gone) if rescan_ok else {}
    )
    introduced = {k: v for k, v in after_inst.items() if k not in before_inst}

    # What the agent said it did, kept separate so the two can be compared.
    risk, risk_counts, vuln_risk = "", {}, []
    cost_usd = 0.0
    turn_budget, result_subtype = None, ""
    # The package manager bump's own outcomes. Nothing to bump is its own reason, ahead
    # of the symptoms. A re-lock that fails (the target does not resolve) fails
    # the deps gate: yarn and poetry then leave the project untouched, so
    # verify's install passes and the gates alone would read vuln-not-cleared,
    # where pip, Maven and Gradle fail verify's install for the same cause.
    bump_reasons: list[str] = []
    relock_failed = False
    pm_bump_managed = None
    if agent in PM_BUMP_AGENTS:
        bumped = load_json(out / "pm-bump.json") or {}
        pm_bump_managed = bool(bumped.get("managed"))
        if not bumped.get("applied"):
            bump_reasons = ["bump-not-applied"]
        else:
            relock_failed = (_read_int(out / "agent.exit") or 0) != 0
        # It claims what it bumped and re-locked; claimed_not_fixed then reads
        # "bumped, still vulnerable".
        claimed = [] if bump_reasons or relock_failed else list(scored_group.vuln_ids)
        in_tok = out_tok = 0
        vulns_new = None
        turns_used = None
        turn_capped = False
    elif agent in EVO_AGENTS:
        fix_report = load_json(out / "fix-report.json")
        claimed = list(parse_fix_report_claims(fix_report))
        risk, risk_counts = parse_breakability(fix_report)
        vuln_risk = parse_vuln_breakability(fix_report)
        facts = analytics_facts(parse_jsonl(out / "analytics.jsonl"))
        in_tok, out_tok = facts["input_tokens"], facts["output_tokens"]
        vulns_new = facts["vulns_new"]
        cost_usd = (
            in_tok * cfg.price_in_per_mtok + out_tok * cfg.price_out_per_mtok
        ) / 1_000_000
        turns_used = facts["agent_iterations"]
        turn_capped = _evo_cap_hits(_read_text(out / "evo-run.log")) > 0
    else:
        claimed = list(parse_claimed_ids(agent_debug_log, scored_group.vuln_ids))
        in_tok, out_tok = _claude_tokens(agent_debug_log)
        cost_usd = _claude_cost(agent_debug_log)
        vulns_new = None
        claude_result = _claude_result(agent_debug_log)
        turn_budget = _claude_turns(cfg)
        turns_used = claude_result.get("num_turns")
        result_subtype = claude_result.get("subtype") or ""
        turn_capped = result_subtype == "error_max_turns"

    # Hitting the memory cap is the harness's limit, not the agent's failure.
    oom_killed = (out / OOM_MARKER).exists()
    corrupt_artifact = _corrupt_artifact(out, "after")
    infra_error = _harness_error(agent, out, timed_out=agent_timed_out)
    harness_error = oom_killed or corrupt_artifact or infra_error is not None

    # Identities when the baseline left per-test reports, else counts from the log.
    baseline_results = baseline._test_results
    regressed = None
    if baseline_results is not None:
        after_results = _test_results(work, out, "after")
        regressed = regressed_tests(baseline_results, after_results)
        tests_after_count = passed_count(after_results) if after_results is not None else None
    else:
        tests_after_count = count_passed_tests(_read_text(out / "test-after.log"), framework)
    tests_exit = _read_int(out / "test-after.exit")
    tests_ok = _tests_ok(baseline.tests_passed_count, tests_after_count, tests_exit, regressed)

    changed = diff_dep_graph(cli_before, cli_after)
    unexpected = unrelated_bumps(cli_before, cli_after, changed, plan, group, scored_group)
    deps_ok = False if relock_failed else _tri_state_exit(out / "install-after.exit")

    verdict = judge(
        scored_group,
        ids_absent=ids_absent,
        agent_claimed_ids=claimed,
        tests_ok=tests_ok,
        boots=_tri_state_exit(out / "boot.exit"),
        unexpected_collateral=unexpected,
        build_ok=_tri_state_exit(out / "build.exit"),
        deps_ok=deps_ok,
        # Collateral asks "did the agent stay inside the upgrade it was asked
        # to make". It is always recorded on the attempt; under
        # --strict-collateral the attempt is failed for it.
        strict_collateral=cfg.strict_collateral,
        rescan_ok=rescan_ok,
        harness_error=harness_error,
    )

    attempt = AgentAttempt(
        agent=agent,
        label=scored_group.label,
        group_index=group.index if group else None,
        requested_ids=list(scored_group.vuln_ids),
        agent_exit=_read_int(out / "agent.exit"),
        agent_claimed=claimed,
        ids_absent=ids_absent,
        deps_ok=deps_ok,
        build_ok=_tri_state_exit(out / "build.exit"),
        tests_ok=tests_ok,
        tests_passed_count_before=baseline.tests_passed_count,
        tests_passed_count_after=tests_after_count,
        tests_regressed_count=len(regressed) if regressed is not None else None,
        tests_regressed=(regressed or [])[:_MAX_REGRESSED_LISTED],
        tests_modified=modified_test_files(_read_text(out / "agent.diff")),
        boots=_tri_state_exit(out / "boot.exit"),
        deps_changed=changed,
        unexpected_collateral=list(verdict.unexpected_collateral),
        vulns_new=vulns_new,
        verified=verdict.verified,
        claimed_not_fixed=verdict.claimed_not_fixed,
        unresolved_ids=list(verdict.unresolved_ids),
        reasons=bump_reasons + list(verdict.reasons) + (["oom-killed"] if oom_killed else [])
        + (["corrupt-artifact"] if corrupt_artifact else [])
        + ([infra_error] if infra_error else []),
        input_tokens=in_tok,
        output_tokens=out_tok,
        latency_s=round(latency, 2),
        timed_out=timed_out,
        budget_s=budget,
        turn_budget=turn_budget,
        turns_used=turns_used,
        result_subtype=result_subtype,
        turn_capped=turn_capped,
        pm_bump_managed=pm_bump_managed,
        breakability_risk=risk,
        breakability_counts=risk_counts,
        vuln_breakability=vuln_risk,
        harness_error=harness_error,
        snyk_policy_modified=_touches_snyk_policy(_read_text(out / "agent.diff")),
        cost_usd=cost_usd,
        fixable_total=len(targets),
        fixable_cleared=len(gone),
        instances=sorted(targets),
        instances_cleared=sorted(gone),
        instances_moved=sorted(moved),
        remaining_by_severity=remaining_by_severity,
        introduced_count=len(introduced) if rescan_ok else None,
        introduced_by_severity=_by_severity(introduced.values()),
        new_projects=new_projects,
        scan_without_wrapper=(out / "snyk-test-after-wrapper.txt").exists(),
        snyk_access=mount_snyk is not False,
    )
    return attempt, work, out


def _target_instances(
    before_inst: dict[tuple[str, str], str], groups: list[FixGroup]
) -> set[tuple[str, str]]:
    """Baseline (manifest, id) instances the given groups are meant to clear."""
    out: set[tuple[str, str]] = set()
    for g in groups:
        for vid in g.vuln_ids:
            same_id = {k for k in before_inst if k[1] == vid}
            in_manifest = {k for k in same_id if k[0] == project_key(g.manifest)}
            # Fall back to every manifest if the plan's manifest name does not
            # line up with the scan's, rather than silently scoring nothing.
            out |= in_manifest or same_id
    return out


def _paths_cleared(
    group: FixGroup, before_paths: list[list[str]], after_paths: list[list[str]]
) -> bool:
    """No remaining path goes through this group's fix or through a direct
    dependency the baseline didn't reach this vuln by. Falls back to "no path at
    all" when none of the baseline paths were the group's (naming mismatch)."""
    if not any(group.owns_path(p) for p in before_paths):
        return not after_paths
    return not any(group.owns_path(p) for p in after_paths) and not _new_paths(
        group, before_paths, after_paths
    )


def _paths_moved(
    group: FixGroup, before_paths: list[list[str]], after_paths: list[list[str]]
) -> bool:
    """The group's own paths are gone, but the vuln now arrives through a new
    direct dependency (e.g. a relocated Maven coordinate): moved, not cleared."""
    return (
        any(group.owns_path(p) for p in before_paths)
        and not any(group.owns_path(p) for p in after_paths)
        and bool(_new_paths(group, before_paths, after_paths))
    )


def _new_paths(
    group: FixGroup, before_paths: list[list[str]], after_paths: list[list[str]]
) -> list[list[str]]:
    # Other direct deps that carried the vuln before stay their own job (another
    # group's, or nobody's); a new one is the agent moving the vuln, not clearing it.
    others = {_direct(p) for p in before_paths if not group.owns_path(p)}
    return [p for p in after_paths if not group.owns_path(p) and _direct(p) not in others]


def _direct(path: list[str]) -> str:
    return split_package_spec(path[1])[0] if len(path) > 1 else ""


def _by_severity(severities) -> dict[str, int]:
    counts: dict[str, int] = {}
    for sev in severities:
        counts[sev or "unknown"] = counts.get(sev or "unknown", 0) + 1
    return counts


# Regressed test ids kept in the report JSON; the full set is in test-results-*.json.
_MAX_REGRESSED_LISTED = 50


def _tests_ok(
    before: int | None,
    after: int | None,
    exit_code: int | None,
    regressed: list[str] | None = None,
) -> bool | None:
    """Every baseline-passing test still passes; without identities, as many pass.

    ``regressed`` (baseline-passed tests now failed, skipped or missing) decides
    when the baseline left per-test reports. Otherwise counts: a baseline count
    with no count after is not measured (None), never an exit-code pass, since
    an unparseable log is also what a disabled test task produces. The exit code
    decides only when the baseline had no count either.
    """
    if regressed is not None:
        return not regressed
    if before is not None:
        return after >= before if after is not None else None
    if exit_code is not None:
        return exit_code == 0
    return None


# Baseline failures that are worth retrying: a scan or plan that produced
# nothing is usually the network or a loaded machine, not the fixture. A
# genuinely broken fixture fails on tests, build or boot, and retrying that
# just wastes time — so those are NOT retried.
_TRANSIENT_BASELINE_REASONS = frozenset({"baseline-scan-failed", "no-fix-plan"})
_BASELINE_ATTEMPTS = 3


def run_baseline_with_retry(
    scenario: Scenario,
    cfg: HarnessConfig,
    repos_dir: Path,
    say,
) -> tuple[BaselineResult, FixPlan | None, list[tuple[Path, Path]]]:
    """Run the baseline, retrying only transient-looking failures.

    Losing a whole case to one flaky `snyk test` is unacceptable in an
    unattended sweep: the case is then excluded from every agent's denominator
    and the run silently covers less than it claims to.
    """
    dirs: list[tuple[Path, Path]] = []
    result = plan = None
    for attempt in range(1, _BASELINE_ATTEMPTS + 1):
        result, plan, work, out = run_baseline(scenario, cfg, repos_dir)
        dirs.append((work, out))
        if result.valid:
            return result, plan, dirs
        transient = set(result.invalid_reasons) <= _TRANSIENT_BASELINE_REASONS
        if not transient or attempt == _BASELINE_ATTEMPTS:
            return result, plan, dirs
        say(
            f"{scenario.name}: baseline {','.join(result.invalid_reasons)} "
            f"(attempt {attempt}/{_BASELINE_ATTEMPTS}), retrying"
        )
    return result, plan, dirs


def run_case(
    scenario: Scenario,
    cfg: HarnessConfig,
    repos_dir: Path,
    *,
    agents: tuple[str, ...] = ALL_AGENTS,
    concurrency: int = 1,
    progress: Callable[[str], None] | None = None,
) -> tuple[CaseResult, list[tuple[Path, Path]]]:
    """Run every agent against one fixture. Returns (result, temp dirs to reap).

    An invalid baseline short-circuits: no agent runs, and the case is reported
    as invalid rather than as anybody's failure.

    concurrency runs attempts in parallel. Fresh-copy isolation makes this
    safe — every attempt has its own work dir, out dir and container, and
    shares nothing but the read-only fixture. The limit is not CPU, it is the
    LLM provider's rate limit: every attempt is an agent invocation, so this
    defaults to 1.
    """
    say = progress or (lambda _m: None)

    say(f"{scenario.name}: baseline + fix plan")
    baseline, plan, dirs = run_baseline_with_retry(scenario, cfg, repos_dir, say)

    if not baseline.valid or plan is None:
        return CaseResult(name=scenario.name, baseline=baseline, attempts=[]), dirs

    # The out dir of the attempt that succeeded is the last one recorded.
    baseline_out = dirs[-1][1]
    # Attempts start from fresh copies and only the out dirs are read from here
    # on, so drop the baseline working copies now: tens of GB on large repos.
    for work, _ in dirs:
        shutil.rmtree(work, ignore_errors=True)
    cli_before = scope_to_manifests(
        load_json(baseline_out / "snyk-test-before.json"), scenario.manifests
    )
    scan_report = _read_text(baseline_out / "snyk-test-before.txt")

    tasks = [(agent, group) for agent in agents for group in plan.groups]

    # Build the agent image once, before any workers start. Concurrent
    # ensure_claude_image calls would otherwise race on the same docker build.
    say(
        f"{scenario.name}: baseline OK "
        f"({baseline.tests_passed_count} tests, {baseline.vulns} vulns) -> "
        f"{plan.total_groups} fix groups covering "
        f"{len(plan.all_fixable_vuln_ids)} vuln ids; {len(tasks)} attempts"
    )

    if tasks:
        say(f"{scenario.name}: preparing agent image")
        _agent_image(scenario, cfg)

    total = len(tasks)

    def run_one(indexed: tuple[int, tuple[str, FixGroup | None]]):
        # Index comes from the task list, not a shared counter. Under
        # concurrency several attempts are in flight at once, so a counter
        # incremented on completion makes every running attempt report the
        # same number.
        n, (agent, group) = indexed
        label = group.label
        say(f"  [{n}/{total}] {agent}: {label} ...")
        result = run_attempt(
            scenario, cfg, repos_dir,
            agent=agent, group=group, plan=plan,
            baseline=baseline, cli_before=cli_before, scan_report=scan_report,
        )
        a = result[0]
        if not a.verified:
            if a.agent in PM_BUMP_AGENTS and a.deps_ok is False and a.agent_exit:
                # A failed re-lock: its error is in the agent's log, and
                # verify's install (of the untouched project) is clean.
                fc = classify("deps", _read_text(result[2] / "agent-debug.log"),
                              _read_text(baseline_out / "install-before.log"),
                              [d.model_dump() for d in a.deps_changed])
            else:
                fc = classify_dirs(a.reasons, a.timed_out, result[2], baseline_out,
                                   [d.model_dump() for d in a.deps_changed],
                                   turn_capped=a.turn_capped)
            a.failure = asdict(fc) if fc else None
        verdict = "PASS" if a.verified else (
            ("HARNESS_ERROR: " if a.harness_error else "TIME_OUT: " if a.timed_out
             else "TURN_CAP: " if a.turn_capped else "FAIL: ")
            + ",".join(a.reasons)
            + (f" [{a.failure['category']}]" if a.failure else ""))
        claim = " CLAIMED-NOT-FIXED" if a.claimed_not_fixed else ""
        say(f"  [{n}/{total}] {agent}: {verdict}{claim} "
            f"({a.total_tokens:,} tok, {a.latency_s:.0f}s)")
        return result

    indexed = list(enumerate(tasks, start=1))
    if concurrency > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(run_one, indexed))
    else:
        results = [run_one(t) for t in indexed]

    attempts: list[AgentAttempt] = []
    for attempt, w, o in results:
        attempts.append(attempt)
        dirs.append((w, o))

    return CaseResult(name=scenario.name, baseline=baseline, attempts=attempts), dirs

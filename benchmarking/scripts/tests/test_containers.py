import json
import os
import subprocess
from pathlib import Path

import pytest

from harness import benchmark, docker
from harness.agents import (
    AGENT_CLAUDE_SNYK_SINGLE_UPGRADE,
    AGENT_EVO_SINGLE_UPGRADE,
)
from harness.benchmark import (
    _claude_api_refused,
    _claude_result,
    _evo_cap_hits,
    _harness_error,
    _touches_snyk_policy,
    run_attempt,
)
from harness.failure_class import classify, classify_dirs
from harness.fix_plan import FixPlan
from harness.outcome import BaselineResult
from harness.scenario import HarnessConfig, Scenario
from harness.verdict import REASON_HARNESS_ERROR, judge

GHOST = json.loads((Path(__file__).parent / "fixtures" / "ghost_before_trimmed.json").read_text())


# --------------------------------------------------------------------------
# docker command construction
# --------------------------------------------------------------------------

@pytest.fixture
def captured(monkeypatch):
    calls = []

    def fake_run(args, **_kw):
        # Only `docker run`; the inspect/rm that reap each container are noise here.
        if args[1] == "run":
            calls.append(args)
        return subprocess.CompletedProcess(args, 0, "false\n", "")

    monkeypatch.setattr(docker.subprocess, "run", fake_run)
    return calls


def _scenario(name="goparrot-geocoder", **kw):
    return Scenario(name=name, images={}, test_cmd="npm test", image="node:20", **kw)


def _run(tmp_path, scenario=None, cfg=None, **kw):
    docker.docker_run(scenario or _scenario(), cfg or HarnessConfig(), tmp_path, tmp_path, **kw)


def _env(args):
    return {args[i + 1] for i, a in enumerate(args) if a == "-e"}


def _blocked(args):
    return {a.split("=", 1)[1] for a in args if a.startswith("--add-host=") and a.endswith(":0.0.0.0")}


def test_github_blocked_in_agent_phase_only(tmp_path, captured):
    _run(tmp_path, phase=docker.PHASE_AGENT)
    _run(tmp_path, phase=docker.PHASE_VERIFY)
    _run(tmp_path, phase=docker.PHASE_BASELINE)
    agent, verify, baseline = captured
    assert _blocked(agent) == {f"{h}:0.0.0.0" for h in docker.GITHUB_HOSTS}
    assert not _blocked(verify) and not _blocked(baseline)
    # host.docker.internal stays mapped everywhere.
    assert "--add-host=host.docker.internal:host-gateway" in verify


def test_snyk_hosts_blocked_only_for_agents_denied_snyk(tmp_path, captured):
    _run(tmp_path, phase=docker.PHASE_AGENT, mount_snyk=False)
    _run(tmp_path, phase=docker.PHASE_AGENT)
    _run(tmp_path, phase=docker.PHASE_VERIFY, mount_snyk=False)
    unaided, aided, verify = captured
    snyk = {f"{h}:0.0.0.0" for h in docker.SNYK_HOSTS}
    assert snyk <= _blocked(unaided)
    assert not snyk & _blocked(aided) and not _blocked(verify)


def test_github_not_blocked_for_cases_that_need_it(tmp_path, captured):
    _run(tmp_path, scenario=_scenario("qdrant-qdrant-client"), phase=docker.PHASE_AGENT)
    assert not _blocked(captured[0])


def test_verify_runs_as_root_with_default_home(tmp_path, captured):
    _run(tmp_path, phase=docker.PHASE_VERIFY)
    args = captured[0]
    assert args[args.index("--user") + 1] == "0:0"
    assert not any(e.startswith("HOME=") for e in _env(args))
    assert "PHASE=verify" in _env(args)


def _sandbox_tmp(args):
    return Path(next(a.removesuffix(":/tmp") for a in args if a.endswith(":/tmp")))


def test_agent_phase_runs_in_prod_like_sandbox(tmp_path, captured):
    # Same sandbox whichever agent runs: there is no per-agent switch.
    _run(tmp_path, phase=docker.PHASE_AGENT)
    args = captured[0]
    assert args[args.index("--user") + 1] != "0:0"
    assert "--read-only" in args
    sandbox = _sandbox_tmp(args).parent
    assert sandbox.name.startswith("vulnbump-agent-")
    assert f"{sandbox / 'passwd'}:/etc/passwd:ro" in args
    assert {
        "HOME=/tmp", "GRADLE_USER_HOME=/tmp/.gradle",
        "MAVEN_OPTS=-Dmaven.repo.local=/tmp/.m2", "npm_config_cache=/tmp/.npm",
    } <= _env(args)


def test_anthropic_api_key_reaches_the_agent(tmp_path, captured, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    _run(tmp_path, phase=docker.PHASE_AGENT)
    assert "ANTHROPIC_API_KEY" in captured[0]


def test_entrypoint_scans_ignore_policy_and_has_no_fix_phase():
    text = docker.Path(docker.__file__).with_name("entrypoint.sh").read_text()
    assert "--ignore-policy" in text
    assert "\n  fix)" not in text
    assert subprocess.run(["sh", "-n", str(docker.Path(docker.__file__).with_name("entrypoint.sh"))]).returncode == 0


# --------------------------------------------------------------------------
# run_attempt orchestration: agent container, then a fresh root verify
# --------------------------------------------------------------------------

def test_memory_cap_defaults_and_per_case_override(tmp_path, captured):
    _run(tmp_path)
    _run(tmp_path, scenario=_scenario(memory="32g"))
    default, override = captured
    assert default[default.index("--memory") + 1] == docker.DEFAULT_MEMORY
    assert override[override.index("--memory") + 1] == "32g"
    assert "--rm" not in default


def test_gradle_fork_cap_mounted_for_root_phases(tmp_path, captured):
    _run(tmp_path)
    assert any(a.endswith(":/root/.gradle/init.d/limits.gradle:ro") for a in captured[0])


def test_agent_tmp_seeded_writable_and_removed(tmp_path, monkeypatch):
    # Nested bind mounts under /tmp made Docker create /tmp/.m2 and
    # /tmp/.gradle as root, so the non-root agent couldn't run Maven or Gradle.
    monkeypatch.setenv("MAVEN_MIRROR_URL", "http://mirror")
    seen = {}

    def fake_run(args, **_kw):
        if args[1] == "run":
            tmp = seen["tmp"] = _sandbox_tmp(args)
            seen["files"] = sorted(str(p.relative_to(tmp)) for p in tmp.rglob("*") if p.is_file())
            seen["writable"] = all(os.access(d, os.W_OK) for d in (tmp / ".m2", tmp / ".gradle" / "init.d"))
            assert not any(":/tmp/" in a for a in args)
            seen["passwd"] = (tmp.parent / "passwd").read_text()
        return subprocess.CompletedProcess(args, 0, "false\n", "")

    monkeypatch.setattr(docker.subprocess, "run", fake_run)
    _run(tmp_path, phase=docker.PHASE_AGENT)
    assert seen["files"] == [
        ".gradle/init.d/limits.gradle", ".gradle/init.d/maven-mirror.gradle", ".m2/settings.xml",
    ]
    assert seen["writable"]
    assert f"vulnbump:x:{os.getuid()}:{os.getgid()}:vulnbump:/tmp:" in seen["passwd"]
    assert not seen["tmp"].parent.exists()


@pytest.mark.parametrize("oom", [True, False])
def test_oom_killed_container_leaves_marker_and_is_removed(tmp_path, monkeypatch, oom):
    calls = []

    def fake_run(args, **_kw):
        calls.append(args[:2])
        out = "true\n" if oom and args[1] == "inspect" else ""
        return subprocess.CompletedProcess(args, 0, out, "")

    monkeypatch.setattr(docker.subprocess, "run", fake_run)
    _run(tmp_path)
    assert (tmp_path / docker.OOM_MARKER).exists() is oom
    assert calls == [["docker", "run"], ["docker", "inspect"], ["docker", "rm"]]


def test_baseline_oom_is_invalid():
    b = BaselineResult(tests_passed_count=5, tests_exit=0, scan_ok=True, plan_present=True, oom_killed=True)
    assert not b.valid and "baseline-oom-killed" in b.invalid_reasons


def test_run_attempt_splits_agent_and_verify(tmp_path, monkeypatch):
    repos = tmp_path / "repos"
    (repos / "demo").mkdir(parents=True)
    (repos / "demo" / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}\n')
    calls = []

    def fake_docker_run(scenario, cfg, work, out, *, phase, **kw):
        calls.append((phase, out, sorted(p.name for p in out.iterdir()), kw))
        if phase == docker.PHASE_AGENT:
            (work / "package.json").write_text('{"dependencies": {"a": "2.0.0"}}\n')
            (work / ".snyk").write_text("ignore: {}\n")
            (out / "agent.log").write_text("Evo output\n")
            (out / "agent.exit").write_text("0\n")
            (out / "agent.seconds").write_text("42\n")
            (out / "fix-report.json").write_text("{}")
            # A forged scan the agent hopes verification picks up.
            (out / "snyk-test-after.json").write_text(json.dumps({"vulnerabilities": []}))
        else:
            # Verify generates a lockfile; it must not show up in agent.diff.
            (work / "package-lock.json").write_text("{}")
        return subprocess.CompletedProcess([], 0, "", ""), False

    monkeypatch.setattr(benchmark, "docker_run", fake_docker_run)
    monkeypatch.setattr(benchmark, "ensure_claude_image", lambda *a, **kw: "agent-img")
    plan = FixPlan.from_scan(GHOST)
    attempt, work, out = run_attempt(
        Scenario(name="demo", images={}, test_cmd="npm test", image="node:20"),
        HarnessConfig(), repos,
        agent=AGENT_EVO_SINGLE_UPGRADE, group=plan.groups[0], plan=plan,
        baseline=BaselineResult(tests_passed_count=1, tests_exit=0),
        cli_before=GHOST,
    )

    (agent_phase, agent_out, _, agent_kw), (verify_phase, verify_out, verify_seen, verify_kw) = calls
    assert (agent_phase, verify_phase) == (docker.PHASE_AGENT, docker.PHASE_VERIFY)
    assert agent_out != verify_out == out
    assert verify_seen == []                       # fresh, empty /out
    # Evo runs in the same image as Claude; verify in the fixture's own.
    assert agent_kw["image"] == "agent-img"
    assert "--prepare-env" in agent_kw["agent_cmd"]
    assert "image" not in verify_kw
    assert not agent_out.exists()                  # reaped after collection
    # Agent artefacts carried over; the forged scan is not.
    assert (out / "agent.log").exists() and (out / "fix-report.json").exists()
    assert not (out / "snyk-test-after.json").exists()
    diff = (out / "agent.diff").read_text()
    assert "package.json" in diff and "package-lock.json" not in diff
    assert attempt.snyk_policy_modified is True
    assert attempt.latency_s == 42
    assert attempt.harness_error is False
    assert "verification-scan-failed" in attempt.reasons


def test_oom_in_either_phase_is_a_harness_error(tmp_path, monkeypatch):
    repos = tmp_path / "repos"
    (repos / "demo").mkdir(parents=True)
    (repos / "demo" / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}\n')

    def fake_docker_run(scenario, cfg, work, out, *, phase, **kw):
        if phase == docker.PHASE_AGENT:
            (out / "fix-report.json").write_text("{}")
            (out / "agent.exit").write_text("0\n")
            (out / docker.OOM_MARKER).touch()
        return subprocess.CompletedProcess([], 0, "", ""), False

    monkeypatch.setattr(benchmark, "docker_run", fake_docker_run)
    monkeypatch.setattr(benchmark, "ensure_claude_image", lambda *a, **kw: "agent-img")
    plan = FixPlan.from_scan(GHOST)
    attempt, _, _ = run_attempt(
        Scenario(name="demo", images={}, test_cmd="npm test", image="node:20"),
        HarnessConfig(), repos,
        agent=AGENT_EVO_SINGLE_UPGRADE, group=plan.groups[0], plan=plan,
        baseline=BaselineResult(tests_passed_count=1, tests_exit=0),
        cli_before=GHOST,
    )
    assert attempt.harness_error is True
    assert attempt.reasons[0] == REASON_HARNESS_ERROR and "oom-killed" in attempt.reasons


def test_rescan_retried_without_maven_wrapper_is_recorded(tmp_path, monkeypatch):
    repos = tmp_path / "repos"
    (repos / "demo").mkdir(parents=True)
    (repos / "demo" / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}\n')

    def fake_docker_run(scenario, cfg, work, out, *, phase, **kw):
        if phase == docker.PHASE_AGENT:
            (out / "fix-report.json").write_text("{}")
            (out / "agent.exit").write_text("0\n")
        else:
            (out / "snyk-test-after-wrapper.txt").write_text("Cannot build Maven dependency tree\n")
            (out / "snyk-test-after.json").write_text(json.dumps(GHOST))
        return subprocess.CompletedProcess([], 0, "", ""), False

    monkeypatch.setattr(benchmark, "docker_run", fake_docker_run)
    monkeypatch.setattr(benchmark, "ensure_claude_image", lambda *a, **kw: "agent-img")
    plan = FixPlan.from_scan(GHOST)
    attempt, _, _ = run_attempt(
        Scenario(name="demo", images={}, test_cmd="npm test", image="node:20"),
        HarnessConfig(), repos,
        agent=AGENT_EVO_SINGLE_UPGRADE, group=plan.groups[0], plan=plan,
        baseline=BaselineResult(tests_passed_count=1, tests_exit=0),
        cli_before=GHOST,
    )
    assert attempt.scan_without_wrapper is True
    assert "verification-scan-failed" not in attempt.reasons


def test_baseline_corrupt_artifact_is_invalid():
    b = BaselineResult(tests_passed_count=5, tests_exit=0, scan_ok=True, plan_present=True,
                       corrupt_artifact=True)
    assert not b.valid and "baseline-corrupt-artifact" in b.invalid_reasons


@pytest.mark.parametrize("log, line", [
    ("install-after.log", "Could not transfer artifact x:y:pom:1 from/to maven-cache: "
                          "Checksum validation failed, expected 'a' but is actually 'b'"),
    ("test-after.log", "[WARNING] Could not validate integrity of download from http://m/x.pom"),
    ("build.log", "> Could not parse POM http://m/x/1/x-1.pom"),
])
def test_corrupt_artifact_is_a_harness_error(tmp_path, monkeypatch, log, line):
    repos = tmp_path / "repos"
    (repos / "demo").mkdir(parents=True)
    (repos / "demo" / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}\n')

    def fake_docker_run(scenario, cfg, work, out, *, phase, **kw):
        if phase == docker.PHASE_AGENT:
            (out / "fix-report.json").write_text("{}")
            (out / "agent.exit").write_text("0\n")
        else:
            (out / log).write_text(f"[INFO] Scanning\n{line}\n")
        return subprocess.CompletedProcess([], 0, "", ""), False

    monkeypatch.setattr(benchmark, "docker_run", fake_docker_run)
    monkeypatch.setattr(benchmark, "ensure_claude_image", lambda *a, **kw: "agent-img")
    plan = FixPlan.from_scan(GHOST)
    attempt, _, _ = run_attempt(
        Scenario(name="demo", images={}, test_cmd="npm test", image="node:20"),
        HarnessConfig(), repos,
        agent=AGENT_EVO_SINGLE_UPGRADE, group=plan.groups[0], plan=plan,
        baseline=BaselineResult(tests_passed_count=1, tests_exit=0),
        cli_before=GHOST,
    )
    assert attempt.harness_error is True
    assert attempt.reasons[0] == REASON_HARNESS_ERROR and "corrupt-artifact" in attempt.reasons


# --------------------------------------------------------------------------
# .snyk detection
# --------------------------------------------------------------------------

def test_agent_diff_keeps_gitignored_lockfile_and_snyk(tmp_path):
    work = tmp_path / "app"
    (work / "node_modules" / "x").mkdir(parents=True)
    (work / ".gitignore").write_text("package-lock.json\n.snyk\n")
    (work / "package-lock.json").write_text('{"v": 1}\n')
    (work / "node_modules" / "x" / "package-lock.json").write_text("{}\n")
    git_dir, tree = benchmark._snapshot(work)
    (work / "package-lock.json").write_text('{"v": 2}\n')
    (work / ".snyk").write_text("ignore: {}\n")
    (work / "node_modules" / "x" / "package-lock.json").write_text('{"v": 2}\n')
    (work / "?" / ".m2").mkdir(parents=True)
    (work / "?" / ".m2" / "a.pom").write_text("x\n")
    dest = tmp_path / "agent.diff"
    benchmark._write_agent_diff(git_dir, tree, work, dest)
    files = [line.split()[2] for line in dest.read_text().splitlines() if line.startswith("diff --git")]
    assert files == ["a/.snyk", "a/package-lock.json"]


def test_snyk_policy_detection():
    added = "diff --git a/.snyk b/.snyk\nnew file mode 100644\n--- /dev/null\n+++ b/.snyk\n@@ -0,0 +1 @@\n+ignore: {}\n"
    nested = "diff --git a/pkg/.snyk b/pkg/.snyk\n--- a/pkg/.snyk\n+++ b/pkg/.snyk\n"
    other = "diff --git a/.snyk.bak b/.snyk.bak\n+++ b/.snyk.bak\n+++ b/docs/snyk\n"
    assert _touches_snyk_policy(added) and _touches_snyk_policy(nested)
    assert not _touches_snyk_policy(other) and not _touches_snyk_policy("")


# --------------------------------------------------------------------------
# harness-error detection
# --------------------------------------------------------------------------

OK_RESULT = json.dumps({"type": "result", "subtype": "success", "is_error": False,
                        "usage": {"input_tokens": 10, "output_tokens": 500}, "total_cost_usd": 0.4})
AUTH_FAIL = json.dumps({"type": "result", "subtype": "success", "is_error": True,
                        "result": "Invalid API key · Please run /login",
                        "usage": {"input_tokens": 0, "output_tokens": 0}, "total_cost_usd": 0})
MAX_TURNS = json.dumps({"type": "result", "subtype": "error_max_turns", "is_error": True,
                        "num_turns": 111, "usage": {"input_tokens": 10, "output_tokens": 900}})


def test_claude_api_refused_detection():
    assert _claude_api_refused(AUTH_FAIL)
    # stream-json: the result is the last event, after init/assistant events.
    assert _claude_api_refused('{"type":"system","subtype":"init"}\nnoise\n' + AUTH_FAIL)
    assert not _claude_api_refused(OK_RESULT + "\n")
    # Ran out of turns is a real (failed) run, not a harness error.
    assert not _claude_api_refused(MAX_TURNS)
    assert not _claude_api_refused("")


def test_claude_result_is_the_last_result_event():
    assert _claude_result('{"type":"system","subtype":"init"}\nnoise\n' + MAX_TURNS)["num_turns"] == 111
    assert _claude_result(OK_RESULT)["subtype"] == "success"
    assert _claude_result("not json\n") == {}


def test_evo_cap_hits_counts_cap_out_events():
    log = ('{"level":"info","event":"llm_usage","iteration":3}\n'
           '{"level":"info","event":"cap_out","iterations":100,"message":"agent: iteration cap reached"}\n')
    assert _evo_cap_hits(log) == 1
    assert _evo_cap_hits("") == 0


def _turn_attempt(tmp_path, monkeypatch, agent, files):
    repos = tmp_path / "repos"
    (repos / "demo").mkdir(parents=True)
    (repos / "demo" / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}\n')
    cmds = []

    def fake_docker_run(scenario, cfg, work, out, *, phase, **kw):
        if phase == docker.PHASE_AGENT:
            cmds.append(kw["agent_cmd"])
            (out / "agent.exit").write_text("1\n")
            for name, text in files.items():
                (out / name).write_text(text)
        return subprocess.CompletedProcess([], 0, "", ""), False

    monkeypatch.setattr(benchmark, "docker_run", fake_docker_run)
    monkeypatch.setattr(benchmark, "ensure_claude_image", lambda *a, **kw: "agent-img")
    plan = FixPlan.from_scan(GHOST)
    attempt, _, _ = run_attempt(
        Scenario(name="demo", images={}, test_cmd="npm test", image="node:20"),
        HarnessConfig(), repos,
        agent=agent, group=plan.groups[0], plan=plan,
        baseline=BaselineResult(tests_passed_count=1, tests_exit=0),
        cli_before=GHOST,
    )
    return attempt, cmds[0], plan


def test_claude_turn_cap_is_recorded(tmp_path, monkeypatch):
    attempt, cmd, _ = _turn_attempt(tmp_path, monkeypatch, AGENT_CLAUDE_SNYK_SINGLE_UPGRADE,
                                    {"agent-debug.log": MAX_TURNS + "\n"})
    assert "--max-turns 110" in cmd
    assert attempt.turn_budget == 110 and attempt.turns_used == 111
    assert attempt.result_subtype == "error_max_turns" and attempt.turn_capped is True
    assert attempt.harness_error is False


def test_evo_turn_cap_is_recorded(tmp_path, monkeypatch):
    summary = {"data": {"attributes": {"interaction": {"extension": {
        "event_type": "summary", "agent_iterations": 140}}}}}
    attempt, _, _ = _turn_attempt(tmp_path, monkeypatch, AGENT_EVO_SINGLE_UPGRADE, {
        "fix-report.json": "{}",
        "analytics.jsonl": json.dumps(summary) + "\n",
        "evo-run.log": '{"event":"cap_out","iterations":100}\n',
    })
    assert attempt.turn_budget is None and attempt.turns_used == 140
    assert attempt.turn_capped is True


def test_turn_cap_failure_class(tmp_path):
    fc = classify_dirs(["build-broken"], False, tmp_path, tmp_path, [], turn_capped=True)
    assert (fc.stage, fc.category) == ("build", "turn-cap")
    assert classify_dirs([], False, tmp_path, tmp_path, [], turn_capped=True).stage == "agent"
    # The wall-clock kill is the harder stop and wins.
    assert classify_dirs([], True, tmp_path, tmp_path, [], turn_capped=True).category == "timeout"



def test_error_codes_match_case_sensitively():
    # IGNORECASE once let ERESOLVE match inside "TemplateResolver".
    log = "[ERROR] TemplateResolverTest.render:42 expected:<a> but was:<b>"
    assert classify("tests", log).category == "test-assertion"
    assert classify("deps", "npm error code ERESOLVE").category == "dependency-conflict"
    assert classify("deps", "npm warn EBADENGINE Unsupported engine").category == "toolchain-version"

def test_claude_tokens_and_cost_sum_every_model():
    # `usage` covers the main model only; a second model shows up in modelUsage.
    multi = json.dumps({
        "type": "result", "total_cost_usd": 1.5,
        "usage": {"input_tokens": 1, "cache_creation_input_tokens": 10,
                  "cache_read_input_tokens": 100, "output_tokens": 5},
        "modelUsage": {
            "claude-sonnet-5": {"inputTokens": 1, "cacheCreationInputTokens": 10,
                                "cacheReadInputTokens": 100, "outputTokens": 5, "costUSD": 1.0},
            "claude-sonnet-4-5@20250929": {"inputTokens": 2, "cacheCreationInputTokens": 20,
                                           "cacheReadInputTokens": 200, "outputTokens": 7, "costUSD": 0.5},
        },
    })
    assert benchmark._claude_tokens(multi) == (333, 12)
    assert benchmark._claude_cost(multi) == 1.5
    # Without modelUsage, fall back to the top-level figures.
    assert benchmark._claude_tokens(OK_RESULT) == (10, 500)
    assert benchmark._claude_cost(OK_RESULT) == 0.4


GRADLE_WRAPPER_BLOCKED = """\
>>> stdout:
Downloading https://services.gradle.org/distributions/gradle-8.10.2-bin.zip

>>> stderr:
Exception in thread "main" java.net.ConnectException: Connection refused
    at java.base/sun.nio.ch.Net.pollConnect(Native Method)
    at java.base/java.net.Socket.connect(Socket.java:633)
    at org.gradle.wrapper.Download.downloadInternal(Download.java:129)
    at org.gradle.wrapper.Install.createDist(Install.java:68)
"""


def _attempt_out(tmp_path, log, exit_code="0"):
    (tmp_path / "agent.log").write_text(log)
    if exit_code is not None:
        (tmp_path / "agent.exit").write_text(f"{exit_code}\n")
    return tmp_path


@pytest.mark.parametrize("agent, log, exit_code, expected", [
    # Killed from outside (or never started): the entrypoint never wrote agent.exit.
    (AGENT_EVO_SINGLE_UPGRADE, "  [1/3] Scanning...\n", None, "agent-killed"),
    (AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, "", None, "agent-killed"),
    (AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, "sh: 1: claude: not found\n", "127", "agent-not-launched"),
    (AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, AUTH_FAIL, "1", "llm-auth"),
    (AGENT_EVO_SINGLE_UPGRADE, "  Error: Snyk rate limit exceeded.\n  Wait a few minutes\n", "2", "snyk-rate-limited"),
    (AGENT_EVO_SINGLE_UPGRADE, "  Error: Snyk is not authenticated.\n", "2", "snyk-auth"),
    (AGENT_EVO_SINGLE_UPGRADE, "Error: anthropic: POST /v1/messages: 401 Unauthorized\n", "1", "llm-auth"),
    (AGENT_EVO_SINGLE_UPGRADE, " ERROR   Unspecified Error (SNYK-CLI-0000)\n"
                 "           ANTHROPIC_API_KEY is not set in the environment\n", "2", "llm-auth"),
    (AGENT_EVO_SINGLE_UPGRADE, "  Error: Snyk scan failed.\n" + GRADLE_WRAPPER_BLOCKED, "2", "blocked-fetch"),
    # Evo's own failures are scored, tokens or not.
    (AGENT_EVO_SINGLE_UPGRADE, "  Error: Dependencies not installed.\n  Install:\n    npm install\n", "2", None),
    (AGENT_EVO_SINGLE_UPGRADE, "  Error: Snyk scan failed.\n/app/pom.xml:\nCannot build Maven dependency tree\n", "2", None),
    (AGENT_EVO_SINGLE_UPGRADE, "  ✗ Not fixed (5)\n", "0", None),
    # Past its scan, a blocked wrapper download is one of Evo's tool results.
    (AGENT_EVO_SINGLE_UPGRADE, "  ✔ Scan complete. Found 3 issues\n" + GRADLE_WRAPPER_BLOCKED, "0", None),
    # A rescan throttled after Evo made its changes still measured them.
    (AGENT_EVO_SINGLE_UPGRADE, "  Error: Re-scan failed — Snyk rate limit exceeded.\n", "1", None),
    (AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, OK_RESULT, "0", None),
    (AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, MAX_TURNS, "1", None),
    # Claude's crash without a result event is its own failure, like Evo's.
    (AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, "", "1", None),
])
def test_harness_error_only_on_infra_signatures(tmp_path, agent, log, exit_code, expected):
    out = _attempt_out(tmp_path, log, exit_code)
    assert _harness_error(agent, out, timed_out=False) == expected


def test_timeout_is_never_a_harness_error(tmp_path):
    out = _attempt_out(tmp_path, "", exit_code=None)
    assert _harness_error(AGENT_EVO_SINGLE_UPGRADE, out, timed_out=True) is None
    assert _harness_error(AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, out, timed_out=True) is None


def test_harness_error_verdict_is_not_verified():
    group = FixPlan.from_scan(GHOST).groups[0]
    v = judge(group, ids_absent=group.vuln_ids, tests_ok=True, boots=None, harness_error=True)
    assert not v.verified and v.reasons[0] == REASON_HARNESS_ERROR


def test_baseline_working_copy_is_dropped_after_the_baseline(tmp_path, monkeypatch):
    work, out = tmp_path / "work", tmp_path / "out"
    (work / "node_modules").mkdir(parents=True)
    out.mkdir()
    (out / "snyk-test-before.json").write_text(json.dumps(GHOST))
    baseline = BaselineResult(tests_passed_count=1, tests_exit=0, scan_ok=True, plan_present=True)
    monkeypatch.setattr(benchmark, "run_baseline_with_retry",
                        lambda *a, **kw: (baseline, FixPlan.from_scan(GHOST), [(work, out)]))

    _, dirs = benchmark.run_case(_scenario(), HarnessConfig(), tmp_path, agents=())

    assert dirs == [(work, out)]
    assert not work.exists() and (out / "snyk-test-before.json").exists()


def test_unreadable_agent_artefact_is_skipped(tmp_path, monkeypatch):
    # A container killed at its budget leaves root-only files behind.
    agent_out, out = tmp_path / "agent", tmp_path / "out"
    agent_out.mkdir(); out.mkdir()
    (agent_out / "agent.log").write_text("log")
    (agent_out / "analytics.jsonl").write_text("{}")
    real_copy = benchmark.shutil.copy2

    def copy2(src, dst, **kw):
        if Path(src).name == "analytics.jsonl":
            raise PermissionError(13, "Permission denied")
        return real_copy(src, dst, **kw)

    monkeypatch.setattr(benchmark.shutil, "copy2", copy2)
    benchmark._collect_agent_artefacts(agent_out, out)
    assert (out / "agent.log").read_text() == "log"
    assert not (out / "analytics.jsonl").exists()

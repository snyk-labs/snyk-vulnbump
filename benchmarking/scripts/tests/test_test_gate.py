"""Test gate: per-test identities from reports, log-count fallback, and the gate itself."""

import json
import os
import time
from pathlib import Path

import pytest

from harness.case_commands import CASE_OVERRIDES, ECOSYSTEM_COMMANDS
from harness import test_results
from harness.benchmark import _tests_ok
from harness.test_results import (
    FAILED,
    PASSED,
    SKIPPED,
    collect_test_results,
    count_passed_tests,
    passed_count,
    regressed_tests,
    report_window,
    modified_test_files,
)

# --------------------------------------------------------------------------
# log parsers (fallback), on snippets of real baseline logs
# --------------------------------------------------------------------------

# reactivex-rxjava, data/scans/20260924T113121Z: one failure, 746 skipped.
GRADLE_FAILED = """\
> Task :test

io.reactivex.rxjava3.core.NotificationTest > announce SKIPPED

io.reactivex.rxjava3.subjects.SingleSubjectTest > announce SKIPPED

13149 tests completed, 1 failed, 746 skipped

> Task :test FAILED

BUILD FAILED in 5m 19s
4 actionable tasks: 3 executed, 1 up-to-date
"""

# The same build all green: Gradle prints no summary at all.
GRADLE_GREEN = """\
> Task :compileTestJava
> Task :testClasses

> Task :test

io.reactivex.rxjava3.core.NotificationTest > announce SKIPPED

BUILD SUCCESSFUL in 5m 2s
4 actionable tasks: 3 executed, 1 up-to-date
"""

MAVEN_CLASS_LINES = """\
[INFO] Running org.pitest.elements.utils.InputStreamLineIterableTest
[INFO] Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.033 s - in org.pitest.elements.utils.InputStreamLineIterableTest
[INFO] Running org.pitest.elements.MutationHtmlReportListenerTest
[INFO] Tests run: 2, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.104 s - in org.pitest.elements.MutationHtmlReportListenerTest
"""


def _maven_module(name: str, run: int, failures: int, errors: int, skipped: int) -> str:
    return f"""\
[INFO] ------------------< org.example:{name} >------------------
[INFO] --- maven-surefire-plugin:3.0.0:test (default-test) @ {name} ---
[INFO] Tests run: {run}, Failures: {failures}, Errors: {errors}, Skipped: {skipped}, Time elapsed: 0.5 s - in org.example.{name}.SomeTest
[INFO]
[INFO] Results:
[INFO]
[INFO] Tests run: {run}, Failures: {failures}, Errors: {errors}, Skipped: {skipped}
[INFO]
"""


def test_maven_sums_every_module_and_excludes_skipped():
    log = (
        _maven_module("core", 10, 1, 0, 2)
        + _maven_module("api", 5, 0, 1, 0)
        + _maven_module("web", 4, 0, 0, 0)
        + "[INFO] Reactor Summary:\n[INFO] BUILD FAILURE\n"
    )
    # (10-1-2) + (5-1) + 4
    assert count_passed_tests(log, test_results.TestFramework.maven) == 15


def test_maven_real_single_module_summary():
    log = MAVEN_CLASS_LINES + (
        "[INFO] \n[INFO] Results:\n[INFO] \n"
        "[INFO] Tests run: 16, Failures: 0, Errors: 0, Skipped: 0\n[INFO] \n[INFO] BUILD SUCCESS\n"
    )
    assert count_passed_tests(log, test_results.TestFramework.maven) == 16


def test_maven_quiet_falls_back_to_class_lines():
    assert count_passed_tests(MAVEN_CLASS_LINES, test_results.TestFramework.maven) == 3


def test_gradle_skipped_is_not_passed():
    assert count_passed_tests(GRADLE_FAILED, test_results.TestFramework.gradle) == 13149 - 1 - 746


def test_gradle_all_green_is_not_measured():
    assert count_passed_tests(GRADLE_GREEN, test_results.TestFramework.gradle) is None


def test_gradle_per_test_lines_skip_skipped():
    log = "A > a() PASSED\nA > b() SKIPPED\nA > c() FAILED\nB > d() PASSED\n"
    assert count_passed_tests(log, test_results.TestFramework.gradle) == 2


def test_jest_sums_every_summary():
    # atlassian-react-beautiful-dnd's real summary, plus a turbo-prefixed second package.
    log = (
        "Test Suites: 1 failed, 237 passed, 238 total\n"
        "Tests:       2 failed, 1229 passed, 1231 total\n"
        "Snapshots:   2 passed, 2 total\n"
        "@medusajs/utils:test: Tests:       3 skipped, 40 passed, 43 total\n"
    )
    assert count_passed_tests(log, test_results.TestFramework.jest) == 1269


def test_mocha_sums_every_run():
    # tryghost-ghost and goparrot-geocoder summaries in one log.
    log = (
        "  ......................!!!!!!!!!.........................\n\n"
        "  68 passing (115ms)\n  9 failing\n\n"
        "        ✔ should return correct values without accuracy\n\n\n"
        "  594 passing (2s)\n  17 pending\n"
    )
    assert count_passed_tests(log, test_results.TestFramework.mocha) == 662


def test_pytest_sums_every_summary_and_ignores_output():
    log = (
        "tests/test_a.py ..F.\n"
        "the fixture reported 99 passed in 3s of setup\n"
        "=========== 1 failed, 3 passed, 2 warnings in 0.35s ===========\n"
        "12 passed, 1 skipped in 65.43s (0:01:05)\n"
    )
    assert count_passed_tests(log, test_results.TestFramework.pytest) == 15


# --------------------------------------------------------------------------
# reports
# --------------------------------------------------------------------------

def _write(path: Path, text: str, mtime: float | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


SUREFIRE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="org.example.FooTest" tests="4" failures="1" errors="1" skipped="1">
  <testcase name="passes" classname="org.example.FooTest" time="0.01"/>
  <testcase name="fails" classname="org.example.FooTest"><failure message="x"/></testcase>
  <testcase name="errors" classname="org.example.FooTest"><error message="y"/></testcase>
  <testcase name="skips" classname="org.example.FooTest"><skipped/></testcase>
</testsuite>
"""

PYTEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="2">
  <testcase classname="tests.test_app" name="test_home_route" time="0.1"/>
  <testcase classname="tests.test_app" name="test_param[a-1]" time="0.1"><skipped type="pytest.skip"/></testcase>
</testsuite></testsuites>
"""

JEST_JSON = {
    "numPassedTests": 1,
    "testResults": [
        {
            "name": "/app/src/a.test.ts",
            "assertionResults": [
                {"ancestorTitles": ["A"], "title": "works", "fullName": "A works", "status": "passed"},
                {"ancestorTitles": ["A"], "title": "breaks", "fullName": "A breaks", "status": "failed"},
                {"ancestorTitles": ["A"], "title": "later", "fullName": "A later", "status": "pending"},
            ],
        }
    ],
}


def test_collects_surefire_gradle_pytest_and_jest(tmp_path):
    work, junit = tmp_path / "app", tmp_path / "out" / "junit"
    _write(work / "core" / "target" / "surefire-reports" / "TEST-org.example.FooTest.xml", SUREFIRE_XML)
    _write(work / "lib" / "build" / "test-results" / "test" / "TEST-org.example.BarTest.xml",
           SUREFIRE_XML.replace("FooTest", "BarTest"))
    _write(work / "node_modules" / "x" / "target" / "surefire-reports" / "TEST-junk.xml", SUREFIRE_XML)
    _write(work / "target" / "surefire-reports" / "not-a-report.xml", SUREFIRE_XML)
    _write(junit / "pytest.xml", PYTEST_XML)
    _write(junit / "jest.json", json.dumps(JEST_JSON))

    results = collect_test_results(work, junit)

    assert results["org.example.FooTest#passes"] == PASSED
    assert results["org.example.FooTest#fails"] == FAILED
    assert results["org.example.FooTest#errors"] == FAILED
    assert results["org.example.FooTest#skips"] == SKIPPED
    assert results["org.example.BarTest#passes"] == PASSED
    assert results["tests.test_app#test_home_route"] == PASSED
    assert results["tests.test_app#test_param[a-1]"] == SKIPPED
    assert results["src/a.test.ts#A works"] == PASSED
    assert results["src/a.test.ts#A breaks"] == FAILED
    assert results["src/a.test.ts#A later"] == SKIPPED
    assert not any("junk" in t for t in results)
    assert passed_count(results) == 4


def test_no_reports_is_none(tmp_path):
    assert collect_test_results(tmp_path, tmp_path / "junit") is None


def test_duplicate_test_keeps_worst_status(tmp_path):
    ok = '<testsuite><testcase classname="C" name="t"/></testsuite>'
    bad = '<testsuite><testcase classname="C" name="t"><failure/></testcase></testsuite>'
    _write(tmp_path / "a" / "target" / "surefire-reports" / "TEST-C.xml", ok)
    _write(tmp_path / "b" / "target" / "surefire-reports" / "TEST-C.xml", bad)
    assert collect_test_results(tmp_path) == {"C#t": FAILED}


def test_truncated_report_is_ignored(tmp_path):
    _write(tmp_path / "target" / "surefire-reports" / "TEST-C.xml", "<testsuite><testcase")
    assert collect_test_results(tmp_path) is None


def test_report_window_drops_stale_and_future_reports(tmp_path):
    work, out = tmp_path / "app", tmp_path / "out"
    now = time.time()
    _write(out / "install-after.exit", "0", now - 100)
    _write(out / "build.exit", "0", now - 50)
    _write(out / "test-after.exit", "0", now)
    _write(out / "install-before.exit", "0", now - 10)  # agent phase's, copied late: not ours
    reports = work / "target" / "surefire-reports"
    fresh = '<testsuite><testcase classname="C" name="fresh"/></testsuite>'
    _write(reports / "TEST-Fresh.xml", fresh, now - 10)
    _write(reports / "TEST-Stale.xml", fresh.replace("fresh", "stale"), now - 500)
    _write(reports / "TEST-Forged.xml", fresh.replace("fresh", "forged"), now + 3600)

    since, until = report_window(out, "after")
    assert collect_test_results(work, since=since, until=until) == {"C#fresh": PASSED}


# --------------------------------------------------------------------------
# the gate
# --------------------------------------------------------------------------

BEFORE = {"C#a": PASSED, "C#b": PASSED, "C#flaky": FAILED, "C#off": SKIPPED}


def test_regressed_covers_failed_skipped_and_missing():
    after = {"C#a": FAILED, "C#flaky": PASSED}
    assert regressed_tests(BEFORE, after) == ["C#a", "C#b"]
    assert regressed_tests(BEFORE, {"C#a": SKIPPED, "C#b": PASSED}) == ["C#a"]
    assert regressed_tests(BEFORE, None) == ["C#a", "C#b"]


def test_swap_fails_even_when_count_holds():
    # A breaks, the flaky one recovers: same count, still a regression.
    after = {"C#a": FAILED, "C#b": PASSED, "C#flaky": PASSED}
    assert passed_count(after) == passed_count(BEFORE)
    assert _tests_ok(2, 2, 0, regressed_tests(BEFORE, after)) is False


def test_identities_decide_over_counts():
    assert _tests_ok(2, 3, 0, []) is True
    assert _tests_ok(2, 3, 0, ["C#a"]) is False


def test_missing_after_count_is_not_measured_not_exit_code():
    assert _tests_ok(12402, None, 0) is None


def test_count_fallback():
    assert _tests_ok(10, 10, 1) is True
    assert _tests_ok(10, 9, 0) is False


def test_exit_code_only_when_baseline_had_no_count():
    assert _tests_ok(None, None, 0) is True
    assert _tests_ok(None, None, 1) is False
    assert _tests_ok(None, None, None) is None


# --------------------------------------------------------------------------
# test-file tampering
# --------------------------------------------------------------------------

def test_modified_test_files_diff():
    diff = "\n".join([
        "diff --git a/pom.xml b/pom.xml",
        "diff --git a/src/test/java/FooTest.java b/src/test/java/FooTest.java",
        "diff --git a/packages/x/src/a.spec.ts b/packages/x/src/a.spec.ts",
        "diff --git a/lib/util.test.js b/lib/util.test.js",
        "diff --git a/tests/conftest.py b/tests/conftest.py",
        "diff --git a/pkg/test_app.py b/pkg/test_app.py",
        "diff --git a/pkg/app_test.py b/pkg/app_test.py",
        "diff --git a/src/__tests__/x.js b/src/__tests__/x.js",
        "diff --git a/src/main/java/Latest.java b/src/main/java/Latest.java",
        "diff --git a/package.json b/package.json",
        "diff --git a/tests/fixtures/basic_project/poetry.lock b/tests/fixtures/basic_project/poetry.lock",
        "diff --git a/src/test/resources/app/pom.xml b/src/test/resources/app/pom.xml",
    ])
    assert modified_test_files(diff) == [
        "lib/util.test.js", "packages/x/src/a.spec.ts", "pkg/app_test.py", "pkg/test_app.py",
        "src/__tests__/x.js", "src/test/java/FooTest.java", "tests/conftest.py",
    ]


# --------------------------------------------------------------------------
# case commands
# --------------------------------------------------------------------------

def test_case_commands_do_not_hide_failures():
    assert "-fae" in ECOSYSTEM_COMMANDS["maven"]["test_cmd"]
    assert "--continue" in ECOSYSTEM_COMMANDS["gradle"]["test_cmd"]
    for cmds in [*ECOSYSTEM_COMMANDS.values(), *CASE_OVERRIDES.values()]:
        install = cmds.get("install_cmd", "")
        assert "|| true" not in install and "2>/dev/null" not in install
    assert "poetry==" in ECOSYSTEM_COMMANDS["poetry"]["install_cmd"]


def test_maven_wrapper_cases_run_through_mvnw():
    import yaml
    from harness.case_commands import MAVEN_WRAPPER_CASES, generate_case

    row = {"ecosystem": "maven", "display": "citerus/dddsample-core", "manifest_file": "pom.xml",
           "repo_url": "u", "commit_sha": "c"}
    inputs = generate_case(row)["inputs"]
    assert inputs["install_cmd"] == "./mvnw -B dependency:resolve"
    assert inputs["build_cmd"] == "./mvnw -B -DskipTests compile"
    assert inputs["test_cmd"] == "./mvnw -B -fae -Dmaven.test.failure.ignore=true test"
    assert test_results._infer_test_framework(inputs["test_cmd"]) == test_results.TestFramework.maven

    # The checked-in case file agrees with the generator.
    path = Path(__file__).resolve().parents[2] / "cases" / "cases.yaml"
    for case in yaml.safe_load(path.read_text())["cases"]:
        if case["metadata"]["ecosystem"] != "maven":
            continue
        cmds = [case["inputs"].get(k) or "" for k in ("install_cmd", "build_cmd", "test_cmd")]
        wrapped = case["name"] in MAVEN_WRAPPER_CASES
        assert all(c.startswith("./mvnw ") == wrapped for c in cmds if c), case["name"]


@pytest.mark.parametrize("fails,expected", [(False, 0), (True, 1)])
def test_strict_install_exit_code_survives_fallback(tmp_path, fails, expected):
    import subprocess

    from harness.case_commands import _NPM_INSTALL

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "npm").write_text(
        f'#!/bin/sh\n[ "$1" = ci ] && exit {1 if fails else 0}\necho "$@" >> {tmp_path}/fallback\n'
    )
    (bin_dir / "npm").chmod(0o755)
    rc = subprocess.run(["sh", "-c", _NPM_INSTALL], env={"PATH": f"{bin_dir}:/usr/bin:/bin"}).returncode
    assert rc == expected
    assert (tmp_path / "fallback").exists() is fails


def test_run_attempt_gates_on_identities_and_flags_test_edits(tmp_path, monkeypatch):
    """Scripted agent adds @Disabled to a test: the skipped test fails the gate."""
    import subprocess

    from harness import benchmark, docker
    from harness.agents import AGENT_EVO_SINGLE_UPGRADE
    from harness.fix_plan import FixPlan
    from harness.outcome import BaselineResult
    from harness.scenario import HarnessConfig, Scenario

    ghost = json.loads((Path(__file__).parent / "fixtures" / "ghost_before_trimmed.json").read_text())
    repos = tmp_path / "repos"
    test_src = repos / "demo" / "src" / "test" / "java" / "FooTest.java"
    _write(test_src, "class FooTest { @Test void a() {} @Test void b() {} }\n")

    def fake_docker_run(scenario, cfg, work, out, *, phase, **kw):
        if phase == docker.PHASE_AGENT:
            p = work / "src" / "test" / "java" / "FooTest.java"
            p.write_text(p.read_text().replace("@Test void b", "@Disabled @Test void b"))
            (out / "agent.exit").write_text("0\n")
        else:
            (out / "install-after.exit").write_text("0\n")
            _write(work / "target" / "surefire-reports" / "TEST-FooTest.xml",
                   '<testsuite><testcase classname="FooTest" name="a"/>'
                   '<testcase classname="FooTest" name="b"><skipped/></testcase></testsuite>')
            (out / "test-after.log").write_text("[INFO] Tests run: 2, Failures: 0, Errors: 0, Skipped: 1\n")
            (out / "test-after.exit").write_text("0\n")
        return subprocess.CompletedProcess([], 0, "", ""), False

    monkeypatch.setattr(benchmark, "docker_run", fake_docker_run)
    monkeypatch.setattr(benchmark, "ensure_claude_image", lambda *a, **kw: "agent-img")
    baseline = BaselineResult(tests_passed_count=2, tests_identified=2, tests_exit=0)
    baseline._test_results = {"FooTest#a": PASSED, "FooTest#b": PASSED}
    plan = FixPlan.from_scan(ghost)
    attempt, _, out = benchmark.run_attempt(
        Scenario(name="demo", images={}, test_cmd="mvn -B test", image="maven", test_framework="maven"),
        HarnessConfig(), repos,
        agent=AGENT_EVO_SINGLE_UPGRADE, group=plan.groups[0], plan=plan, baseline=baseline, cli_before=ghost,
    )

    assert attempt.tests_ok is False
    assert attempt.tests_regressed == ["FooTest#b"] and attempt.tests_regressed_count == 1
    assert attempt.tests_passed_count_after == 1
    assert attempt.tests_modified == ["src/test/java/FooTest.java"]
    assert "tests-regressed" in attempt.reasons
    assert json.loads((out / "test-results-after.json").read_text())["FooTest#b"] == SKIPPED


def test_fuzz_tests_renamed_between_runs_are_not_regressed():
    before = {"f#md4 fuzzy [12,7] ok": PASSED, "f#md4 fuzzy [3,99] ok": PASSED, "f#plain": PASSED}
    after = {"f#md4 fuzzy [5,41] ok": PASSED, "f#md4 fuzzy [8] ok": PASSED, "f#plain": FAILED}
    assert regressed_tests(before, after) == ["f#md4 fuzzy [3,99] ok", "f#plain"]

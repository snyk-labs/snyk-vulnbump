"""Per-test results from machine-readable reports, with log parsing as fallback.

The gate prefers test identities: JUnit XML (surefire, Gradle, pytest
--junitxml) and Jest's --json file, keyed by ``classname#name``. When a run
leaves no report, each case's declared (or inferred) framework parser reads a
passed-test count from the log instead.
"""

from __future__ import annotations

import json
import os
import re
import warnings
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path


class TestFramework(StrEnum):
    jest = "jest"
    mocha = "mocha"
    pytest = "pytest"
    maven = "maven"
    gradle = "gradle"
    rspec = "rspec"
    go = "go"
    dotnet = "dotnet"
    phpunit = "phpunit"

# Jest / Vitest summary: "Tests:  7 passed, 7 total" or "Tests:  2 skipped, 5 passed, 7 total".
# One per jest run; turbo/lerna monorepos print several, prefixed by the package.
_JEST_PASSED = re.compile(r"\bTests:[^\n]*?(\d+)\s+passed", re.IGNORECASE)

# pytest summary: "===== 1 failed, 5 passed in 0.35s =====" or, with -q, "5 passed in 0.35s"
_PYTEST_SUMMARY = re.compile(
    r"^[= ]*(\d+ (?:passed|failed|errors?|skipped|xfailed|xpassed|deselected|warnings?)\b.*?)"
    r" in [\d.]+s\b",
    re.MULTILINE,
)
_PYTEST_PASSED = re.compile(r"(\d+)\s+passed\b")

# Maven surefire: "Tests run: 5, Failures: 0, Errors: 0, Skipped: 0"
_MAVEN_SUMMARY = re.compile(
    r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)"
    r"(?P<per_class>.*Time elapsed)?",
    re.IGNORECASE,
)

# RSpec: "3 examples, 0 failures"
_RSPEC_SUMMARY = re.compile(r"(\d+)\s+examples?,\s*(\d+)\s+failures?", re.IGNORECASE)

# PHPUnit: "OK (3 tests, 5 assertions)"
_PHPUNIT_OK = re.compile(r"OK\s*\(\s*(\d+)\s+tests?", re.IGNORECASE)

# PHPUnit failures still report executed tests: "Tests: 3, Assertions: 5, Failures: 1."
_PHPUNIT_TESTS = re.compile(r"Tests:\s*(\d+)", re.IGNORECASE)
_PHPUNIT_FAILURES = re.compile(r"Failures:\s*(\d+)", re.IGNORECASE)

# Mocha: "  68 passing (1m)" — one per mocha run, summed
_MOCHA_PASSING = re.compile(r"^\s*(\d+)\s+passing\b", re.MULTILINE)

# Gradle summary, per test task, printed only when something failed:
# "37 tests completed, 2 failed" or "37 tests completed, 2 failed, 746 skipped"
_GRADLE_SUMMARY = re.compile(
    r"(\d+)\s+tests?\s+completed(?:,\s+(\d+)\s+failed)?(?:,\s+(\d+)\s+skipped)?",
)
# Gradle per-test: "MyTest > myMethod() PASSED" / "FAILED" / "SKIPPED"
_GRADLE_RESULT = re.compile(r"^\s*\S+.*\b(PASSED|FAILED|SKIPPED)\s*$", re.MULTILINE)

# dotnet test: "Passed!  - Failed:     0, Passed:     3, Skipped:     0, Total:     3"
_DOTNET_PASSED = re.compile(r"Passed:\s*(\d+)", re.IGNORECASE)

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


def _count_go_test_json(log: str) -> int | None:
    passed = 0
    saw_json = False
    for line in log.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        saw_json = True
        if event.get("Action") == "pass" and event.get("Test"):
            passed += 1
    return passed if saw_json else None


def _count_go_plain(log: str) -> int | None:
    """Fallback for `go test ./...`: count passing packages (not individual tests)."""
    if "=== RUN" in log or '"Action":"pass"' in log:
        return None
    packages = [line for line in log.splitlines() if re.match(r"^ok\s+\S", line.strip())]
    return len(packages) if packages else None


def _count_go(log: str) -> int | None:
    return _count_go_test_json(log) or _count_go_plain(log)


def _sum_matches(pattern: re.Pattern, log: str) -> int | None:
    matches = pattern.findall(log)
    return sum(int(m) for m in matches) if matches else None


def _count_jest(log: str) -> int | None:
    return _sum_matches(_JEST_PASSED, log)


def _count_pytest(log: str) -> int | None:
    passed = None
    for summary in _PYTEST_SUMMARY.findall(log):
        match = _PYTEST_PASSED.search(summary)
        passed = (passed or 0) + (int(match.group(1)) if match else 0)
    return passed


def _count_maven(log: str) -> int | None:
    """Passing tests (run - failures - errors - skipped) from surefire output.

    Surefire prints a line per test class (with "Time elapsed") and, under each
    module's "Results:" header, a summary line without it. Summing the summary
    lines covers every module without double-counting; per-class lines are the
    fallback when no summary is printed (`-q`).
    """
    summaries: list[re.Match] = []
    per_class: list[re.Match] = []
    for match in _MAVEN_SUMMARY.finditer(log):
        (per_class if match.group("per_class") else summaries).append(match)
    matches = summaries or per_class
    if not matches:
        return None
    return sum(
        max(int(m.group(1)) - int(m.group(2)) - int(m.group(3)) - int(m.group(4)), 0)
        for m in matches
    )


def _count_rspec(log: str) -> int | None:
    match = _RSPEC_SUMMARY.search(log)
    if not match:
        return None
    examples = int(match.group(1))
    failures = int(match.group(2))
    return max(examples - failures, 0)


def _count_phpunit(log: str) -> int | None:
    match = _PHPUNIT_OK.search(log)
    if match:
        return int(match.group(1))
    match = _PHPUNIT_TESTS.search(log)
    if not match:
        return None
    total = int(match.group(1))
    fail_match = _PHPUNIT_FAILURES.search(log)
    failures = int(fail_match.group(1)) if fail_match else 0
    return max(total - failures, 0)


def _count_mocha(log: str) -> int | None:
    return _sum_matches(_MOCHA_PASSING, log)


def _count_gradle(log: str) -> int | None:
    """Count Gradle test results.

    Prefers the summary lines ('37 tests completed, 2 failed, 3 skipped'),
    summed across test tasks. Falls back to per-test PASSED lines. Gradle
    prints neither for an all-green run without testLogging, so that is None
    (not measured), never a pass.

    Summary lines only appear for tasks with failures, so in a multi-module
    build with some green modules this undercounts; JUnit XML is the real source.
    """
    completed = failed = skipped = 0
    found_summary = False
    for m in _GRADLE_SUMMARY.finditer(log):
        found_summary = True
        completed += int(m.group(1))
        failed += int(m.group(2) or 0)
        skipped += int(m.group(3) or 0)
    if found_summary:
        return max(completed - failed - skipped, 0)

    per_test = _GRADLE_RESULT.findall(log)
    # Logging only SKIPPED events (rxjava does) says nothing about what passed.
    if not {"PASSED", "FAILED"} & set(per_test):
        return None
    return sum(1 for r in per_test if r == "PASSED")


def _count_dotnet(log: str) -> int | None:
    match = _DOTNET_PASSED.search(log)
    return int(match.group(1)) if match else None


_PARSERS: dict[TestFramework, Callable[[str], int | None]] = {
    TestFramework.jest: _count_jest,
    TestFramework.mocha: _count_mocha,
    TestFramework.pytest: _count_pytest,
    TestFramework.maven: _count_maven,
    TestFramework.gradle: _count_gradle,
    TestFramework.rspec: _count_rspec,
    TestFramework.go: _count_go,
    TestFramework.dotnet: _count_dotnet,
    TestFramework.phpunit: _count_phpunit,
}


def resolve_test_framework(
    test_cmd: str,
    *,
    test_framework: str = "",
    case_name: str = "",
) -> TestFramework | None:
    """Return the parser key for a case, inferring from ``test_cmd`` when needed."""
    if test_framework:
        fw = test_framework.strip().lower()
        try:
            return TestFramework(fw)
        except ValueError:
            supported = ", ".join(sorted(f.value for f in TestFramework))
            warnings.warn(
                f"eval case {case_name!r}: unknown test_framework {test_framework!r}; "
                f"supported: {supported}. "
                "Add a parser in harness/test_results.py.",
                stacklevel=2,
            )
            return None

    inferred = _infer_test_framework(test_cmd)
    if inferred is None:
        warnings.warn(
            f"eval case {case_name!r}: cannot infer test framework from "
            f"test_cmd {test_cmd!r}; set inputs.test_framework in cases.yaml "
            "and add a parser in harness/test_results.py.",
            stacklevel=2,
        )
    return inferred


def count_passed_tests(
    log: str,
    framework: TestFramework | None,
) -> int | None:
    """Return the number of tests reported as passed, or None if unparseable."""
    if not log.strip() or framework is None:
        return None
    parser = _PARSERS.get(framework)
    if parser is None:
        return None
    clean = _strip_ansi(log)
    return parser(clean)


def _infer_test_framework(test_cmd: str) -> TestFramework | None:
    cmd = test_cmd.strip().lower()
    if not cmd:
        return None
    if "phpunit" in cmd:
        return TestFramework.phpunit
    if cmd.startswith("dotnet test") or " dotnet test" in cmd:
        return TestFramework.dotnet
    if "go test" in cmd:
        return TestFramework.go
    if "gradlew" in cmd or cmd.startswith("gradle ") or " gradle " in cmd:
        return TestFramework.gradle
    if "mvnw" in cmd or cmd.startswith("mvn ") or " mvn " in cmd:
        return TestFramework.maven
    if "pytest" in cmd:
        return TestFramework.pytest
    if "rspec" in cmd:
        return TestFramework.rspec
    if "mocha" in cmd:
        return TestFramework.mocha
    if "jest" in cmd or cmd.startswith("npm test") or cmd == "npm test":
        return TestFramework.jest
    return None


# --------------------------------------------------------------------------
# test identities from machine-readable reports
# --------------------------------------------------------------------------

PASSED, FAILED, SKIPPED = "passed", "failed", "skipped"
_WORST = {PASSED: 0, SKIPPED: 1, FAILED: 2}
_JEST_STATUS = {"passed": PASSED, "failed": FAILED}  # pending/todo/skipped/disabled -> skipped
_PRUNE_DIRS = {"node_modules", ".git", ".gradle", ".venv", "venv", "__pycache__", ".m2"}

# Files that the container writes just before the test step, per phase suffix.
# Reports older than the newest of them are stale (agent runs, committed files).
_PRE_TEST_FILES = ("install-{s}.exit", "snyk-test-{s}.json", "snyk-test-{s}.txt",
                   "snyk-test-{s}.log", "build.exit")


def _is_build_report(path: Path) -> bool:
    """Surefire's target/surefire-reports/TEST-*.xml or Gradle's build/test-results/**/TEST-*.xml."""
    return path.name.startswith("TEST-") and path.suffix == ".xml" and (
        path.parent.name == "surefire-reports" or "test-results" in path.parts
    )


def _parse_junit_xml(path: Path) -> list[tuple[str, str]] | None:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return None
    out = []
    for case in root.iter("testcase"):
        tid = f"{case.get('classname', '')}#{case.get('name', '')}"
        tags = {child.tag for child in case}
        if tags & {"failure", "error"}:
            status = FAILED
        elif "skipped" in tags:
            status = SKIPPED
        else:
            status = PASSED
        out.append((tid, status))
    return out


def _parse_jest_json(path: Path) -> list[tuple[str, str]] | None:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict) or "testResults" not in data:
        return None
    out = []
    for suite in data["testResults"]:
        file = str(suite.get("name", ""))
        file = file.removeprefix("/app/")
        for a in suite.get("assertionResults", []):
            title = a.get("fullName") or " ".join([*a.get("ancestorTitles", []), a.get("title", "")])
            out.append((f"{file}#{title}", _JEST_STATUS.get(a.get("status"), SKIPPED)))
    return out


def report_window(out: Path, suffix: str) -> tuple[float | None, float | None]:
    """(since, until) mtimes bounding the reports the `suffix` test step can have written."""
    before = [
        (out / name.format(s=suffix)).stat().st_mtime
        for name in _PRE_TEST_FILES
        if (out / name.format(s=suffix)).exists()
    ]
    exit_file = out / f"test-{suffix}.exit"
    since = max(before) - 1 if before else None
    until = exit_file.stat().st_mtime + 2 if exit_file.exists() else None
    return since, until


def collect_test_results(
    work: Path,
    junit_dir: Path | None = None,
    *,
    since: float | None = None,
    until: float | None = None,
) -> dict[str, str] | None:
    """Per-test status keyed by ``classname#name``; None when no report was found.

    Reads surefire/Gradle XML anywhere under ``work`` and every XML/JSON file
    in ``junit_dir`` (pytest --junitxml, jest --json). Files outside the
    [since, until] mtime window are ignored. A test reported more than once
    keeps its worst status.
    """
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(work):
        dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS]
        files.extend(p for f in filenames if _is_build_report(p := Path(dirpath) / f))
    if junit_dir is not None and junit_dir.is_dir():
        files.extend(p for p in sorted(junit_dir.rglob("*")) if p.suffix in (".xml", ".json"))

    results: dict[str, str] = {}
    found = False
    for path in files:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if (since is not None and mtime < since) or (until is not None and mtime > until):
            continue
        parsed = _parse_jest_json(path) if path.suffix == ".json" else _parse_junit_xml(path)
        if parsed is None:
            continue
        found = True
        for tid, status in parsed:
            if _WORST[status] >= _WORST.get(results.get(tid, PASSED), 0):
                results[tid] = status
    return results if found else None


def passed_count(results: dict[str, str]) -> int:
    return sum(1 for status in results.values() if status == PASSED)


_DIGITS = re.compile(r"\d+")


def regressed_tests(before: dict[str, str], after: dict[str, str] | None) -> list[str]:
    """Tests that passed in the baseline but are failed, skipped or missing after."""
    after = after or {}
    lost = [t for t, s in before.items() if s == PASSED and after.get(t) != PASSED]
    # Fuzz tests put random numbers in their names (webpack's WasmHashes), so a
    # baseline test missing after can pass under a new name. Match those one for
    # one against new passing tests with the same name once digits are ignored.
    spare = Counter(_DIGITS.sub("#", t) for t, s in after.items() if s == PASSED and t not in before)
    regressed = []
    for t in lost:
        shape = _DIGITS.sub("#", t)
        if t not in after and spare[shape]:
            spare[shape] -= 1
        else:
            regressed.append(t)
    return sorted(regressed)


# Paths that hold tests, for flagging test-file edits in agent.diff.
_TEST_PATH = re.compile(
    r"(^|/)(src/test|tests?|__tests__)/"
    r"|\.(test|spec)\.[^/]+$"
    r"|(^|/)test_[^/]*\.py$"
    r"|_test\.py$"
)
_DIFF_HEADER = re.compile(r"^diff --git a/(.*?) b/(.*)$", re.MULTILINE)
# Dependency manifests under a test dir (e.g. tests/fixtures/*/poetry.lock) are
# scanned by --all-projects, so upgrading them is part of the fix, not a test edit.
_MANIFEST = re.compile(
    r"(^|/)(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json"
    r"|pom\.xml|build\.gradle(\.kts)?|gradle\.lockfile|pyproject\.toml|poetry\.lock"
    r"|requirements[^/]*\.txt|Pipfile(\.lock)?|setup\.py)$"
)


def modified_test_files(diff: str) -> list[str]:
    """Test source files touched by a `git diff` (added, removed, or edited)."""
    paths = set()
    for a, b in _DIFF_HEADER.findall(diff):
        paths.update(p for p in (a, b) if _TEST_PATH.search(p) and not _MANIFEST.search(p))
    return sorted(paths)

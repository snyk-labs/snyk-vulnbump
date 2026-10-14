"""Categorise why a fix broke the repo, from the harness's own logs.

Rule-based: the first gate that failed picks the log (install, build or
tests), lines already present in the baseline log are dropped, and the rest
are matched against CATEGORIES in priority order. The upgraded package the
errors point at is reported as the culprit.

    uv run python -m harness.failure_class ../reports/<run_id>/benchmark.json

backfills the categories into an existing report from data/scans/<run_id>/.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from .scans import SCANS_DIR, after_dir

OTHER = "other"

# Priority order: the first category with a matching line wins. Specific
# causes (timeout, conflict, toolchain) come before the generic compile and
# runtime symptoms they would otherwise also trigger. Matching ignores case,
# so all-caps error codes are wrapped in (?-i:\b...\b): otherwise ERESOLVE
# matches inside "TemplateResolver".
CATEGORIES: tuple[tuple[str, re.Pattern], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE)) for name, pattern in (
        ("timeout", r"\[harness\] \w+ exceeded \d+s"),
        ("dependency-conflict",
         r"Could not resolve dependencies|Could not find artifact|Could not resolve all "
         r"(files|dependencies)|(?-i:\bERESOLVE\b)|ResolutionImpossible|SolverProblemError|"
         r"version solving failed|No matching distribution found|No matching version found|"
         r"conflicting dependencies"),
        ("toolchain-version",
         r"class file has wrong version|compiled by a more recent version|Unsupported class file "
         r"major version|release version \d+ not supported|invalid target release|"
         r"(?-i:\bEBADENGINE\b)|engine \"node\" is incompatible|requires a different Python|"
         r"Requires-Python"),
        ("module-format",
         r"(?-i:\bERR_REQUIRE_ESM\b)|require\(\) of ES Module|"
         r"Cannot use import statement outside a module|(?-i:\bERR_PACKAGE_PATH_NOT_EXPORTED\b)"),
        ("binary-incompatibility",
         r"NoSuchMethodError|NoSuchFieldError|NoClassDefFoundError|ClassNotFoundException|"
         r"IncompatibleClassChangeError|AbstractMethodError|LinkageError"),
        ("removed-api",
         r"cannot find symbol|package \S+ does not exist|cannot import name|No module named|"
         r"ModuleNotFoundError|has no attribute|Cannot find module|is not exported|"
         r"error TS2305|error TS2307|error TS2339|Unresolved reference"),
        ("api-signature-change",
         r"incompatible types|cannot be applied to|no suitable (method|constructor)|does not "
         r"override|unexpected keyword argument|required positional argument|takes \d+ positional|"
         r"is not a function|error TS2345|error TS2554"),
        ("test-assertion",
         r"AssertionError|AssertionFailedError|ComparisonFailure|expected:?\s*<|Expected:|"
         r"^\s*expect\(|^FAILED \S+::"),
    )
)

_STAGE_LOG = {
    "deps": ("install-after.log", "install-before.log"),
    "build": ("build.log", "build.log"),
    "tests": ("test-after.log", "test-before.log"),
}
# /app/src/main/java/org/x/Foo.java:[10,23] -> Foo.java:[10,23]
_APP_PATH = re.compile(r"/app/(?:\S*/)?")


@dataclass(frozen=True)
class FailureClass:
    stage: str          # deps | build | tests
    category: str
    detail: str         # first matching log line, trimmed
    culprit: str = ""   # upgraded package the errors point at


def failed_stage(reasons: list[str]) -> str | None:
    """The first broken gate that has a log to read. Scan-only failures have none."""
    if "deps-unresolved" in reasons:
        return "deps"
    if "build-broken" in reasons:
        return "build"
    if "tests-regressed" in reasons or "tests-not-measured" in reasons:
        return "tests"
    return None


def _clean(line: str) -> str:
    line = re.sub(r"^\[(ERROR|WARNING|INFO)\]\s*", "", line.strip())
    return _APP_PATH.sub("", line)


def _new_lines(after: str, before: str) -> tuple[list[str], list[str]]:
    """(cleaned, raw) lines of `after` that the baseline log does not have."""
    seen = {_clean(l) for l in before.splitlines()}
    pairs = [(_clean(l), l) for l in after.splitlines()]
    kept = [(c, l) for c, l in pairs if c and c not in seen]
    return [c for c, _ in kept], [l for _, l in kept]


def _dep_keys(name: str) -> list[str]:
    """Strings an error would mention for this package, most specific first."""
    if ":" in name:                     # maven group:artifact
        group, artifact = name.split(":", 1)
        return [artifact, group]
    return [name, name.replace("-", "_")] if "-" in name else [name]


def _culprit(lines: list[str], deps_changed: list[dict]) -> str:
    text = "\n".join(lines).lower()
    hits = Counter()
    for d in deps_changed:
        if d.get("before") == d.get("after"):
            continue
        for key in _dep_keys(d["name"]):
            if len(key) > 2 and key.lower() in text:
                hits[d["name"]] = text.count(key.lower())
                break
    return hits.most_common(1)[0][0] if hits else ""


def classify(stage: str, log_after: str, log_before: str = "",
             deps_changed: list[dict] | None = None) -> FailureClass:
    lines, raw = _new_lines(log_after, log_before)
    # Raw lines keep paths such as node_modules/<pkg>/, which name the package.
    culprit = _culprit(raw, deps_changed or [])
    for category, pattern in CATEGORIES:
        for i, line in enumerate(lines):
            if pattern.search(line):
                # javac names the missing symbol on the next line.
                if i + 1 < len(lines) and lines[i + 1].startswith("symbol:"):
                    line = f"{line} ({lines[i + 1]})"
                return FailureClass(stage, category, re.sub(r"\s+", " ", line)[:200], culprit)
    return FailureClass(stage, OTHER, "", culprit)


def classify_dirs(reasons: list[str], timed_out: bool, after_path: Path, before_dir: Path,
                  deps_changed: list[dict], turn_capped: bool = False) -> FailureClass | None:
    stage = failed_stage(reasons)
    if timed_out:
        # The container was killed mid-step, so its logs just stop.
        return FailureClass(stage or "agent", "timeout", "attempt hit its budget and was killed")
    if turn_capped:
        # Stopped mid-work too, so whatever the logs show is unfinished.
        return FailureClass(stage or "agent", "turn-cap", "agent hit its turn budget")
    if stage is None:
        return None
    after_name, before_name = _STAGE_LOG[stage]

    def read(p: Path) -> str:
        try:
            return p.read_text(errors="replace")
        except OSError:
            return ""

    return classify(stage, read(after_path / after_name), read(before_dir / before_name),
                    deps_changed)


def backfill(report_path: Path) -> None:
    """Add failure categories to an existing report from its preserved logs."""
    report = json.loads(report_path.read_text())
    run_dir = SCANS_DIR / report_path.parent.name
    for name, case in report.get("cases", {}).items():
        for a in case.get("attempts", []):
            if a.get("verified"):
                continue
            label = "" if a.get("group_index") is None else a["label"]
            after = after_dir(run_dir / name, a["agent"], label)
            fc = classify_dirs(a.get("reasons") or [], a.get("timed_out", False),
                               after, run_dir / name / "before", a.get("deps_changed") or [],
                               turn_capped=a.get("turn_capped", False))
            a["failure"] = asdict(fc) if fc else None
            print(f"{name}: {a['failure']}")
    report_path.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(prog="harness.failure_class")
    p.add_argument("report", type=Path)
    backfill(p.parse_args().report)

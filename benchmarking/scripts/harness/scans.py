"""Persist snyk scan JSON artifacts across runs."""

from __future__ import annotations

import re
import shutil
from datetime import datetime, timezone
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parents[2]
SCANS_DIR = BENCHMARK_DIR / "data" / "scans"

# Kept next to the post-fix scan: Evo's own per-group record, the agent log,
# and the build/test logs behind the verdict.
_BEFORE_EXTRAS = ("snyk-test-before.txt", "install-before.log", "build.log", "test-before.log")
_AFTER_EXTRAS = ("snyk-test-after.txt", "snyk-test-after-wrapper.txt", "snyk-test-after-wrapper.log",
                 "fix-report.json", "agent-debug.log", "agent.log",
                 "agent.diff", "prompt.txt", "install-after.log", "build.log", "test-after.log")


def generate_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_segment(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9._@-]+", "_", label).strip("_")


def after_dir(case_dir: Path, agent: str, label: str = "") -> Path:
    """A case's after/<agent>[-<group>] dir, as preserve_scan writes it."""
    return case_dir / "after" / _safe_segment(f"{agent}-{label}" if label else agent)


def preserve_scan(
    run_id: str,
    case_name: str,
    out_dir: Path,
    *,
    phase: str = "before",
    agent: str = "",
    group_label: str = "",
) -> None:
    """Copy scan artefacts from out_dir to persistent storage.

    Layout:
        data/scans/<run_id>/<case>/before/{snyk-test-before.{json,txt},install-before.log,build.log,test-before.log}
        data/scans/<run_id>/<case>/after/<agent>[-<group>]/{snyk-test-after.{json,txt},
            snyk-test-after-wrapper.{txt,log},fix-report.json,
            agent-debug.log,agent.log,agent.diff,prompt.txt,install-after.log,build.log,test-after.log}
    """
    case_dir = SCANS_DIR / run_id / case_name
    if phase == "before":
        names = ("snyk-test-before.json", *_BEFORE_EXTRAS)
        dest_dir = case_dir / "before"
    else:
        names = ("snyk-test-after.json", *_AFTER_EXTRAS)
        suffix = _safe_segment(f"{agent}-{group_label}" if group_label else agent)
        dest_dir = case_dir / "after" / suffix if suffix else case_dir / "after"

    for name in names:
        src = out_dir / name
        if src.exists():
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest_dir / name)

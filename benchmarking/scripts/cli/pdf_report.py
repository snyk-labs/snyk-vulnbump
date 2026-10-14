"""Render a benchmark JSON report as a multi-page PDF.

    uv run python -m cli.pdf_report ../reports/<run_id>/benchmark.json

Pages: overview with KPI cards, failure reasons, per-repo results, token usage
and cost, token distribution, latency. Ecosystems come from cases.yaml metadata.
"""

from __future__ import annotations

import argparse
import math
import textwrap
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
matplotlib.rcParams["text.parse_math"] = False

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import yaml  # noqa: E402
from matplotlib.axes import Axes  # noqa: E402
from matplotlib.backends.backend_pdf import PdfPages  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import PathPatch, Rectangle  # noqa: E402
from matplotlib.path import Path as MplPath  # noqa: E402

from harness.agents import (  # noqa: E402
    CLAUDE_DEFAULT_MAX_TURNS,
    EVO_AGENTS,
    HARNESS_CLAUDE_SNYK,
    HARNESS_CLAUDE_UNAIDED,
    HARNESS_EVO,
    HARNESS_MODE_FOR,
    HARNESS_PM_BUMP,
    HARNESS_PM_BUMP_MIN,
    MODE_SINGLE_UPGRADE,
    MODES,
    PM_BUMP_AGENTS,
    parse_vuln_breakability,
)
from harness.scans import SCANS_DIR, after_dir  # noqa: E402
from harness.snyk import load_json, vuln_facts  # noqa: E402

from .report import (  # noqa: E402
    SEVERITIES,
    attempt_baseline_valid,
    cluster_stats,
    fixable_counts,
    is_harness_error,
    remaining_counts,
    rescan_failed,
)

CASES_YAML = Path(__file__).resolve().parents[2] / "cases" / "cases.yaml"

_KPI_NOTES = (
    "Fixable baseline vulns gone in the harness rescan",
    "Deps resolve, snyk test OK, vulns cleared, repo builds, baseline-passing tests still pass",
    "Baseline-passing tests still pass (per test where reported, else count)",
    "",
    "Median latency per repo run",
)

_MODE_DESC = {
    MODE_SINGLE_UPGRADE: "single-upgrade (one package upgrade per attempt)",
}
_HARNESS_NAMES = {
    HARNESS_EVO: "Evo Remediation Agent",
    HARNESS_CLAUDE_SNYK: "Claude Code + Snyk scan",
    HARNESS_CLAUDE_UNAIDED: "Claude Code unaided",
    HARNESS_PM_BUMP: "Package manager bump",
    HARNESS_PM_BUMP_MIN: "Package manager bump (min pin)",
}


def _harness_mode(agent: str) -> tuple[str, str | None]:
    harness, mode = HARNESS_MODE_FOR.get(agent, (agent, None))
    return _HARNESS_NAMES.get(harness, harness), mode


def agent_display(agent: str) -> str:
    harness, mode = _harness_mode(agent)
    return f"{harness} ({mode})" if mode else harness

_PAGE = (11, 8.5)  # landscape letter
_BAR = "#4c78a8"
_ACCENT = "#f58518"
_HEADER_BG = "#3b5b7a"
_ZEBRA_BG = "#eef3f8"
_GRID = "#cbd5e1"
_TOTAL_BG = "#d5dfea"
_ROWS_PER_PAGE = 24

_NUMERIC_CELL_RE = re.compile(r"^\$?-?[\d,]+(\.\d+)?[%sk]?$")


# --- data --------------------------------------------------------------------

def _ecosystems(cases_yaml: Path) -> dict[str, str]:
    if not cases_yaml.exists():
        return {}
    data = yaml.safe_load(cases_yaml.read_text())
    return {
        c["name"]: (c.get("metadata") or {}).get("ecosystem", "unknown")
        for c in data.get("cases", [])
    }


def _attempts(report: dict, ecosystems: dict[str, str]) -> list[dict]:
    """Attempts graded against a valid baseline (their own repeat's)."""
    rows = []
    for name, case in sorted(report.get("cases", {}).items()):
        for a in case.get("attempts", []):
            if not attempt_baseline_valid(case, a):
                continue
            rows.append({**a, "case": name, "ecosystem": ecosystems.get(name, "unknown")})
    return rows


def _green(a: dict) -> bool:
    return (a.get("deps_ok") is not False and a.get("build_ok") is not False
            and a.get("tests_ok") is True and a.get("boots") is not False)


def _rate(num: int, den: int) -> float | None:
    return round(num / den * 100, 1) if den else None


def _sum_sev(attempts: list[dict], key: str) -> dict[str, int]:
    out: Counter = Counter()
    for a in attempts:
        out.update(a.get(key) or {})
    return dict(out)


def _vuln_facts(report: dict, case: str, repeat: int | None) -> list[dict]:
    entry = report["cases"][case]
    baselines = entry.get("baselines") or [entry["baseline"]]
    b = baselines[repeat] if repeat is not None and repeat < len(baselines) else entry["baseline"]
    return b.get("vuln_facts") or []


def _stats(all_attempts: list[dict], report: dict) -> dict:
    # Harness errors say nothing about the agent: counted, but out of every rate.
    attempts = [a for a in all_attempts if not is_harness_error(a)]
    by_run: dict[tuple, list[dict]] = {}
    for a in attempts:
        by_run.setdefault((a["case"], a.get("repeat"), a["agent"]), []).append(a)
    cleared = fixable = remaining_unverified = 0
    remaining: Counter = Counter()
    per_repo_pass: dict[str, tuple[int, int]] = {}
    for (case, repeat, _), run in by_run.items():
        fx, cl = fixable_counts(run)
        fixable += fx
        cleared += cl
        rem, unverified = remaining_counts(run, _vuln_facts(report, case, repeat))
        remaining.update(rem)
        remaining_unverified += unverified
        v, d = per_repo_pass.get(case, (0, 0))
        per_repo_pass[case] = (v + sum(1 for a in run if a.get("verified")), d + len(run))
    macro, ci = cluster_stats(per_repo_pass)
    n = len(attempts)
    return {
        "cases": len({a["case"] for a in attempts}),
        "attempts": n,
        "harness_errors": len(all_attempts) - n,
        "tests_modified": sum(1 for a in attempts if a.get("tests_modified")),
        "policy_modified": sum(1 for a in attempts if a.get("snyk_policy_modified")),
        "unrelated_bumps": sum(1 for a in attempts if a.get("unexpected_collateral")),
        "macro_rate": None if macro is None else round(macro * 100, 1),
        "rate_ci": None if ci is None else [round(x * 100, 1) for x in ci],
        "cleared": cleared,
        "fixable": fixable,
        "cleared_rate": _rate(cleared, fixable),
        "verified": sum(1 for a in attempts if a.get("verified")),
        "verified_rate": _rate(sum(1 for a in attempts if a.get("verified")), n),
        "deps_rate": _rate(sum(1 for a in attempts if a.get("deps_ok") is not False), n),
        "build_rate": _rate(sum(1 for a in attempts if a.get("build_ok") is not False), n),
        "tests_rate": _rate(sum(1 for a in attempts if a.get("tests_ok") is True), n),
        "green_rate": _rate(sum(1 for a in attempts if _green(a)), n),
        "new": sum(a.get("introduced_count") or 0 for a in attempts),
        "new_sev": _sum_sev(attempts, "introduced_by_severity"),
        "remaining_sev": dict(remaining),
        "remaining_unverified": remaining_unverified,
        "rescans_failed": sum(1 for a in attempts if rescan_failed(a)),
        "new_projects": sum(1 for a in attempts if a.get("new_projects")),
        "claimed_not_fixed": sum(1 for a in attempts if a.get("claimed_not_fixed")),
        "timed_out": sum(1 for a in attempts if a.get("timed_out")),
        "turn_capped": sum(1 for a in attempts if a.get("turn_capped")),
        "input_tokens": sum(a.get("input_tokens") or 0 for a in attempts),
        "output_tokens": sum(a.get("output_tokens") or 0 for a in attempts),
        "cost": sum(a.get("cost_usd") or 0.0 for a in attempts),
        "latencies": [a["latency_s"] for a in attempts if a.get("latency_s") is not None],
    }


def _percentiles(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p90": None, "p95": None}
    return {f"p{q}": round(float(np.percentile(values, q)), 2) for q in (50, 90, 95)}


def _verdict(a: dict) -> str:
    if is_harness_error(a):
        return "HARNESS_ERROR"
    if a.get("verified"):
        return "PASS"
    if a.get("timed_out"):
        return "TIME_OUT"
    return "TURN_CAP" if a.get("turn_capped") else "FAIL"


# --- formatting --------------------------------------------------------------

def _fmt(value: object) -> str:
    return "-" if value is None else str(value)


def _fmt_int(value: int | None) -> str:
    return "-" if value is None else f"{value:,}"


def _fmt_pct(value: float | None) -> str:
    return "-" if value is None else f"{value}%"


def _fmt_macro(s: dict) -> str:
    if s["macro_rate"] is None:
        return "-"
    ci = s["rate_ci"]
    return f"{s['macro_rate']:.0f}%" + (f" [{ci[0]:.0f}-{ci[1]:.0f}]" if ci else "")


def _is_claude(agent: str) -> bool:
    # Same split the harness prices by: every agent but Evo and the package manager bump runs Claude Code.
    return agent not in EVO_AGENTS and agent not in PM_BUMP_AGENTS


def _fmt_sev(counts: dict[str, int]) -> str:
    return "/".join(str(counts.get(s, 0)) for s in SEVERITIES)


def _fmt_ok(value: bool | None) -> str:
    return "n/a" if value is None else ("OK" if value else "FAIL")


def _fmt_tests(a: dict) -> str:
    before, after = a.get("tests_passed_count_before"), a.get("tests_passed_count_after")
    if before is None and after is None:
        return "n/a"
    if after is None and a.get("build_ok") is False:
        return "build failed"
    return f"{_fmt(after)}/{_fmt(before)}"


def _fmt_num(value: float) -> str:
    return f"{value:,.0f}" if abs(value) >= 100 else f"{value:.3g}"


def _numeric_columns(rows: list[list]) -> set[int]:
    if not rows:
        return set()
    numeric: set[int] = set()
    for col in range(len(rows[0])):
        cells = [str(row[col]).strip() for row in rows]
        real = [c for c in cells if c not in ("", "-", "n/a")]
        if real and all(_NUMERIC_CELL_RE.match(c) for c in real):
            numeric.add(col)
    return numeric


# --- drawing -----------------------------------------------------------------

def _table(ax: Axes, title: str, col_labels: list[str], rows: list[list],
           fontsize: float = 8, row_scale: float = 1.5,
           fit_height: bool = False):
    ax.axis("off")
    if title:
        ax.set_title(title, fontsize=11, fontweight="bold", loc="left")
    if not rows:
        ax.text(0.0, 0.85, "No data", fontsize=9, va="top")
        return
    numeric_cols = _numeric_columns(rows)
    total_rows = [i for i, r in enumerate(rows, start=1) if len(r) > 1 and r[1] == "All"]
    table = ax.table(
        cellText=[[str(c) for c in row] for row in rows],
        colLabels=col_labels,
        loc="upper left",
        cellLoc="left",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(fontsize)
    table.scale(1, row_scale)
    table.auto_set_column_width(col=list(range(len(col_labels))))
    for row, cells in enumerate(rows, start=1):
        extra = max(str(c).count("\n") for c in cells)
        if extra:
            for col in range(len(col_labels)):
                cell = table[row, col]
                cell.set_height(cell.get_height() * (1 + 0.75 * extra))
    for col in range(len(col_labels)):
        align = "right" if col in numeric_cols else "left"
        header = table[0, col]
        header.set_facecolor(_HEADER_BG)
        header.set_edgecolor(_GRID)
        header.set_text_props(fontweight="bold", color="white", ha=align)
        for row in range(1, len(rows) + 1):
            cell = table[row, col]
            cell.set_edgecolor(_GRID)
            cell.set_facecolor(_ZEBRA_BG if row % 2 == 0 else "white")
            cell.set_text_props(ha=align)
            if row in total_rows:
                cell.set_facecolor(_TOTAL_BG)
                cell.set_text_props(fontweight="bold")
    # Shrink font (and rows, if fit_height) until the table fits inside its axes.
    renderer = ax.figure.canvas.get_renderer()
    box = ax.get_window_extent(renderer)
    for _ in range(10):
        tb = table.get_window_extent(renderer)
        factor = box.width / tb.width
        if fit_height:
            factor = min(factor, (tb.y1 - box.y0) / tb.height)
        if factor >= 1:
            break
        # Half-point steps: frozen widths measured at odd sizes clip text in the PDF.
        fontsize = math.floor(fontsize * max(factor, 0.8) * 2) / 2
        table.set_fontsize(fontsize)
        if fit_height:
            table.scale(1, max(factor, 0.8))
    # The "All" ecosystem row aggregates the rows above it: set it off with a
    # heavy rule. Cell positions are only known once the table is laid out.
    if total_rows:
        table._update_positions(ax.figure.canvas.get_renderer())
        table._autoColumns = []  # keep these widths at save time, so the rule fits
        last = len(col_labels) - 1
        for row in total_rows:
            first, end = table[row, 0], table[row, last]
            y = first.get_y() + first.get_height()
            ax.add_line(Line2D([first.get_x(), end.get_x() + end.get_width()], [y, y],
                               transform=ax.transAxes, color=_HEADER_BG, linewidth=2,
                               clip_on=False))
    return table


def _hist(ax: Axes, data: list[float], title: str, xlabel: str) -> None:
    ax.set_title(title, fontsize=10)
    if not data:
        ax.text(0.5, 0.5, "No data", ha="center", va="center")
        ax.axis("off")
        return
    bins = min(20, max(5, len(set(data))))
    ax.hist(data, bins=bins, color=_BAR, edgecolor="white")
    ax.set_xlabel(xlabel)
    ax.set_ylabel("count")
    markers = (
        ("p50", float(np.percentile(data, 50)), "#2f6f4f", "-"),
        ("p90", float(np.percentile(data, 90)), "#a15c00", "--"),
        ("p95", float(np.percentile(data, 95)), "#8b2f2f", "--"),
        ("mean", float(np.mean(data)), "#444444", ":"),
    )
    for label, value, color, style in markers:
        ax.axvline(value, color=color, linestyle=style, linewidth=1.2, label=f"{label} {_fmt_num(value)}")
    ax.legend(fontsize=6, loc="upper right")


def _card(fig: Figure, rect: tuple, label: str, value: str) -> None:
    ax = fig.add_axes(rect)
    ax.axis("off")
    ax.add_patch(Rectangle((0, 0), 1, 1, transform=ax.transAxes,
                           facecolor=_ZEBRA_BG, edgecolor=_GRID))
    ax.text(0.5, 0.62, value, ha="center", va="center", fontsize=15,
            fontweight="bold", color=_HEADER_BG)
    ax.text(0.5, 0.22, label, ha="center", va="center", fontsize=8, color="#555555")


def _footer(fig: Figure, page_num: int, total_pages: int, timestamp: str) -> None:
    fig.text(0.04, 0.02, f"Generated {timestamp}", fontsize=7, color="#888888", ha="left")
    fig.text(0.96, 0.02, f"Page {page_num}/{total_pages}", fontsize=7,
             color="#888888", ha="right")


def _page(title: str) -> Figure:
    fig = plt.figure(figsize=_PAGE)
    fig.suptitle(title, fontsize=14, fontweight="bold", x=0.04, y=0.94, ha="left")
    return fig


def _harness_hashes(ctx: dict) -> str:
    """Evo's commit comes from the snyk binary version; Claude Code only has a release version."""
    report = ctx["report"]
    version = (report.get("cli") or {}).get("snyk_version") or ""
    tail = version.rsplit(".", 1)[-1]
    evo = tail[:7] if len(tail) >= 7 and all(c in "0123456789abcdef" for c in tail) else version
    control = (report.get("fairness") or {}).get("control") or "n/a"
    names = list(dict.fromkeys(_harness_mode(a)[0] for a in ctx["agents"]))
    hashes = {n: (evo or "n/a") if n == _HARNESS_NAMES[HARNESS_EVO] else control for n in names}
    if len(names) == 1:
        return hashes[names[0]]
    return ", ".join(f"{n} {hashes[n]}" for n in names) or "n/a"


def _turns(ctx: dict) -> str:
    f = ctx["report"].get("fairness") or {}
    if f.get("turn_budget"):
        return f["turn_budget"]
    n = f.get("agent_max_iterations") or 0
    return str(n) if n else f"Evo default (100 + 10), Claude {CLAUDE_DEFAULT_MAX_TURNS}"


def _timeouts(ctx: dict) -> str:
    budgets = [a["budget_s"] for a in ctx["attempts"] if a.get("budget_s")]
    if not budgets:
        return "n/a"
    lo, hi = min(budgets), max(budgets)
    return f"{lo / 60:.0f} min" if lo == hi else f"{lo / 60:.0f}-{hi / 60:.0f} min"


# No reds or greens: those mean pass/fail in the funnel.
_ECO_COLORS = {"maven": "#7b2cbf", "gradle": "#3a86ff", "npm": "#4cc9f0", "yarn": "#264653",
               "pip": "#e9c46a", "poetry": "#8d6e63"}
_FLOW_PASS = "#2ecc71"
_FLOW_DROP = "#e63946"
_FUNNEL = (
    ("INSTALL", "Deps resolve", "Deps fail", lambda a: a.get("deps_ok") is not False),
    ("SNYK TEST", "All vulns cleared", "Vulns remain",
     lambda a: a.get("fixable_cleared") == a.get("fixable_total")),
    ("BUILD", "Build pass", "Build fail", lambda a: a.get("build_ok") is not False),
    ("TEST", "Tests pass", "Tests fail", lambda a: a.get("tests_ok") is True),
)


def _sankey(ax: Axes, attempts: list[dict]) -> None:
    """Attempts per ecosystem flowing through the verification gates; each drops at its first failed gate."""
    ax.axis("off")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ecos = Counter(a["ecosystem"] for a in attempts)
    # columns[i] = [(key, label, value, color)], links = (src_key, dst_key, value, color)
    columns = [[(f"eco:{e}", e, n, _ECO_COLORS.get(e, _BAR)) for e, n in ecos.most_common()]]
    links = []
    alive = attempts
    for i, (_, ok_label, fail_label, gate) in enumerate(_FUNNEL):
        ok = [a for a in alive if gate(a)]
        fail = len(alive) - len(ok)
        ok_key, fail_key = f"ok{i}", f"fail{i}"
        col = [(ok_key, ok_label, len(ok), _FLOW_PASS)]
        if fail:
            col.append((fail_key, fail_label, fail, _FLOW_DROP))
        columns.append(col)
        if i == 0:
            for e, _ in ecos.most_common():
                mine = [a for a in alive if a["ecosystem"] == e]
                n_ok = sum(1 for a in mine if gate(a))
                links += [(f"eco:{e}", ok_key, n_ok, _ECO_COLORS.get(e, _BAR)),
                          (f"eco:{e}", fail_key, len(mine) - n_ok, _FLOW_DROP)]
        else:
            links += [(f"ok{i - 1}", ok_key, len(ok), _FLOW_PASS),
                      (f"ok{i - 1}", fail_key, fail, _FLOW_DROP)]
        alive = ok
    total = len(attempts) or 1
    pad, node_w, min_h = 0.04, 0.012, 0.035
    # Largest scale at which every column, min heights included, fits in the axes.
    scale = 1 / total
    for _ in range(20):
        worst = max(sum(max(v * scale, min_h) for *_, v, _ in c) + pad * (len(c) - 1)
                    for c in columns)
        if worst <= 1:
            break
        scale *= 0.97
    pos = {}  # key -> [x, y_top, height, out_offset, in_offset]
    stages = ["ECOSYSTEM"] + [stage for stage, *_ in _FUNNEL]
    for ci, col in enumerate(columns):
        x = ci / (len(columns) - 1) * 0.87  # right margin for the last column's labels
        ax.text(x, 1.03, stages[ci], ha="left", va="bottom", fontsize=8, fontweight="bold",
                color="#6c757d")
        y = 1.0
        for key, label, value, color in col:
            h = max(value * scale, min_h)
            pos[key] = [x, y, h, 0.0, 0.0]
            ax.add_patch(Rectangle((x, y - h), node_w, h, facecolor=color, edgecolor="none",
                                   alpha=0.9))
            ax.text(x + node_w + 0.006, y - h / 2, f"{label}  {value}", ha="left", va="center",
                    fontsize=9, color="#1a1a2e", zorder=3)
            y -= h + pad
    for src, dst, value, color in links:
        if not value:
            continue
        s, d = pos[src], pos[dst]
        # Scale each band to its node so min-height nodes stay filled.
        hs = value / sum(v for a, _, v, _ in links if a == src) * s[2]
        hd = value / sum(v for _, b, v, _ in links if b == dst) * d[2]
        x0, x1 = s[0] + node_w, d[0]
        y0, y1 = s[1] - s[3], d[1] - d[4]
        xm = (x0 + x1) / 2
        verts = [(x0, y0), (xm, y0), (xm, y1), (x1, y1), (x1, y1 - hd),
                 (xm, y1 - hd), (xm, y0 - hs), (x0, y0 - hs), (x0, y0)]
        codes = [MplPath.MOVETO, MplPath.CURVE4, MplPath.CURVE4, MplPath.CURVE4, MplPath.LINETO,
                 MplPath.CURVE4, MplPath.CURVE4, MplPath.CURVE4, MplPath.CLOSEPOLY]
        ax.add_patch(PathPatch(MplPath(verts, codes), facecolor=color, edgecolor="none",
                               alpha=0.25))
        s[3] += hs
        d[4] += hd



# --- pages -------------------------------------------------------------------

def _page_overview(ctx: dict) -> Figure:
    fig = plt.figure(figsize=_PAGE)
    harnesses = ", ".join(dict.fromkeys(h for h, _ in map(_harness_mode, ctx["agents"])))
    modes = ", ".join(dict.fromkeys(m for _, m in map(_harness_mode, ctx["agents"]) if m))
    title = f"Benchmarking report: harness {harnesses}" + (f", {modes} mode" if modes else "")
    fig.suptitle(title, fontsize=16, fontweight="bold", x=0.04, ha="left")
    llm = ctx["report"].get("llm", {})
    model_meta = "\n".join([
        f"Model: {llm.get('model') or 'n/a'}",
        f"Provider: {llm.get('provider') or 'n/a'}",
        f"Harness: {', '.join(dict.fromkeys(_harness_mode(a)[0] for a in ctx['agents'])) or 'n/a'}",
        f"Mode: {', '.join(_MODE_DESC.get(m, m) for m in dict.fromkeys(_harness_mode(a)[1] for a in ctx['agents']) if m) or 'n/a'}",
    ])
    run_meta = "\n".join([
        f"Repos: {len(ctx['report'].get('cases', {}))}",
        f"Attempts: {len(ctx['attempts'])}",
        f"Harness git hash: {_harness_hashes(ctx)}",
        f"Timeout per repo: {_timeouts(ctx)}  |  turns: {_turns(ctx)}",
        f"Run: {ctx['report'].get('generated_at', '')[:19]}",
    ])
    fig.text(0.04, 0.92, model_meta, fontsize=8, va="top")
    fig.add_artist(Line2D([0.04, 0.28], [0.853, 0.853], color=_GRID, linewidth=1))
    fig.text(0.04, 0.843, run_meta, fontsize=8, va="top")
    fig.add_artist(Line2D([0.04, 0.28], [0.758, 0.758], color=_GRID, linewidth=1))

    # One band of KPI cards per agent.
    top = 0.74
    band_h, gap = 0.11, 0.02
    for agent in ctx["agents"]:
        s = ctx["by_agent"][agent]
        p50 = _percentiles(s["latencies"])["p50"]
        cards = [
            ("Vulns cleared", _fmt_pct(s["cleared_rate"])),
            ("Pass rate", _fmt_pct(s["verified_rate"])),
            ("Tests pass rate", _fmt_pct(s["tests_rate"])),
            ("Cost / run", f"${s['cost'] / s['attempts']:,.2f}" if s["attempts"] else "-"),
            ("p50 latency", f"{p50:.0f}s" if p50 is not None else "-"),
        ]
        bottom = top - band_h
        if len(ctx["agents"]) > 1:
            fig.text(0.04, top + 0.005, agent_display(agent), fontsize=9, fontweight="bold")
        width, card_gap = 0.174, 0.016
        for i, (label, value) in enumerate(cards):
            _card(fig, (0.04 + i * (width + card_gap), bottom, width, band_h - 0.01), label, value)
        top = bottom - gap - (0.02 if len(ctx["agents"]) > 1 else 0)
    for i, note in enumerate(_KPI_NOTES):
        fig.text(0.04 + i * (width + card_gap), top + gap - 0.005, textwrap.fill(note, 36),
                 fontsize=7, color="#555555", va="top")
    top -= 0.04

    if _has_sankey(ctx):
        # The funnel takes the rest of the page; the tables move to _page_performance.
        fig.text(0.04, top - 0.01, "Upgrades through the verification gates", fontsize=11,
                 fontweight="bold", va="top")
        _sankey(fig.add_axes((0.04, 0.08, 0.92, top - 0.16)),
                [a for a in ctx["attempts"] if not is_harness_error(a)])
    else:
        _performance_tables(fig, ctx, top - 0.02, "1. Performance")
    return fig


def _has_sankey(ctx: dict) -> bool:
    return len(ctx["agents"]) == 1 and _harness_mode(ctx["agents"][0])[1] in MODES


def _page_performance(ctx: dict) -> Figure:
    fig = _page("1. Performance")
    _performance_tables(fig, ctx, 0.86, "")
    return fig


def _performance_tables(fig: Figure, ctx: dict, perf_top: float, title: str) -> None:
    perf_rows, qual_rows = [], []
    for agent in ctx["agents"]:
        for eco, s in ctx["by_agent_eco"][agent]:
            perf_rows.append([
                agent_display(agent), eco, s["cases"], _fmt_pct(s["deps_rate"]),
                f"{s['cleared']}/{s['fixable']}", _fmt_pct(s["cleared_rate"]),
                _fmt_pct(s["build_rate"]), _fmt_pct(s["tests_rate"]),
                s["verified"], _fmt_pct(s["verified_rate"]), _fmt_macro(s),
            ])
            qual_rows.append([
                agent_display(agent), eco, s["new"], _fmt_sev(s["new_sev"]),
                _fmt_sev(s["remaining_sev"]), s["remaining_unverified"], s["rescans_failed"],
                s["new_projects"], s["claimed_not_fixed"], s["timed_out"], s["turn_capped"],
                s["tests_modified"], s["policy_modified"], s["unrelated_bumps"],
                s["harness_errors"],
            ])

    perf = _table(
        fig.add_axes((0.04, perf_top - 0.22, 0.92, 0.22)),
        title,
        ["Harness", "Ecosystem", "# repos", "Deps resolve rate", "Vulns cleared / fixable",
         "Vuln fix rate", "Build pass rate", "Tests pass rate", "# repos pass", "Pass rate",
         "Macro [95% CI]"],
        perf_rows,
        fontsize=7,
        row_scale=1.2,
    )
    # Place the quality table under the performance table's rendered extent.
    qual_top = perf_top - 0.06
    if perf is not None:
        perf_bbox = perf.get_window_extent(fig.canvas.get_renderer())
        qual_top = perf_bbox.transformed(fig.transFigure.inverted()).y0 - 0.06
    _table(
        fig.add_axes((0.04, qual_top - 0.22, 0.92, 0.22)),
        "Quality metrics (severity columns are crit/high/med/low; remaining = fixable not "
        "cleared, failed rescans included; new is unknown for failed rescans)",
        ["Harness", "Ecosystem", "New vulns", "New by severity",
         "Remaining by severity", "Remaining, rescan failed", "Rescan failed",
         "New projects", "Claimed not fixed", "Timed out", "Turn-capped", "Tests modified",
         ".snyk modified", "Unrelated bumps", "Harness errors"],
        qual_rows,
        fontsize=7,
        row_scale=1.2,
    )


_BREAKDOWNS = (
    ("Ecosystem", "ecosystem", None),
    ("Severity", "severity", ("critical", "high", "medium", "low")),
    ("Fix difficulty (upgrade size)", "difficulty", ("patch", "minor", "major")),
    ("Direct vs transitive", "dependency", ("direct", "transitive")),
    ("Breakability (Evo's risk assessment)", "breakability", ("low", "medium", "high")),
)
_NOT_ASSESSED = "not assessed"


def _scan_dir(ctx: dict, case: str, repeat: int | None) -> Path:
    entry = ctx["report"]["cases"][case]
    repeats = len(entry.get("baselines") or [entry["baseline"]])
    return SCANS_DIR / ctx["run_id"] / (case if repeats < 2 else f"{case}/repeat-{(repeat or 0) + 1}")


def _baseline_facts(ctx: dict, case: str, repeat: int | None) -> dict[tuple, dict]:
    facts = _vuln_facts(ctx["report"], case, repeat)
    if not facts:
        # Reports from before vuln_facts: read the preserved baseline scan.
        facts = vuln_facts(load_json(_scan_dir(ctx, case, repeat) / "before" / "snyk-test-before.json"))
    return {(f["manifest"], f["id"]): f for f in facts}


def _attempt_breakability(ctx: dict, a: dict) -> list[dict]:
    if a.get("vuln_breakability") or a["agent"] not in EVO_AGENTS:
        return a.get("vuln_breakability") or []
    # Reports from before vuln_breakability: read the preserved fix report.
    label = "" if a.get("group_index") is None else a["label"]
    return parse_vuln_breakability(load_json(
        after_dir(_scan_dir(ctx, a["case"], a.get("repeat")), a["agent"], label) / "fix-report.json"))


def _risk_for(entries: list[dict], manifest: str, vid: str) -> str | None:
    """The fix report names manifests as /app/... paths, the scan relative to the
    scanned dir, so match on the id and use the manifest's directory to break ties."""
    matches = [e for e in entries if e["id"] == vid]
    want = str(Path(re.sub(r"^(\.\./)+", "", manifest)).parent).removeprefix(".")
    for e in matches:
        if any(str(Path(f).parent).endswith(want) for f in e["files"]):
            return e["risk"]
    return matches[0]["risk"] if matches else None


def _vuln_outcomes(ctx: dict, agent: str) -> list[dict]:
    """One row per fixable instance: its category, and whether it was cleared,
    and cleared by an attempt that passed every gate."""
    runs: dict[tuple, list[dict]] = {}
    for a in ctx["attempts"]:
        if a["agent"] == agent and not is_harness_error(a):
            runs.setdefault((a["case"], a.get("repeat")), []).append(a)
    rows = []
    for (case, repeat), run in runs.items():
        facts = _baseline_facts(ctx, case, repeat)
        seen, missed, failed = set(), set(), set()
        risk: dict[tuple, str] = {}
        for a in run:
            entries = _attempt_breakability(ctx, a)
            for k in a.get("instances") or []:
                if tuple(k) not in risk and (r := _risk_for(entries, *k)):
                    risk[tuple(k)] = r
            inst = {tuple(k) for k in a.get("instances") or []}
            seen |= inst
            missed |= inst - {tuple(k) for k in a.get("instances_cleared") or []}
            if not a.get("verified"):
                failed |= inst
        for k in seen:
            f = facts.get(k)
            rows.append({
                "ecosystem": run[0]["ecosystem"],
                "severity": (f and f["severity"]) or "unknown",
                "difficulty": f["difficulty"] if f else "unknown",
                "dependency": ("direct" if f["direct"] else "transitive") if f else "unknown",
                "breakability": risk.get(k, _NOT_ASSESSED),
                "cleared": k not in missed,
                "passed": k not in missed and k not in failed,
            })
    return rows


def _rate_bars(ax: Axes, title: str, rows: list[dict], key: str,
               order: tuple[str, ...] | None, empty: str = "No data") -> None:
    ax.set_title(title, fontsize=10, loc="left")
    present = {r[key] for r in rows}
    cats = [c for c in order if c in present] + sorted(present - set(order)) if order else sorted(present)
    if not cats:
        ax.text(0.5, 0.5, empty, ha="center", va="center", fontsize=8, color="#555555")
        ax.axis("off")
        return
    groups = [[r for r in rows if r[key] == c] for c in cats]
    fix = [100 * sum(r["cleared"] for r in g) / len(g) for g in groups]
    ok = [100 * sum(r["passed"] for r in g) / len(g) for g in groups]
    x = np.arange(len(cats))
    for offset, values, color, label in ((-0.2, fix, _BAR, "Fix rate"),
                                         (0.2, ok, _ACCENT, "Pass rate")):
        bars = ax.bar(x + offset, values, 0.38, color=color, label=label)
        ax.bar_label(bars, labels=[f"{v:.0f}%" for v in values], fontsize=7, padding=2)
    ax.set_xticks(x, [f"{c}\n(n={len(g)})" for c, g in zip(cats, groups)], fontsize=7)
    ax.set_ylim(0, 112)
    ax.set_yticks(range(0, 101, 25), [f"{v}%" for v in range(0, 101, 25)], fontsize=7)
    ax.grid(axis="y", color=_GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)


def _pages_breakdowns(ctx: dict) -> list:
    def page(agent: str):
        def render(_ctx: dict) -> Figure:
            suffix = f": {agent_display(agent)}" if len(ctx["agents"]) > 1 else ""
            fig = _page(f"1. Performance by vulnerability category{suffix}")
            fig.text(0.04, 0.895,
                     "Per fixable vuln (manifest, id). Fix rate: cleared by the harness rescan. "
                     "Pass rate: cleared by an attempt that also passed every gate "
                     "(deps, build, tests).", fontsize=8, color="#555555")
            rows = _vuln_outcomes(ctx, agent)
            for i, (title, key, order) in enumerate(_BREAKDOWNS):
                col, row = i % 3, i // 3
                mine, empty = rows, "No data"
                if key == "breakability" and agent not in EVO_AGENTS:
                    mine, empty = [], "Evo only: the risk comes from Evo's fix report"
                _rate_bars(fig.add_axes((0.05 + col * 0.32, 0.50 - row * 0.40, 0.27, 0.30)),
                           title, mine, key, order, empty)
            fig.legend(handles=[Rectangle((0, 0), 1, 1, color=_BAR),
                                Rectangle((0, 0), 1, 1, color=_ACCENT)],
                       labels=["Fix rate", "Pass rate"], loc="upper right",
                       bbox_to_anchor=(0.96, 0.95), ncol=2, fontsize=8, frameon=False)
            return fig
        return render

    return [page(a) for a in ctx["agents"]]


_FAILED_LINES_PER_PAGE = 34


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n - 1] + "…"


def _wrap(text: str, width: int, lines: int = 2) -> str:
    return textwrap.fill(" ".join(text.split()), width, max_lines=lines, placeholder=" …")


def _failed(ctx: dict) -> list[dict]:
    return [a for a in ctx["attempts"] if not a.get("verified") and not is_harness_error(a)]


def _page_failures(ctx: dict) -> Figure:
    fig = _page("2. Failure reasons")
    failed = _failed(ctx)
    reasons = Counter(r for a in failed for r in a.get("reasons") or [])
    reason_rows = [[r, c] for r, c in reasons.most_common()] or [["None", 0]]
    _table(fig.add_axes((0.04, 0.66, 0.30, 0.20)), "Failure reasons", ["Reason", "Count"], reason_rows)
    categories = Counter((f["stage"], f["category"]) for a in failed if (f := a.get("failure")))
    category_rows = [[stage, cat, c] for (stage, cat), c in categories.most_common()]
    _table(fig.add_axes((0.40, 0.66, 0.40, 0.20)), "Failure categories (from logs)",
           ["Stage", "Category", "Count"], category_rows or [["-", "None", 0]])
    return fig


def _pages_failed(ctx: dict) -> list:
    failed = sorted(_failed(ctx), key=lambda a: (a["case"], a.get("group_index") or 0))
    one_agent = len(ctx["agents"]) == 1
    grouped = any(a.get("group_index") is not None for a in failed)
    cols = ["Repo", "Verdict", "Failure reasons", "Category", "Culprit", "First error"]
    if grouped:
        cols.insert(1, "Group")
    if not one_agent:
        cols.insert(1, "Harness")
    rows = []
    for a in failed:
        f = a.get("failure") or {}
        # "Foo.java:[10,23] cannot find symbol" -> "cannot find symbol"
        detail = re.sub(r"^\S+:\[\d+,\d+\]\s*", "", f.get("detail") or "-")
        row = [_wrap(a["case"], 32), _verdict(a), _wrap(", ".join(a.get("reasons") or []) or "-", 36, 3),
               f.get("category", "-"), _wrap(f.get("culprit") or "-", 30), _wrap(detail, 60, 3)]
        if grouped:
            row.insert(1, _fmt(a.get("group_index")))
        if not one_agent:
            row.insert(1, agent_display(a["agent"]))
        rows.append(row)
    # Split by wrapped line count, not rows, so every page fits.
    chunks, chunk, lines = [], [], 0.0
    for row in rows:
        n = 1 + 0.75 * max(str(c).count("\n") for c in row)  # matches _table's row growth
        if chunk and lines + n > _FAILED_LINES_PER_PAGE:
            chunks.append(chunk)
            chunk, lines = [], 0.0
        chunk.append(row)
        lines += n
    chunks.append(chunk)

    def page(chunk: list[list], idx: int):
        def render(_ctx: dict) -> Figure:
            suffix = f" ({idx + 1}/{len(chunks)})" if len(chunks) > 1 else ""
            fig = _page(f"2. Failed attempts{suffix}")
            _table(
                fig.add_axes((0.02, 0.08, 0.96, 0.80)),
                "",
                cols,
                chunk or [["None"] + [""] * (len(cols) - 1)],
                fontsize=7,
                row_scale=1.2,
                fit_height=True,
            )
            return fig
        return render

    return [page(c, i) for i, c in enumerate(chunks)]


def _page_tokens(ctx: dict) -> Figure:
    fig = _page("4. Token usage")
    total = _stats(ctx["attempts"], ctx["report"])
    # Token totals leave out harness errors, so the average must too.
    n = total["attempts"]
    cache_note = " (Claude incl. cache)" if any(_is_claude(a) for a in ctx["agents"]) else ""
    usage_rows = [
        ["Total tokens", _fmt_int(total["input_tokens"] + total["output_tokens"])],
        [f"Total input tokens{cache_note}", _fmt_int(total["input_tokens"])],
        ["Total output tokens", _fmt_int(total["output_tokens"])],
        ["Avg input tokens / run", _fmt_int(round(total["input_tokens"] / n) if n else None)],
        ["Avg output tokens / run", _fmt_int(round(total["output_tokens"] / n) if n else None)],
    ]
    _table(fig.add_axes((0.04, 0.52, 0.60, 0.34)), "Totals", ["Metric", "Value"], usage_rows)

    llm = ctx["report"].get("llm", {})
    p_in, p_out = llm.get("price_in_per_mtok") or 0.0, llm.get("price_out_per_mtok") or 0.0
    cost_rows = []
    for agent in ctx["agents"]:
        s = ctx["by_agent"][agent]
        # Claude Code reports one total that prices cache reads and writes at
        # their own rates; flat --price-in/--price-out would overstate it.
        priced = (p_in or p_out) and not _is_claude(agent)
        label = (f"{agent_display(agent)} ({llm.get('model') or 'model'}):\n"
                 f"input ${p_in:g} / 1M tokens,\noutput ${p_out:g} / 1M tokens"
                 if priced else f"{agent_display(agent)}\n(tool-reported cost)")
        if _is_claude(agent):
            label += "\ninput tokens incl. cache"
        in_cost = s["input_tokens"] / 1e6 * p_in if priced and p_in else None
        out_cost = s["output_tokens"] / 1e6 * p_out if priced and p_out else None
        cost_rows.append([
            label, _fmt_int(s["input_tokens"]), _fmt_int(s["output_tokens"]),
            "-" if in_cost is None else f"${in_cost:,.2f}",
            "-" if out_cost is None else f"${out_cost:,.2f}",
            f"${s['cost'] / s['attempts']:,.2f}" if s["attempts"] else "-",
            f"${s['cost']:,.2f}",
        ])
    cost_rows.append(["Total", _fmt_int(total["input_tokens"]), _fmt_int(total["output_tokens"]),
                      "", "", "", f"${total['cost']:,.2f}"])
    _table(
        fig.add_axes((0.02, 0.10, 0.96, 0.30)),
        "Cost estimate",
        ["Harness (pricing used)", "Input tokens", "Output tokens", "Input tokens cost (USD)",
         "Output tokens cost (USD)", "Cost per run (USD)", "Total cost (USD)"],
        cost_rows,
        fontsize=7,
        row_scale=2.6,
    )
    return fig


def _page_token_charts(ctx: dict) -> Figure:
    fig = _page("5. Token distribution")
    attempts = ctx["attempts"]
    tin = sum(a.get("input_tokens") or 0 for a in attempts)
    tout = sum(a.get("output_tokens") or 0 for a in attempts)
    ax_pie = fig.add_axes((0.30, 0.55, 0.40, 0.35))
    if tin or tout:
        total = tin + tout

        def _autopct(pct: float) -> str:
            return f"{pct:.1f}%\n({pct / 100 * total / 1000:,.0f}K)"

        ax_pie.pie([tin, tout], labels=["input", "output"], autopct=_autopct,
                   colors=[_BAR, _ACCENT])
        ax_pie.set_title("Token split: input vs output")
    else:
        ax_pie.text(0.5, 0.5, "No data", ha="center", va="center")
        ax_pie.axis("off")
    _hist(fig.add_axes((0.08, 0.10, 0.38, 0.34)),
          [a["input_tokens"] for a in attempts if a.get("input_tokens") is not None],
          "Input tokens per attempt", "input tokens")
    _hist(fig.add_axes((0.56, 0.10, 0.38, 0.34)),
          [a["output_tokens"] for a in attempts if a.get("output_tokens") is not None],
          "Output tokens per attempt", "output tokens")
    return fig


def _page_latency(ctx: dict) -> Figure:
    fig = _page("6. Latency and cost")
    attempts = ctx["attempts"]
    latencies = [a["latency_s"] for a in attempts if a.get("latency_s") is not None]
    costs = [a["cost_usd"] for a in attempts if a.get("cost_usd") is not None]
    lat, cost = _percentiles(latencies), _percentiles(costs)
    _table(
        fig.add_axes((0.04, 0.66, 0.7, 0.18)),
        "Percentiles",
        ["Metric", "p50", "p90", "p95"],
        [
            ["Agent latency per attempt (s)", _fmt(lat["p50"]), _fmt(lat["p90"]), _fmt(lat["p95"])],
            ["Cost per attempt (USD)", _fmt(cost["p50"]), _fmt(cost["p90"]), _fmt(cost["p95"])],
        ],
    )
    _hist(fig.add_axes((0.08, 0.12, 0.38, 0.40)), latencies,
          "Agent latency per attempt (s)", "seconds")
    _hist(fig.add_axes((0.56, 0.12, 0.38, 0.40)), costs, "Cost per attempt (USD)", "USD")
    return fig


def _case_rows(ctx: dict) -> list[list]:
    rows = []
    for a in ctx["attempts"]:
        case = a["case"] if a.get("group_index") is None else f"{a['case']} [{a.get('label', '')}]"
        rows.append([
            _clip(case, 80), a["ecosystem"], agent_display(a["agent"]), _verdict(a),
            f"{_fmt(a.get('fixable_cleared'))}/{_fmt(a.get('fixable_total'))}",
            "?" if rescan_failed(a) else _fmt_sev(a.get("remaining_by_severity") or {}),
            "?" if rescan_failed(a) else _fmt(a.get("introduced_count")),
            _fmt_ok(a.get("deps_ok")), _fmt_ok(a.get("build_ok")), _fmt_tests(a),
            _fmt_int(a.get("input_tokens")), _fmt_int(a.get("output_tokens")),
            f"${a['cost_usd']:,.2f}" if a.get("cost_usd") is not None else "-",
            f"{a['latency_s']:.0f}s" if a.get("latency_s") is not None else "-",
        ])
    return rows


def _pages_cases(ctx: dict) -> list:
    rows = _case_rows(ctx)
    chunks = [rows[i:i + _ROWS_PER_PAGE] for i in range(0, len(rows), _ROWS_PER_PAGE)] or [[]]

    def page(chunk: list[list], idx: int):
        def render(_ctx: dict) -> Figure:
            suffix = f" ({idx + 1}/{len(chunks)})" if len(chunks) > 1 else ""
            fig = _page(f"3. Per-repo results{suffix}")
            _table(
                fig.add_axes((0.02, 0.10, 0.96, 0.78)),
                "",
                ["Repo", "Ecosystem", "Harness", "Verdict", "Cleared", "Remaining C/H/M/L",
                 "New", "Deps", "Build", "Tests after/before", "Tok in", "Tok out", "Cost", "Time"],
                chunk,
                fontsize=7,
                fit_height=True,
            )
            return fig
        return render

    return [page(c, i) for i, c in enumerate(chunks)]


# --- entry -------------------------------------------------------------------

def _context(report: dict, cases_yaml: Path, run_id: str = "") -> dict:
    attempts = _attempts(report, _ecosystems(cases_yaml))
    agents = sorted({a["agent"] for a in attempts})
    by_agent_eco = {}
    for agent in agents:
        mine = [a for a in attempts if a["agent"] == agent]
        ecos = sorted({a["ecosystem"] for a in mine})
        rows = [(eco, _stats([a for a in mine if a["ecosystem"] == eco], report)) for eco in ecos]
        if len(ecos) > 1:
            rows.append(("All", _stats(mine, report)))
        by_agent_eco[agent] = rows
    return {
        "report": report,
        "run_id": run_id,
        "attempts": attempts,
        "agents": agents,
        "by_agent": {
            agent: _stats([a for a in attempts if a["agent"] == agent], report) for agent in agents
        },
        "by_agent_eco": by_agent_eco,
    }


def generate_pdf(report_path: Path, out_path: Path | None = None,
                 cases_yaml: Path = CASES_YAML) -> Path:
    report = json.loads(Path(report_path).read_text())
    ctx = _context(report, cases_yaml, Path(report_path).parent.name)
    out_path = out_path or Path(report_path).with_suffix(".pdf")
    pages = [_page_overview, *([_page_performance] if _has_sankey(ctx) else []), *_pages_breakdowns(ctx), _page_failures, *_pages_failed(ctx),
             *_pages_cases(ctx),
             _page_tokens, _page_token_charts, _page_latency]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with PdfPages(out_path) as pdf:
        for page_num, page_fn in enumerate(pages, start=1):
            fig = page_fn(ctx)
            _footer(fig, page_num, len(pages), timestamp)
            pdf.savefig(fig)
            plt.close(fig)
    return out_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cli.pdf_report")
    p.add_argument("report", help="benchmark JSON report")
    p.add_argument("--out", default=None, help="PDF path; defaults to the report path with .pdf")
    p.add_argument("--cases-yaml", default=str(CASES_YAML))
    args = p.parse_args(argv)
    out = generate_pdf(Path(args.report), Path(args.out) if args.out else None,
                       Path(args.cases_yaml))
    print(f"pdf: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

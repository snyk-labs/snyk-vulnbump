"""Render Figure 6: share of fixable vulnerability instances fixed by a PASS, by fix difficulty and
dependency type, for the three agents and the package manager bump (drawn hollow and dashed, as in Figure 4).

All series are recomputed from the four reports with the agents' definitions; the agents' values are first
checked against results.json. The bump's instance numbers are restricted to the agents' 2,066
(case, manifest, id) instances, as in pm_bump_baseline.py.

Run from the repo root: uv run --project benchmarking/scripts --group analysis python benchmarking/analysis/figure6_vuln_fix_by_difficulty.py
Writes benchmarking/analysis/figures/vuln-fix-by-difficulty.pdf.
"""

import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import PercentFormatter

HERE = Path(__file__).parent
FIG = HERE / "figures"
FIG.mkdir(exist_ok=True)
R = json.loads((HERE / "outputs" / "results.json").read_text())
EVO, SNYK_SCAN, UNAIDED, PM_BUMP = ("evo-remediation-agent", "claude-code-snyk-scan", "claude-code-unaided",
                                    "package-manager-bump")
# arm -> (report folder, agent key)
REPORT = {arm: (arm, f"{arm}-single-upgrade") for arm in (EVO, SNYK_SCAN, UNAIDED, PM_BUMP)}

AGENTS = [UNAIDED, SNYK_SCAN, EVO]
ARMS = AGENTS + [PM_BUMP]
BAR_ORDER = [PM_BUMP] + AGENTS  # baseline first, as in the tables
LABEL = {EVO: "Evo Remediation Agent", SNYK_SCAN: "Claude Code + Snyk scan", UNAIDED: "Claude Code unaided",
         PM_BUMP: "Package manager bump"}
# Pale orange, blue and purple, matching the pastel dataset figures. Validated with the dataviz
# validator: CVD dE 13.6, normal-vision dE 15.7 (worst pair orange/blue). They sit above the lightness
# band by design, so every mark gets a darker outline and a value label. The baseline is white with
# grey hatching and a dashed outline, as in figure4_failures.py.
FILL = {UNAIDED: "#f0ae84", SNYK_SCAN: "#a3c3e8", EVO: "#8f80bd", PM_BUMP: "#ffffff"}
EDGE = {UNAIDED: "#c98559", SNYK_SCAN: "#7397c2", EVO: "#665a96", PM_BUMP: "#8a8984"}
HATCH = {PM_BUMP: "////"}
LINESTYLE = {PM_BUMP: (0, (3, 1.5))}
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.family": "serif", "font.size": 9, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y", "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.axisbelow": True, "legend.frameon": False, "pdf.fonttype": 42, "hatch.linewidth": 0.5,
})


def style(arm):
    return dict(facecolor=FILL[arm], edgecolor=EDGE[arm], linewidth=0.6, hatch=HATCH.get(arm),
                linestyle=LINESTYLE.get(arm, "solid"))


def legend_handles():
    return [plt.Rectangle((0, 0), 1, 1, **style(a), label=LABEL[a]) for a in BAR_ORDER]


def bars(ax, groups, values, fmt):
    """Vertical grouped bars with the value above each bar, as in the distribution figure."""
    n, w = len(BAR_ORDER), 0.2
    x = np.arange(len(groups))
    for i, arm in enumerate(BAR_ORDER):
        xs = x + (i - (n - 1) / 2) * w
        ax.bar(xs, values[arm], w - 0.02, **style(arm))
        for xx, v in zip(xs, values[arm]):
            ax.text(xx, v + 1.5, fmt(v), ha="center", va="bottom", fontsize=6.5, color=INK2)
    ax.set_xticks(x)
    ax.set_xticklabels(groups, fontsize=7.5)
    ax.set_ylim(0, 108)
    ax.set_yticks(np.arange(0, 101, 20))
    ax.yaxis.set_major_formatter(PercentFormatter(100, decimals=0))


reports = {arm: json.loads((HERE.parent / "reports" / d / "benchmark.json").read_text()) for arm, (d, _) in REPORT.items()}
att = {arm: {(case, a["group_index"]): a for case, c in reports[arm]["cases"].items() for a in c["attempts"]
             if a["agent"] == REPORT[arm][1] and not a["harness_error"]} for arm in ARMS}
KEYS = set(att[EVO])
assert len(KEYS) == 307 and all(set(att[arm]) == KEYS for arm in ARMS)

# Instances fixed by a PASS: every covering attempt cleared the instance and passed every gate.
FACTS = {(case, f["manifest"], f["id"]): f for case, c in reports[EVO]["cases"].items()
         for f in c["baseline"]["vuln_facts"]}


def instance_dims(arm, keep=None):
    cover = defaultdict(list)
    for (case, _), a in att[arm].items():
        cl = {tuple(x) for x in a["instances_cleared"]}
        for m, i in a["instances"]:
            if keep is None or (case, m, i) in keep:
                cover[(case, m, i)].append(((m, i) in cl, a["verified"]))
    by = {"difficulty": defaultdict(lambda: {"n": 0, "safe": 0}), "direct": defaultdict(lambda: {"n": 0, "safe": 0})}
    for key, v in cover.items():
        for dim in by:
            val = FACTS[key].get(dim, "unknown")
            val = ("direct" if val else "transitive") if dim == "direct" else val
            by[dim][val]["n"] += 1
            by[dim][val]["safe"] += all(x and p for x, p in v)
    return set(cover), by


AGENT_INSTANCES = instance_dims(EVO)[0]
VULNS = {}
for arm in AGENTS:
    inst, VULNS[arm] = instance_dims(arm)
    assert inst == AGENT_INSTANCES and len(inst) == 2066
    assert all(VULNS[arm][d][k][f] == R["vulns"][arm]["by"][d][k][f]
               for d in VULNS[arm] for k in VULNS[arm][d] for f in ("n", "safe")), arm
inst, VULNS[PM_BUMP] = instance_dims(PM_BUMP, keep=AGENT_INSTANCES)
assert inst == AGENT_INSTANCES

fig, axes = plt.subplots(1, 2, figsize=(6.4, 2.7), gridspec_kw={"width_ratios": [3, 2]})
for ax, dim, keys, title in [
    (axes[0], "difficulty", [("patch", "Patch"), ("minor", "Minor"), ("major", "Major")], "(a) Fix difficulty"),
    (axes[1], "direct", [("direct", "Direct"), ("transitive", "Transitive")], "(b) Dependency type"),
]:
    by = VULNS[EVO][dim]
    groups = [f"{l}\n(n={by[k]['n']:,})" for k, l in keys]
    vals = {arm: [100 * VULNS[arm][dim][k]["safe"] / VULNS[arm][dim][k]["n"] for k, _ in keys] for arm in ARMS}
    bars(ax, groups, vals, lambda v: f"{v:.0f}")
    ax.set_title(title, loc="left", fontsize=9, fontweight="bold", color=INK)
axes[0].set_ylabel("% vulnerabilities", fontsize=8)
fig.tight_layout()
fig.legend(handles=legend_handles(), loc="lower center", ncol=4, bbox_to_anchor=(0.5, 1.0), fontsize=7.5,
           columnspacing=1.2, handlelength=1.6)
fig.savefig(FIG / "vuln-fix-by-difficulty.pdf", bbox_inches="tight", dpi=200)
plt.close(fig)
print("wrote vuln-fix-by-difficulty.pdf")
for arm in ARMS:
    print(f"  {arm:<22}", "  ".join(f"{k} {v['safe']}/{v['n']} ({100 * v['safe'] / v['n']:.1f}%)"
                                    for d in ("difficulty", "direct") for k, v in sorted(VULNS[arm][d].items())))

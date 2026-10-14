"""Render Figure 4: failed attempts by first failed gate, for the three agents and the package manager bump.

Counts come from pm_bump_baseline.json (written by pm_bump_baseline.py, which checks the agents' counts
against the paper). The bump is the non-agent baseline, so it is drawn hollow, hatched and dashed, like
its dashed box in the pipeline figure.

Run from the repo root: uv run --project benchmarking/scripts --group analysis python benchmarking/analysis/figure4_failures.py
Writes benchmarking/analysis/figures/failure-first-gate.pdf.
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).parent
FIG = HERE / "figures"
FIG.mkdir(exist_ok=True)
EVO, SNYK_SCAN, UNAIDED, PM_BUMP = ("evo-remediation-agent", "claude-code-snyk-scan", "claude-code-unaided",
                                    "package-manager-bump")
J = json.loads((HERE / "outputs" / "pm_bump_baseline.json").read_text())
COUNTS = {**{a: v["fig:failures"] for a, v in J["agents_reproduced"].items()}, PM_BUMP: J[PM_BUMP]["fig:failures"]}

ARMS = [UNAIDED, SNYK_SCAN, EVO, PM_BUMP]
LABEL = {EVO: "Evo Remediation Agent", SNYK_SCAN: "Claude Code + Snyk scan", UNAIDED: "Claude Code unaided",
         PM_BUMP: "Package manager bump"}
# Agent colours as in the other results figures; the baseline is white with grey hatching and a dashed outline.
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


reasons = [("vuln-not-cleared", "Vulnerability not fixed"), ("deps-unresolved", "Dependencies did not resolve"),
           ("build-broken", "Build broken"), ("tests-regressed", "Tests regressed")]
totals = {a: sum(COUNTS[a].values()) for a in ARMS}
assert all(sum(COUNTS[a].get(k, 0) for k, _ in reasons) == totals[a] for a in ARMS)

fig, ax = plt.subplots(figsize=(5.8, 3.1))
n, h = len(ARMS), 0.2
y = np.arange(len(reasons))
for i, arm in enumerate(ARMS):
    v = [COUNTS[arm].get(k, 0) for k, _ in reasons]
    ys = y + (i - (n - 1) / 2) * h
    ax.barh(ys, v, h - 0.03, **style(arm))
    for yy, vv in zip(ys, v):
        ax.text(vv + 1.2, yy, str(vv), va="center", fontsize=6.5, color=INK2)
ax.set_yticks(y)
ax.set_yticklabels([l for _, l in reasons], fontsize=7.5)
ax.invert_yaxis()
ax.grid(axis="y", visible=False)
ax.grid(axis="x", visible=True)
ax.set_xlim(0, 118)
ax.set_xlabel("Failed attempts, by first failed gate", fontsize=8)
handles = [plt.Rectangle((0, 0), 1, 1, **style(a), label=f"{LABEL[a]} ({totals[a]} failures)") for a in ARMS]
ax.legend(handles=handles, loc="lower right", fontsize=7.5)
fig.savefig(FIG / "failure-first-gate.pdf", bbox_inches="tight", dpi=200)
plt.close(fig)
print("wrote failure-first-gate.pdf", totals)

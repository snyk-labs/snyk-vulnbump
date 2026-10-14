"""Render Figure 5: PASS rate by the semver jump of the recommended upgrade, for the three agents and the
package manager bump (drawn hollow and dashed, as in Figure 4).

All series are recomputed from the four reports with the agents' definitions, and the PASS counts are
checked against the paper. Pairing is on (case, group_index). The jump of an upgrade is the semver jump
of its recommended version, taken from the agents' label (the agents agree; the baseline's two tokuhirom
tomcat targets differ only in the patch digit). Patch labels sit left of the markers, where no line runs.

Run from the repo root: uv run --project benchmarking/scripts --group analysis python benchmarking/analysis/figure5_pass_rate_by_jump.py
Writes benchmarking/analysis/figures/pass-rate-by-jump.pdf.
"""

import json
import re
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

HERE = Path(__file__).parent
FIG = HERE / "figures"
FIG.mkdir(exist_ok=True)
EVO, SNYK_SCAN, UNAIDED, PM_BUMP = ("evo-remediation-agent", "claude-code-snyk-scan", "claude-code-unaided",
                                    "package-manager-bump")
# arm -> (report folder, agent key)
REPORT = {arm: (arm, f"{arm}-single-upgrade") for arm in (EVO, SNYK_SCAN, UNAIDED, PM_BUMP)}

AGENTS = [UNAIDED, SNYK_SCAN, EVO]
ARMS = AGENTS + [PM_BUMP]
LABEL = {EVO: "Evo Remediation Agent", SNYK_SCAN: "Claude Code + Snyk scan", UNAIDED: "Claude Code unaided",
         PM_BUMP: "Package manager bump"}
# Pale orange, blue and purple, matching the pastel dataset figures. Validated with the dataviz
# validator: CVD dE 13.6, normal-vision dE 15.7 (worst pair orange/blue). They sit above the lightness
# band by design, so every mark gets a darker outline and a value label. The baseline is white with
# a dashed outline, as in figure4_failures.py.
FILL = {UNAIDED: "#f0ae84", SNYK_SCAN: "#a3c3e8", EVO: "#8f80bd", PM_BUMP: "#ffffff"}
EDGE = {UNAIDED: "#c98559", SNYK_SCAN: "#7397c2", EVO: "#665a96", PM_BUMP: "#8a8984"}
LINESTYLE = {PM_BUMP: (0, (3, 1.5))}
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.family": "serif", "font.size": 9, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y", "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.axisbelow": True, "legend.frameon": False, "pdf.fonttype": 42, "hatch.linewidth": 0.5,
})


def jump(label):
    m = re.search(r"@([\d.]+)\S*\s*->\s*\S*@([\d.]+)", label)
    a, b = ([int(x) for x in g.split(".")[:3] if x] for g in m.groups())
    a, b = a + [0] * (3 - len(a)), b + [0] * (3 - len(b))
    if a[0] != b[0]:
        return "major"
    if a[1] != b[1]:
        return "minor0" if a[0] == 0 else "minor"
    return "patch"


reports = {arm: json.loads((HERE.parent / "reports" / d / "benchmark.json").read_text()) for arm, (d, _) in REPORT.items()}
att = {arm: {(case, a["group_index"]): a for case, c in reports[arm]["cases"].items() for a in c["attempts"]
             if a["agent"] == REPORT[arm][1] and not a["harness_error"]} for arm in ARMS}
KEYS = set(att[EVO])
assert len(KEYS) == 307 and all(set(att[arm]) == KEYS for arm in ARMS)

# Version jump per upgrade, from one agent's label; the agents agree on every upgrade.
JUMP = {k: jump(att[EVO][k]["label"]) for k in KEYS}
assert all(jump(att[arm][k]["label"]) == JUMP[k] for arm in ARMS for k in KEYS)
passed, n_jump = Counter(), Counter()
for arm in ARMS:
    for k, a in att[arm].items():
        passed[(arm, JUMP[k])] += a["verified"]
        n_jump[(arm, JUMP[k])] += 1
# Checks against the paper: non-major and major PASS counts and the bump's patch/minor/major.
for arm, nonmajor, major in [(EVO, 182, 95), (SNYK_SCAN, 166, 72), (UNAIDED, 133, 50), (PM_BUMP, 114, 30)]:
    assert sum(passed[(arm, j)] for j in ("patch", "minor", "minor0")) == nonmajor and passed[(arm, "major")] == major
assert (passed[(PM_BUMP, "patch")], passed[(PM_BUMP, "minor")] + passed[(PM_BUMP, "minor0")]) == (38, 76)

jname = {"patch": "Patch", "minor": "Minor", "minor0": "Minor (0.x)", "major": "Major"}
jtick = {j: f"{jname[j]}\n({n_jump[(EVO, j)]} upgrades)" for j in jname}
jrate = {(arm, j): passed[(arm, j)] / n_jump[(arm, j)] for arm in ARMS for j in jname}


def marker(arm):
    return dict(s=40, color=FILL[arm], edgecolor=EDGE[arm], linewidth=0.8, zorder=3)


fig, ax = plt.subplots(figsize=(5.2, 2.9))
main, xm = ["patch", "minor", "major"], [0, 1, 2]
for arm in ARMS:
    v = [jrate[(arm, j)] for j in main]
    ax.plot(xm, v, color=EDGE[arm], lw=1.6, ls=LINESTYLE.get(arm, "solid"), zorder=2)
    ax.scatter(xm, v, **marker(arm))
    for k, (xx, vv) in enumerate(zip(xm, v)):
        if k == 0:  # Patch: label on the left, clear of the outgoing lines
            dy = {SNYK_SCAN: 0.022, EVO: -0.022}.get(arm, 0)
            ax.text(xx - 0.08, vv + dy, f"{100 * vv:.0f}", va="center", ha="right", fontsize=6.5, color=INK2)
        else:
            ax.text(xx + 0.07, vv, f"{100 * vv:.0f}", va="center", fontsize=6.5, color=INK2)
    v0 = jrate[(arm, "minor0")]
    ax.scatter(2.9, v0, **marker(arm))
    ax.text(2.97, v0, f"{100 * v0:.0f}", va="center", fontsize=6.5, color=INK2)
ax.axvline(2.45, color=GRID, lw=1, ls="--")
ax.text(2.9, 1.0, "no semver\nguarantee", ha="center", va="top", fontsize=6.5, color=INK2)
ax.set_xticks(xm + [2.9])
ax.set_xticklabels([jtick["patch"], jtick["minor"], jtick["major"], jtick["minor0"]], fontsize=7)
ax.set_xlim(-0.3, 3.25)
ax.set_ylim(0.2, 1.02)
ax.yaxis.set_major_formatter(lambda v, _: f"{100 * v:.0f}%")
ax.set_ylabel("Upgrades passing every gate", fontsize=8)
handles = [Line2D([], [], color=EDGE[a], lw=1.6, ls=LINESTYLE.get(a, "solid"), marker="o", markersize=6,
                  markerfacecolor=FILL[a], markeredgecolor=EDGE[a], markeredgewidth=0.8, label=LABEL[a])
           for a in [EVO, SNYK_SCAN, UNAIDED, PM_BUMP]]
ax.legend(handles=handles, loc="lower left", fontsize=7, handlelength=2.6)
fig.savefig(FIG / "pass-rate-by-jump.pdf", bbox_inches="tight", dpi=200)
plt.close(fig)
print("wrote pass-rate-by-jump.pdf")
for arm in ARMS:
    print(f"  {arm:<22}", "  ".join(f"{j} {passed[(arm, j)]}/{n_jump[(arm, j)]} ({100 * jrate[(arm, j)]:.1f}%)"
                                    for j in jname))

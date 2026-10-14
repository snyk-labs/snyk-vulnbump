"""Render Figure 2: Snyk Open Source production distributions versus the VulnBump dataset.

Panels (a)-(c) and (e) hard-code their inputs. Production: issue-project pairs introduced April-September
2026, from Snyk Open Source production statistics (not published); fix difficulty is aggregated across
languages, weighted by language share (62.7/22.1/9.9). VulnBump: the 43 repositories in
benchmarking/cases/cases.yaml, unique (repository, vulnerability id) pairs, from candidate mining (not
published).

Panel (d), VulnBump fix difficulty, is computed here from the evaluation-time baseline scans in the
published reports: the baseline `vuln_facts[*].difficulty` (harness.snyk.fix_difficulty: smallest semver
jump to a fixed release), the same field Figure 6 uses. Unit: unique (repository, vulnerability id); when
one id gets different classes in two manifests of a repository, the smaller jump counts. Unknown (no fixed
version or unparseable) is omitted. The script prints three variants; the figure uses every baseline
vulnerability with a fixed version, which is comparable with production.

Run from the repo root: uv run --project benchmarking/scripts --group analysis python benchmarking/analysis/figure2_distributions.py
Writes benchmarking/analysis/figures/distribution-comparison.pdf.
"""

import json
from collections import Counter
from pathlib import Path

import matplotlib
import yaml

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#ffffff"
SNYK_COLOR, VB_COLOR, VB_EDGE_COLOR = "#9a8fc0", "#bccadb", "#7a8ba5"

plt.rcParams.update({
    "font.family": "serif", "font.size": 9, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y", "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.axisbelow": True, "legend.frameon": False, "pdf.fonttype": 42,
})


def draw_distribution_comparison(path, SNYK=SNYK_COLOR, VB=VB_COLOR, VB_EDGE=VB_EDGE_COLOR, snyk_label="Snyk Open Source production",
                                 c_title="(c) Direct dependency share", c_ylabel="% of findings that are direct", vb_fix=None,
                                 vpp_p10=None, e_ylabel="Vulnerabilities per project", close_pad=0):
    vb_edge = VB_EDGE or SURFACE
    vb_line = VB_EDGE or VB
    ECOS6 = ["Maven", "Gradle", "npm", "Yarn", "pip", "Poetry"]
    # Production shares over the six package managers, and fix difficulty aggregated across
    # Java, JavaScript and Python weighted by language share (62.7/22.1/9.9).
    prod_pm = [50.59, 17.29, 16.56, 5.04, 5.87, 4.65]
    prod_fix = [35.1, 38.49, 26.41]
    panels = [
        ("(a) Package manager", ECOS6, prod_pm, [57.1, 2.9, 19.8, 7.8, 6.2, 6.2],
         "% of vulnerabilities", 70),
        ("(b) Severity", ["Critical", "High", "Medium", "Low"], [7.1, 47.5, 40.8, 4.6], [6.3, 44.3, 41.5, 7.8],
         "% of vulnerabilities", 60),
        (c_title, ECOS6, [14.0, 19.4, 34.6, 22.1, 55.5, 15.3],
         [15.8, 11.3, 32.7, 24.8, 84.0, 11.5], c_ylabel, 95),
        ("(d) Fix difficulty", ["Patch", "Minor", "Major"], prod_fix, vb_fix, "% of vulnerabilities", 60),
    ]
    fig = plt.figure(figsize=(7.2, 4.9))
    gsp = fig.add_gridspec(2, 3)
    axs = [fig.add_subplot(gsp[0, 0]), fig.add_subplot(gsp[0, 1]), fig.add_subplot(gsp[0, 2]),
           fig.add_subplot(gsp[1, 0])]
    for ax, (title, labels, prod, bench, ylabel, ymax) in zip(axs, panels):
        x = np.arange(len(labels))
        w = 0.38
        ax.bar(x - w / 2, prod, w, color=SNYK, edgecolor=SURFACE, linewidth=0.8)
        ax.bar(x + w / 2, bench, w, color=VB, edgecolor=vb_edge, linewidth=0.6 if VB_EDGE else 0.8)
        for xx, p, b in zip(x, prod, bench):
            # close_pad: push the two labels of a near-equal pair apart so they don't touch
            pad = close_pad if abs(p - b) < 5 else 0
            ax.text(xx - w / 2 - pad, p + 1, f"{p:.0f}", ha="center", va="bottom", fontsize=6.5, color=INK2)
            ax.text(xx + w / 2 + pad, b + 1, f"{b:.0f}", ha="center", va="bottom", fontsize=6.5, color=INK2)
        rot = len(labels) > 4
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=35 if rot else 0, ha="right" if rot else "center", fontsize=7.5)
        ax.set_title(title, loc="left", fontsize=9, fontweight="bold", color=INK)
        ax.set_ylabel(ylabel, fontsize=8)
        ax.set_ylim(0, ymax)
    ax = fig.add_subplot(gsp[1, 1:])
    vpp = {"Java": ([13, 51, 114, 163], [13, 40, 92, 130]), "JavaScript": ([6, 20, 49, 85], [4.5, 14, 73.75, 118.7]),
           "Python": ([5, 15, 43, 78], [23, 29, 36, 56.4])}
    for i, (lang, sets) in enumerate(vpp.items()):
        for j, (vals, col) in enumerate(zip(sets, (SNYK, VB))):
            xx = i + (-0.14 if j == 0 else 0.14)
            p25, med, p75, p90 = vals
            edge = vb_edge if j else SURFACE
            line = vb_line if j else col
            ax.add_patch(plt.Rectangle((xx - 0.08, p25), 0.16, p75 - p25, facecolor=col, edgecolor=edge,
                                       linewidth=0.6 if (j and VB_EDGE) else 0))
            ax.plot([xx, xx], [p75, p90], color=line, lw=1.2)
            ax.plot([xx - 0.05, xx + 0.05], [p90, p90], color=line, lw=1.2)
            if vpp_p10:
                p10 = vpp_p10[lang][j]
                ax.plot([xx, xx], [p10, p25], color=line, lw=1.2)
                ax.plot([xx - 0.05, xx + 0.05], [p10, p10], color=line, lw=1.2)
            ax.plot([xx - 0.08, xx + 0.08], [med, med], color=line if (j and VB_EDGE) else SURFACE, lw=2)
    ax.set_xticks(range(len(vpp)))
    ax.set_xticklabels(list(vpp), fontsize=7.5)
    ax.set_xlim(-0.6, len(vpp) - 0.4)
    ax.set_ylabel(e_ylabel, fontsize=8)
    ax.set_title("(e) Vulnerabilities per project", loc="left", fontsize=9, fontweight="bold", color=INK)
    ax.text(0.99, 1.06 if vpp_p10 else 0.97, "bar: P25-P75\ntick: median\nwhiskers: P10-P90" if vpp_p10 else "bar: P25-P75, tick: median, whisker: P90",
            transform=ax.transAxes,
            ha="right", va="top", fontsize=6.5, color=INK2)
    fig.tight_layout(h_pad=1.4)
    fig.legend(handles=[plt.Rectangle((0, 0), 1, 1, color=SNYK, label=snyk_label),
                        plt.Rectangle((0, 0), 1, 1, facecolor=VB, edgecolor=vb_edge, linewidth=0.6 if VB_EDGE else 0, label="VulnBump dataset")],
               loc="lower center", ncol=2, bbox_to_anchor=(0.5, 1.0), fontsize=8)
    fig.savefig(path, bbox_inches="tight", dpi=200)
    plt.close(fig)


ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "benchmarking" / "reports"
# report folder -> agent key
RUNS = {d: f"{d}-single-upgrade" for d in ("evo-remediation-agent", "claude-code-snyk-scan", "claude-code-unaided")}
LANG = {"maven": "Java", "gradle": "Java", "npm": "JS", "yarn": "JS", "pip": "Python", "poetry": "Python"}
CLASSES = ("patch", "minor", "major")

cases = yaml.safe_load((ROOT / "benchmarking" / "cases" / "cases.yaml").read_text())["cases"]
lang = {c["name"]: LANG[c["metadata"]["ecosystem"]] for c in cases}

reports = {d: json.loads((REPORTS / d / "benchmark.json").read_text()) for d in RUNS}
facts = {d: {(c, f["manifest"], f["id"]): f["difficulty"] for c, v in r["cases"].items()
             for f in v["baseline"]["vuln_facts"]} for d, r in reports.items()}
base = facts["evo-remediation-agent"]
assert all(f == base for f in facts.values()), "baselines differ across runs"

fixable = set()
for d, agent in RUNS.items():
    for c, v in reports[d]["cases"].items():
        for a in v["attempts"]:
            if a["agent"] == agent and not a["harness_error"]:
                fixable |= {(c, m, i) for m, i in a["instances"]}


def split(keys, dedupe=True):
    best = {}
    for c, m, i in keys:
        d = base[(c, m, i)]
        if d not in CLASSES:
            continue
        k = (c, i) if dedupe else (c, m, i)
        best[k] = min(best.get(k, d), d, key=CLASSES.index)
    out = {}
    for group in ("All", "Java", "JS", "Python"):
        n = Counter(d for k, d in best.items() if group == "All" or lang[k[0]] == group)
        tot = sum(n.values())
        out[group] = (tot, [round(100 * n[x] / tot, 1) for x in CLASSES])
    return out


sets = {
    "with a fixed version, unique (repo, id)": split(base),
    "fixable, unique (repo, id)": split(fixable),
    "fixable, (repo, manifest, id) as fig:difficulty": split(fixable, dedupe=False),
}
print(f"baseline instances {len(base)}, unique (repo, id) {len({(c, i) for c, _, i in base})}, "
      f"fixable instances {len(fixable)}, unknown among fixable {sum(base[k] == 'unknown' for k in fixable)}")
for name, s in sets.items():
    print(f"\n{name}  (patch / minor / major %)")
    for g, (n, p) in s.items():
        print(f"  {g:7s} n={n:5d}  {p}")

# Panel (d) as printed in the paper (34 / 41 / 24).
VB_FIX = sets["with a fixed version, unique (repo, id)"]["All"][1]
assert VB_FIX == [34.5, 41.1, 24.4], VB_FIX


FIG = Path(__file__).parent / "figures"
FIG.mkdir(exist_ok=True)
# P10 whiskers: production from Snyk Open Source production statistics (not published), VulnBump per
# repository from candidate mining (not published).
VPP_P10 = {"Java": (3, 2), "JavaScript": (2, 1.6), "Python": (2, 10.7)}
draw_distribution_comparison(
    FIG / "distribution-comparison.pdf", snyk_label="Snyk Open Source", c_title="(c) Direct vs. transitive",
    c_ylabel="% direct", vb_fix=VB_FIX, vpp_p10=VPP_P10,
    e_ylabel="Vulnerabilities", close_pad=0.06)
print("\nwrote distribution-comparison.pdf")

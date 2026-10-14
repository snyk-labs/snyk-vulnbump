"""Render Figure 1: the dataset selection Sankey.

Counts: candidate repositories per selection stage from candidate mining (not published), then the
final dataset in benchmarking/cases/cases.yaml.

Run from the repo root: uv run --project benchmarking/scripts --group analysis python benchmarking/analysis/figure1_dataset.py
Writes benchmarking/analysis/figures/dataset-sankey.pdf.
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import PathPatch
from matplotlib.path import Path as MPath

INK, INK2, SURFACE = "#0b0b0b", "#52514e", "#ffffff"
EDGE = "#7a8ba5"
# Gradient through the VulnBump colour of Figure 2 (#bccadb), from pale to slate.
CMAP = LinearSegmentedColormap.from_list("vulnbump", ["#e3e9f0", "#bccadb", "#7a8ba5", "#56698a"])
plt.rcParams.update({"font.family": "serif", "pdf.fonttype": 42})


def draw_selection_sankey(path):
    SRC = ["Popular open-source projects", "GitHub searches for vulnerable packages", "BUMP projects",
           "Gradle submodules", "Popular Maven projects"]
    SRC_PASS = [216, 178, 83, 22, 9]
    SRC_FAIL = [58, 102, 50, 24, 25]
    COLUMNS = [
        [(s, a + b) for s, a, b in zip(SRC, SRC_PASS, SRC_FAIL)],
        [("Installs", 508), ("Did not resolve", 259)],
        [("Builds", 475), ("Build failed", 33)],
        [("Tests run", 199), ("No tests ran", 276)],
        [("Tests green (> 85%)", 141), ("Tests not green", 58)],
        [("Vulnerable", 99), ("No vulnerabilities", 42)],
        [("VulnBump dataset", 43), ("Not selected", 56)],
        [("Maven", 18), ("npm", 11), ("Poetry", 5), ("Gradle", 3), ("Yarn", 3), ("pip", 3)],
    ]
    LINKS = [(SRC[i], "Installs", SRC_PASS[i]) for i in range(5)] + [(SRC[i], "Did not resolve", SRC_FAIL[i]) for i in range(5)]
    LINKS += [("Installs", "Builds", 475), ("Installs", "Build failed", 33),
              ("Builds", "Tests run", 199), ("Builds", "No tests ran", 276),
              ("Tests run", "Tests green (> 85%)", 141), ("Tests run", "Tests not green", 58),
              ("Tests green (> 85%)", "Vulnerable", 99), ("Tests green (> 85%)", "No vulnerabilities", 42),
              ("Vulnerable", "VulnBump dataset", 43), ("Vulnerable", "Not selected", 56)]
    LINKS += [("VulnBump dataset", e, n) for e, n in COLUMNS[-1]]
    DROPPED = {"Did not resolve", "Build failed", "No tests ran", "Tests not green", "No vulnerabilities", "Not selected"}
    HEADERS = ["Sources", "Dependencies\nresolve", "Build", "Tests run", ">85% tests\ngreen", "Vulnerable", "Selection", "Ecosystem"]

    H, PAD, NW, MINH = 100.0, 2.6, 0.12, 0.9
    scale = (H - PAD * 4) / 767
    xs = np.arange(len(COLUMNS)) * 1.0
    pos = {}
    for ci, col in enumerate(COLUMNS):
        last = ci == len(COLUMNS) - 1
        pad = PAD * 2.4 if last else (PAD if ci == 0 else PAD * 2.6)
        y = H
        for name, v in col:
            h = max(v * scale, 2.6 if last else MINH)
            pos[name] = [xs[ci], y, h, v, 0.0, 0.0]  # x, top, height, value, out offset, in offset
            y -= h + pad
    pass_cols = {n: CMAP(t) for n, t in zip(["Installs", "Builds", "Tests run", "Tests green (> 85%)", "Vulnerable",
                                             "VulnBump dataset"], np.linspace(0.25, 1.0, 6))}

    def node_color(name):
        if name in DROPPED:
            return "#cfcdc8"
        if name in SRC:
            return CMAP(0.12)
        if name in pass_cols:
            return pass_cols[name]
        return CMAP(1.0)


    fig, ax = plt.subplots(figsize=(7.4, 4.3))
    for s, t, v in LINKS:
        ps, pt = pos[s], pos[t]
        w = v * scale
        x0, x1 = ps[0] + NW / 2, pt[0] - NW / 2
        y0 = ps[1] - ps[4]
        y1 = pt[1] - pt[5]
        ps[4] += w
        pt[5] += w
        xm = (x0 + x1) / 2
        verts = [(x0, y0), (xm, y0), (xm, y1), (x1, y1), (x1, y1 - w), (xm, y1 - w), (xm, y0 - w), (x0, y0 - w), (x0, y0)]
        codes = [MPath.MOVETO, MPath.CURVE4, MPath.CURVE4, MPath.CURVE4, MPath.LINETO, MPath.CURVE4, MPath.CURVE4,
                 MPath.CURVE4, MPath.CLOSEPOLY]
        col = "#e2e0dc" if t in DROPPED else "#dfe5ee"
        ax.add_patch(PathPatch(MPath(verts, codes), facecolor=col, edgecolor="none", alpha=0.9, zorder=1))
    for name, (x, top, h, v, _, _) in pos.items():
        ax.add_patch(plt.Rectangle((x - NW / 2, top - h), NW, h, facecolor=node_color(name), edgecolor=EDGE, lw=0.5, zorder=2))
        if x == xs[0]:
            two = {"Popular open-source projects": "Popular open-source\nprojects",
                   "GitHub searches for vulnerable packages": "GitHub searches for\nvulnerable packages"}.get(name, name)
            ax.text(x - NW / 2 - 0.05, top - h / 2, f"{two}  {v}", ha="right", va="center", fontsize=6.3,
                    color=INK, linespacing=1.05)
        elif x == xs[-1]:
            ax.text(x + NW / 2 + 0.05, top - h / 2, f"{name}  {v}", ha="left", va="center", fontsize=6.3, color=INK)
        else:
            if name in DROPPED:
                ax.text(x, top - h - 1.2, f"{name}\n{v}", ha="center", va="top", fontsize=6.1,
                        linespacing=1.05, color=INK2)
            else:
                label = f"VulnBump\n{v}" if name == "VulnBump dataset" else f"{v}"
                ax.text(x + NW / 2 + 0.04, top - h / 2, label, ha="left", va="center", fontsize=6.1,
                        linespacing=1.05, color=INK)
    for x, hd in zip(xs, HEADERS):
        ax.text(x, H + 6.5, hd, ha="center", va="center", fontsize=6.3, fontweight="bold", color=INK, linespacing=1.05)
    ax.set_xlim(-1.25, xs[-1] + 0.72)
    ax.set_ylim(-10, H + 12)
    ax.axis("off")
    fig.savefig(path, bbox_inches="tight", dpi=200)
    plt.close(fig)


FIG = Path(__file__).parent / "figures"
FIG.mkdir(exist_ok=True)
draw_selection_sankey(FIG / "dataset-sankey.pdf")
print("wrote dataset-sankey.pdf")

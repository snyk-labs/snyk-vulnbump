"""Extract the agents' pairwise and three-way PASS overlap, source-edit PASSes and failure-cause totals.

Run from the repo root: uv run --project benchmarking/scripts --group analysis python benchmarking/analysis/extract_overlap.py
Reads results.json (extract_results.py), the three agents' reports, the PASS attempts' agent.diff files
and failure_causes.json (failure_causes.py). Writes benchmarking/analysis/outputs/results_overlap.json.
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REPORTS = ROOT / "benchmarking" / "reports"
SCANS = ROOT / "benchmarking" / "data" / "scans"
sys.path.insert(0, str(ROOT / "benchmarking" / "scripts"))
from harness.scans import after_dir  # noqa: E402  (falls back to the pre-rename scan dir names)

EVO, SNYK_SCAN, UNAIDED = "evo-remediation-agent", "claude-code-snyk-scan", "claude-code-unaided"
# arm -> (report folder, agent key, scan run id)
ARMS = {
    EVO: (EVO, f"{EVO}-single-upgrade", "20261004T201008Z"),
    SNYK_SCAN: (SNYK_SCAN, f"{SNYK_SCAN}-single-upgrade", "20261005T030735Z"),
    UNAIDED: (UNAIDED, f"{UNAIDED}-single-upgrade", "20261004T132240Z"),
}
PM_LABEL = {"maven": "Maven", "gradle": "Gradle", "npm": "npm", "yarn": "Yarn", "pip": "pip", "poetry": "Poetry"}

R1 = json.loads((HERE / "outputs" / "results.json").read_text())
cases_yaml = yaml.safe_load((ROOT / "benchmarking" / "cases" / "cases.yaml").read_text())
ECO = {c["name"]: c["metadata"]["ecosystem"] for c in cases_yaml["cases"]}
reports = {k: json.loads((REPORTS / d / "benchmark.json").read_text()) for k, (d, _, _) in ARMS.items()}
out = {}


def attempts(arm):
    agent = ARMS[arm][1]
    for case, c in reports[arm]["cases"].items():
        for a in c["attempts"]:
            if a["agent"] == agent and not a["harness_error"]:
                yield case, a


def attempt_dir(arm, case, a):
    _, agent, run = ARMS[arm]
    return after_dir(SCANS / run / case, agent, a["label"])


def jump(label):
    """Semver class of the recommended upgrade, as in figure5_pass_rate_by_jump.py."""
    m = re.search(r"@([\d.]+)\S*\s*->\s*\S*@([\d.]+)", label)
    a, b = ([int(x) for x in g.split(".")[:3] if x] for g in m.groups())
    a, b = a + [0] * (3 - len(a)), b + [0] * (3 - len(b))
    if a[0] != b[0]:
        return "major"
    if a[1] != b[1]:
        return "minor0" if a[0] == 0 else "minor"
    return "patch"


# C1. Pairwise exact tests on the discordant pairs (already in results.json; copied with formatted values).
out["mcnemar"] = {}
for pair, v in R1["paired"].items():
    x, y = pair.split("_vs_")
    out["mcnemar"][pair] = {"n": v["n"], "only_" + x: v["only_" + x], "only_" + y: v["only_" + y],
                            "discordant": v["only_" + x] + v["only_" + y], "p": v["mcnemar_exact_p"],
                            "p_sci": f"{v['mcnemar_exact_p']:.1e}"}

# C2. Three-way pass overlap per upgrade, joined on (case, group_index).
res = {arm: {(c, a["group_index"]): bool(a["verified"]) for c, a in attempts(arm)} for arm in ARMS}
keys = sorted(set.intersection(*(set(v) for v in res.values())))
assert len(keys) == 307, len(keys)
overlap = defaultdict(Counter)
combo = Counter()
for k in keys:
    n = sum(res[arm][k] for arm in ARMS)
    overlap["total"][n] += 1
    overlap[PM_LABEL[ECO[k[0]]]][n] += 1
    if n in (1, 2):
        combo["+".join(arm for arm in ARMS if res[arm][k])] += 1
out["overlap"] = {pm: {"n": sum(c.values()), "all3": c[3], "two": c[2], "one": c[1], "none": c[0]}
                  for pm, c in overlap.items()}
out["overlap_combos"] = dict(combo)

# C4. Dependency-file-only vs application-source PASSes, from each PASS attempt's agent.diff.
TEST_PATH = re.compile(
    r"(^|/)(test|tests|__tests__|spec|testing)/|(^|/)src/test/|"
    r"(^|/)[^/]*(_test\.[^/]+|\.spec\.[^/]+|\.test\.[^/]+|Tests?\.java|IT\.java)$|"
    r"(^|/)test_[^/]*\.py$|(^|/)conftest\.py$")
DEP_FILE = re.compile(
    r"(^|/)(pom\.xml|build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradle\.properties|[^/]*\.versions\.toml|"
    r"package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|\.npmrc|\.yarnrc(\.yml)?|"
    r"poetry\.lock|pyproject\.toml|requirements[^/]*\.txt|constraints[^/]*\.txt|Pipfile(\.lock)?|"
    r"setup\.py|setup\.cfg|maven-wrapper\.properties|gradle-wrapper\.properties)$")
# Generated artefacts written by builds or tests, and build/tooling configuration: neither side.
NEITHER = re.compile(r"\.(png|jpe?g|gif|csv|db|sqlite)$|(^|/)\.size-snapshot\.json$|(^|/)(tox\.ini|tsconfig[^/]*\.json|"
                     r"Dockerfile)$")
SOURCE = re.compile(r"\.(java|kt|kts|groovy|scala|ts|tsx|js|jsx|mjs|cjs|py|xml|ya?ml|properties|json|factories|imports)$")
# A changed line that only declares a dependency (e.g. "gitpython==3.1.60" in a Python list).
DEP_SPEC_LINE = re.compile(r"""^\s*["']?[A-Za-z0-9_.\-\[\]]+\s*(==|>=|<=|~=|!=|>|<)\s*[\w.*]+["']?,?\s*(#.*)?$""")


def file_class(path, body):
    if TEST_PATH.search(path):
        return "test"
    if DEP_FILE.search(path):
        return "dep"
    if NEITHER.search(path):
        return "neither"
    changed = [l[1:] for l in body.splitlines()
               if l[:1] in "+-" and not l.startswith(("+++", "---")) and l[1:].strip()]
    if changed and all(DEP_SPEC_LINE.match(l) for l in changed):
        return "dep"  # e.g. airbnb-knowledge-repo's _version.py dependency list
    if SOURCE.search(path):
        return "source"
    return "neither"


src = {arm: Counter() for arm in ARMS}
src_files = Counter()
upgrade_dep_only = set()
for arm in ARMS:
    for case, a in attempts(arm):
        if not a["verified"]:
            continue
        p = attempt_dir(arm, case, a) / "agent.diff"
        assert p.exists(), p
        classes = []
        for chunk in re.split(r"(?m)^(?=diff --git )", p.read_text(errors="replace")):
            m = re.match(r"diff --git a/(\S+) b/", chunk)
            if m:
                fc = file_class(m.group(1), chunk)
                classes.append(fc)
                src_files[fc] += 1
        needs_src = "source" in classes
        j = "major" if jump(a["label"]) == "major" else "nonmajor"
        src[arm]["pass"] += 1
        src[arm]["pass_" + j] += 1
        if needs_src:
            src[arm]["source"] += 1
            src[arm]["source_" + j] += 1
        else:
            upgrade_dep_only.add((case, a["group_index"]))
out["source_edits"] = {
    arm: {**dict(c), "share": c["source"] / c["pass"],
          "share_major": c["source_major"] / c["pass_major"],
          "share_nonmajor": c["source_nonmajor"] / c["pass_nonmajor"]}
    for arm, c in src.items()}
out["source_edits_file_classes"] = dict(src_files)
out["upgrades_passed_dep_only_by_some_agent"] = len(upgrade_dep_only)

# C3. Failure causes (one primary cause per failed attempt), from failure_causes.json.
fc_path = HERE / "outputs" / "failure_causes.json"
if fc_path.exists():
    fc = json.loads(fc_path.read_text())
    out["failure_causes"] = {"counts": fc["counts"], "totals": fc["totals"]}
    for arm in ARMS:
        n_fail = sum(1 for _, a in attempts(arm) if not a["verified"])
        assert sum(fc["counts"][arm].values()) == n_fail, (arm, n_fail)

(HERE / "outputs" / "results_overlap.json").write_text(json.dumps(out, indent=1))
print(json.dumps(out, indent=1))

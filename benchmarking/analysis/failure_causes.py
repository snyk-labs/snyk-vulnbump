"""Assign one primary failure cause to every failed attempt in the three agents' single-upgrade reports.

Run from the repo root: uv run --project benchmarking/scripts --group analysis python benchmarking/analysis/failure_causes.py
Writes benchmarking/analysis/outputs/failure_causes.json.

Rule-based over the attempt fields, agent.diff and the verify logs, followed by manual reading of every
failed attempt; disagreements are fixed in OVERRIDES. One annotator, no agreement measured.
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
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
UNFIXED = ["within_major", "transitive_pin", "no_change", "python_split", "wrong_version", "moved", "other_unfixed"]
BROKEN = ["dep_conflict", "api_migration", "binary_incompat", "behaviour_change", "old_toolchain", "other_broken"]
LABELS = {
    "within_major": "Stopped within the current major version",
    "transitive_pin": "Pinned, excluded or overrode transitive packages instead",
    "no_change": "No dependency change, or reverted",
    "python_split": "Fix locked only for newer Python versions",
    "wrong_version": "Chose a still-vulnerable version",
    "moved": "Vulnerability moved to another direct dependency",
    "other_unfixed": "Other (target reached, path remains)",
    "dep_conflict": "Dependencies do not resolve",
    "api_migration": "Missing module or symbol (API migration)",
    "binary_incompat": "Binary incompatibility at run time",
    "behaviour_change": "Behaviour change caught by tests",
    "old_toolchain": "Type definitions need a newer TypeScript compiler",
    "other_broken": "Other or unclear",
}
# Root-cause families for the paper's table: (family, category) per (first gate, cause).
FAMILIES = {
    "Vulnerability remediation": ["still_vulnerable", "partial_fix", "no_upgrade"],
    "Version compatibility": ["dependency_constraints", "runtime_constraint", "toolchain_constraint"],
    "Code compatibility": ["api_build", "missing_at_runtime", "behaviour"],
}
CATEGORY_LABELS = {
    "still_vulnerable": "Upgraded to still-vulnerable version",
    "partial_fix": "Still reachable via another path",
    "no_upgrade": "No upgrade made, or reverted",
    "dependency_constraints": "Resolver rejects dependency versions",
    "runtime_constraint": "Fix requires newer Python",
    "toolchain_constraint": "Dependencies need newer TypeScript",
    "api_build": "Changed API breaks build",
    "missing_at_runtime": "Class or method missing at runtime",
    "behaviour": "Changed behaviour fails tests",
}


def category(gate, cause):
    if cause in ("within_major", "wrong_version"):
        return "still_vulnerable"
    if cause in ("transitive_pin", "other_unfixed", "moved"):
        return "partial_fix"
    if cause == "no_change":
        return "no_upgrade"
    if cause == "dep_conflict":
        return "dependency_constraints"
    if cause == "python_split":
        return "runtime_constraint"
    if cause == "old_toolchain":
        return "toolchain_constraint"
    if cause == "api_migration":
        return "api_build" if gate == "build" else "missing_at_runtime"
    if cause == "binary_incompat":
        return "missing_at_runtime"
    return "behaviour"  # behaviour_change; other_broken is the turn-capped Jackson config exception


HEURISTICS = [
    "One primary cause per failed attempt, chosen by the first failed gate (attempt reasons[0]; gate order "
    "dependencies -> rescan -> build -> tests; a failed verification rescan counts with the rescan gate).",
    "Rescan-first, moved: every targeted instance left uncleared is in instances_moved.",
    "Rescan-first, python_split: the diff adds the target package to pyproject.toml/poetry.lock/requirements "
    "with a python / python_version marker, so the fixed version is locked only for newer interpreters.",
    "Rescan-first, target package changed (deps_changed, else a version change in the diff): within_major if "
    "it stays in its current major while the recommended version is a new major; wrong_version otherwise "
    "(the chosen version is still vulnerable, below the target or in a still-affected line); other_unfixed if "
    "the recommended version or later was reached and a path to the vulnerability remains.",
    "Rescan-first, target package unchanged but other dependency lines changed (exclusions, "
    "dependencyManagement/constraints pins, BOM or property overrides, resolutions, a different parent "
    "upgraded): transitive_pin.",
    "Rescan-first, no dependency file changed in agent.diff (or the change was reverted): no_change.",
    "Dependencies-first: all are dependency-resolution failures (dep_conflict); the failure_class labels are "
    "used only as a hint because of its ERESOLVE/IGNORECASE false positives.",
    "Build/tests-first: lines of the first failed gate's log absent from the baseline log are matched, in "
    "order, for toolchain errors (TypeScript/Java/Node version), linkage errors (NoSuchMethodError, "
    "NoClassDefFoundError, ...), missing symbols/modules (cannot find symbol, package does not exist, "
    "TS2305/2307/2339/2694, No module named), then assertion failures (behaviour_change); else other_broken.",
    "Every failed attempt was then read (diff, agent final report, logs); disagreements are fixed in an "
    "explicit OVERRIDES table with a reason.",
]

DEP_FILE = re.compile(
    r"(^|/)(pom\.xml|build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradle\.properties|libs\.versions\.toml|"
    r"package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|\.npmrc|\.yarnrc(\.yml)?|"
    r"pyproject\.toml|poetry\.lock|requirements[^/]*\.txt|constraints[^/]*\.txt|setup\.py|setup\.cfg|"
    r"Pipfile(\.lock)?)$")
PY_MARKER = re.compile(r"python_(full_)?version\s*[<>=]|python\s*=\s*\"[<>=]")

# Manual decisions after reading the attempt (key: arm, case, group_index) -> (cause, reason).
OVERRIDES = {
    # javax -> jakarta: Spring 6 test/context jars load, the project's javax.persistence classes are gone.
    (EVO, "informatici-openhospital-core", 6): ("api_migration", "NoClassDefFoundError javax/persistence/EntityManager (javax->jakarta)"),
    (EVO, "informatici-openhospital-core", 11): ("api_migration", "NoClassDefFoundError javax/persistence/EntityManager (javax->jakarta)"),
    (EVO, "informatici-openhospital-core", 12): ("api_migration", "NoClassDefFoundError javax/persistence/EntityManager (javax->jakarta)"),
    # pac4j 6 removed JEESessionStore, which the project's configuration still names.
    (EVO, "pac4j-dropwizard-pac4j", 2): ("api_migration", "ClassNotFoundException org.pac4j.core.context.session.JEESessionStore (removed in pac4j 6)"),
    # requirements.txt was set to nbconvert==7.17.1, but the rescan still resolves nbconvert 5.6.1.
    (EVO, "airbnb-knowledge-repo", 5): ("other_unfixed", "nbconvert==7.17.1 written to requirements.txt; rescan still finds nbconvert 5.6.1"),
    # jackson-bom 2.22.2 set via a Gradle extra property; 2.22.2 is inside the affected range [2.22.0,2.22.3).
    (UNAIDED, "tokuhirom-java-handbook", 4): ("wrong_version", "jackson-bom 2.22.2, still vulnerable ([2.22.0,2.22.3))"),
    (UNAIDED, "tokuhirom-java-handbook", 5): ("wrong_version", "jackson-bom 2.22.2, still vulnerable ([2.22.0,2.22.3))"),
    (UNAIDED, "tokuhirom-java-handbook", 6): ("wrong_version", "jackson-bom 2.22.2, still vulnerable ([2.22.0,2.22.3))"),
    (UNAIDED, "tokuhirom-java-handbook", 27): ("wrong_version", "jackson-bom 2.22.2, still vulnerable ([2.22.0,2.22.3))"),
    (UNAIDED, "tokuhirom-java-handbook", 28): ("wrong_version", "jackson-bom 2.22.2, still vulnerable ([2.22.0,2.22.3))"),
    # Turn cap hit mid-migration (Dropwizard 5); remaining errors are Jackson config-parsing failures.
    (EVO, "pac4j-dropwizard-pac4j", 0): ("other_broken", "turn cap; Jackson 'Conflicting setter definitions' while parsing pac4j config"),
}


def parse_label(label):
    m = re.match(r"(.*?): (.*)@([^@ ]+) -> (.*)@([^@ ]+)$", label)
    return m.group(2), m.group(3), m.group(5)


def vnums(v):
    if v is None:
        return None
    n = [int(x) for x in re.findall(r"\d+", v)[:3]]
    return n + [0] * (3 - len(n))


def python_split(short, dep_lines):
    """Target added with a python marker in pyproject/requirements, or a new poetry.lock entry whose
    python floor is 3.9+ (the fixed release is then locked only for newer interpreters)."""
    for f, ls in dep_lines.items():
        if re.search(r"pyproject\.toml$|requirements[^/]*\.txt$", f):
            for l in ls:
                if l.startswith("+") and re.search(r"(^|[\s\"'{\[])%s\b" % re.escape(short), l.lower()) \
                        and PY_MARKER.search(l):
                    return True
        if f.endswith("poetry.lock"):
            for i, l in enumerate(ls):
                if l.lower() == f'+name = "{short}"':
                    block = " ".join(ls[i + 1:i + 8])
                    if re.search(r'\+python-versions = "[^"]*>=\s*3\.(9|1\d)', block) or \
                            re.search(r"\+markers = .*python_(full_)?version\s*>=", block):
                        return True
    return False


def remaining_versions(adir, a, pkg):
    """Versions of the upgraded package still flagged for the targeted ids in the post-fix scan."""
    try:
        j = json.loads((adir / "snyk-test-after.json").read_text())
    except (OSError, ValueError):
        return set()
    ids = set(a["requested_ids"])
    return {v["version"] for p in (j if isinstance(j, list) else [j]) for v in p.get("vulnerabilities", [])
            if v["id"] in ids and v["packageName"].lower() == pkg.lower()}


def read(p):
    try:
        return p.read_text(errors="replace")
    except OSError:
        return ""


def diff_files(diff):
    """{path: [added/removed lines]} from agent.diff."""
    out, cur = defaultdict(list), None
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            cur = line.split()[-1][2:]
            out[cur]
        elif cur and line[:1] in "+-" and not line.startswith(("+++", "---")):
            out[cur].append(line)
    return out


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def new_lines(after, before):
    after, before = ANSI.sub("", after), ANSI.sub("", before)
    seen = {re.sub(r"\s+", " ", l.strip()) for l in before.splitlines()}
    return [l for l in after.splitlines() if l.strip() and re.sub(r"\s+", " ", l.strip()) not in seen]


BROKEN_RULES = [
    ("old_toolchain", re.compile(
        r"class file has wrong version|Unsupported class file major version|release version \d+ not supported|"
        r"invalid target release|EBADENGINE|requires a different Python|Requires-Python|"
        r"error TS1\d{3}:|error TS2416|Cannot find type definition file|has no exported member '.*' in .*d\.ts")),
    ("binary_incompat", re.compile(
        r"NoSuchMethodError|NoSuchFieldError|NoClassDefFoundError|ClassNotFoundException|"
        r"IncompatibleClassChangeError|AbstractMethodError|LinkageError")),
    ("api_migration", re.compile(
        r"cannot find symbol|package \S+ does not exist|cannot import name|No module named|ModuleNotFoundError|"
        r"has no attribute|Cannot find module|is not exported|error TS2305|error TS2307|error TS2339|"
        r"error TS2694|error TS2345|error TS2554|error TS2724|error TS2322|error TS2352|error TS2769|error TS2833|error TS2503|incompatible types|cannot be applied to|"
        r"no suitable (method|constructor)|does not override|is not a function")),
    ("behaviour_change", re.compile(
        r"AssertionError|AssertionFailedError|ComparisonFailure|expected:?\s*<|Expected:|Tests run:.*Failures: [1-9]|"
        r"FAILED \S+::|Error creating bean|OptimisticLock")),
]


def classify(arm, case, a, adir):
    first = a["reasons"][0] if a["reasons"] else "none"
    pkg, frm, to = parse_label(a["label"])
    short = pkg.split(":")[-1].lower()
    files = diff_files(read(adir / "agent.diff"))
    dep_lines = {f: ls for f, ls in files.items() if DEP_FILE.search(f) and ls}

    if first in ("vuln-not-cleared", "verification-scan-failed"):
        gate = "rescan"
        uncleared = a["fixable_total"] - a["fixable_cleared"]
        if a["instances_moved"] and len(a["instances_moved"]) >= uncleared:
            return gate, "moved", f"{len(a['instances_moved'])} moved of {uncleared} uncleared"
        if python_split(short, dep_lines):
            return gate, "python_split", "target locked with a python-version floor or marker"
        tgt = [d for d in a.get("deps_changed") or []
               if d["name"].lower() in (pkg.lower(), short) or d["name"].lower().split(":")[-1] == short]
        tgt = [d["after"] for d in tgt if d["after"] and d["after"] != d["before"]]
        remaining = remaining_versions(adir, a, pkg)
        if not tgt:
            # deps_changed misses BOM/property-managed versions in some sub-projects: use the rescan.
            tgt = [v for v in remaining if vnums(v) != vnums(frm)]
        if tgt:
            after = max(tgt, key=vnums)
            va, vf, vt = vnums(after), vnums(frm), vnums(to)
            ev = f"{short} {frm} -> {after} (target {to})"
            if va >= vt:
                if after in remaining:
                    return gate, "wrong_version", ev + "; chosen version still vulnerable"
                return gate, "other_unfixed", ev
            if va[0] == vf[0] < vt[0]:
                return gate, "within_major", ev
            return gate, "wrong_version", ev
        if dep_lines:
            return gate, "transitive_pin", "dependency files changed, target untouched: " + ", ".join(sorted(dep_lines))
        return gate, "no_change", "no dependency file changed"

    if first == "deps-unresolved":
        log = new_lines(read(adir / "install-after.log"), "")
        hit = next((l.strip() for l in log if re.search(r"(?-i:\bERESOLVE\b)|ResolutionImpossible|"
                                                       r"conflict|out of sync|in sync|Missing:|Invalid:", l)), "")
        return "dependencies", "dep_conflict", hit[:160]

    gate = {"build-broken": "build", "tests-regressed": "tests"}.get(first, first)
    after_name, before_name = {"build": ("build.log", "build.log"),
                               "tests": ("test-after.log", "test-before.log")}.get(gate, ("", ""))
    before_dir = adir.parent.parent / "before"
    log = new_lines(read(adir / after_name), read(before_dir / before_name))
    for cause, rx in BROKEN_RULES:
        for l in log:
            if rx.search(l):
                return gate, cause, l.strip()[:160]
    return gate, "other_broken", "no rule matched"


def main():
    by_attempt, counts, totals, root_counts = [], {}, {}, {}
    snyk_scan_major = Counter()
    major_counts = {}
    for arm, (d, agent, run) in ARMS.items():
        rep = json.loads((REPORTS / d / "benchmark.json").read_text())
        c, cm, cc = Counter(), Counter(), Counter()
        for case, cdata in rep["cases"].items():
            for a in cdata["attempts"]:
                if a["agent"] != agent or a["harness_error"] or a["verified"]:
                    continue
                adir = after_dir(SCANS / run / case, agent, a["label"])
                assert adir.is_dir(), adir
                gate, cause, ev = classify(arm, case, a, adir)
                key = (arm, case, a["group_index"])
                if key in OVERRIDES:
                    cause, why = OVERRIDES[key]
                    ev = f"override: {why}"
                c[cause] += 1
                cc[category(gate, cause)] += 1
                _, frm, to = parse_label(a["label"])
                major = vnums(frm)[0] != vnums(to)[0]
                cm[cause] += major
                if arm == SNYK_SCAN and gate == "rescan" and major:
                    snyk_scan_major[cause] += 1
                by_attempt.append({"arm": arm, "case": case, "group_index": a["group_index"], "label": a["label"],
                                   "first_gate": gate, "major": major, "cause": cause,
                                   "category": category(gate, cause), "evidence": ev})
        counts[arm] = {k: c.get(k, 0) for k in UNFIXED + BROKEN}
        totals[arm] = sum(c.values())
        root_counts[arm] = {k: cc.get(k, 0) for f in FAMILIES.values() for k in f}
        major_counts[arm] = {k: cm.get(k, 0) for k in UNFIXED + BROKEN}
    out = {"root_counts": root_counts, "families": FAMILIES, "category_labels": CATEGORY_LABELS,
           "counts": counts, "totals": totals, "labels": LABELS, "groups": {"unfixed": UNFIXED, "broken": BROKEN},
           "major_counts": major_counts,
           f"{SNYK_SCAN}_major_rescan_first": dict(snyk_scan_major), "heuristics": HEURISTICS,
           "overrides": len(OVERRIDES), "by_attempt": by_attempt}
    (Path(__file__).parent / "outputs" / "failure_causes.json").write_text(json.dumps(out, indent=1))
    print(f"{'cause':<18}" + "".join(f"{a:>23}" for a in ARMS))
    for k in UNFIXED + BROKEN:
        print(f"{k:<18}" + "".join(f"{counts[a][k]:>23}" for a in ARMS))
    print(f"{'total':<18}" + "".join(f"{totals[a]:>23}" for a in ARMS))
    print(f"{SNYK_SCAN} major rescan-first:", dict(snyk_scan_major))
    for fam, cats in FAMILIES.items():
        print(f"{fam:<26}" + "".join(f"{sum(root_counts[a][k] for k in cats):>15}" for a in ARMS))
        for k in cats:
            print(f"  {k:<24}" + "".join(f"{root_counts[a][k]:>15}" for a in ARMS))


if __name__ == "__main__":
    main()

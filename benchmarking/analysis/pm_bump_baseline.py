"""Package manager bump (package-manager-bump-single-upgrade) as a fourth column of Tables 2-4 and Figure 4.

Every number uses the definitions behind the agents' columns, and the script first recomputes the
agents' published cells (Tables tab:key, tab:headline, tab:causes and the Figure 4 counts) and
checks them against the cells printed in the paper before computing the baseline.

- Table 2 (tab:key): per-gate rates are the report's totals (deps_ok_rate, build_ok_rate,
  tests_kept_rate, green_rate; a gate that does not apply counts as passed). "Targeted
  vulnerabilities fixed" counts attempts whose reasons include neither vuln-not-cleared nor
  verification-scan-failed. Instances: an instance counts as fixed if every covering attempt cleared it.
- Table 3 (tab:headline): macro rates with a repository-level percentile bootstrap (10,000
  resamples, seed 12345, as extract_results.py, for both PASS and the vulnerability-fix rate).
- Instance drift: the baseline's 8 Oct scan has 2,072 fixable instances, the agents' 2,066. The paper
  keeps 2,066, so instance-level baseline numbers are restricted to the agents' (case, manifest, id)
  set; the six extra instances are reported separately.
- Figure 4: first failed gate is reasons[0]; a failed verification rescan counts with the rescan gate.
- Table 4 (tab:causes): failure_causes.classify() and category() on the baseline's attempts, plus
  baseline-specific rules and overrides (PM_BUMP_OVERRIDES), each with a reason. Failures that fit no
  existing row go to "other".

Run from the repo root: uv run --project benchmarking/scripts --group analysis python benchmarking/analysis/pm_bump_baseline.py
Writes benchmarking/analysis/outputs/pm_bump_baseline.json.
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import failure_causes as fc  # noqa: E402
from harness.scans import after_dir  # noqa: E402  (benchmarking/scripts is on sys.path via failure_causes)

ROOT = HERE.parents[1]
REPORTS = ROOT / "benchmarking" / "reports"
SCANS = ROOT / "benchmarking" / "data" / "scans"
EVO, SNYK_SCAN, UNAIDED, PM_BUMP = fc.EVO, fc.SNYK_SCAN, fc.UNAIDED, "package-manager-bump"
# arm -> (report folder, agent key)
ARMS = {arm: (arm, f"{arm}-single-upgrade") for arm in (UNAIDED, SNYK_SCAN, EVO, PM_BUMP)}
AGENTS = [UNAIDED, SNYK_SCAN, EVO]
# The package manager bump report merges the main run with a tokuhirom re-run.
PM_BUMP_RUN, PM_BUMP_RERUN = "20261008T084649Z", {"tokuhirom-java-handbook": "20261008T102937Z"}
SEED, B = 12345, 10000

# Cells as printed in the paper, used to prove the definitions match.
PAPER = {
    "tab:key": {
        UNAIDED: ["95.4\\%", "63.5\\%", "98.4\\%", "98.7\\%", "93.8\\%", "59.6\\%", "(183/307)", "72.7\\%", "(1{,}503/2{,}066)"],
        SNYK_SCAN: ["94.8\\%", "83.7\\%", "98.0\\%", "99.0\\%", "92.8\\%", "77.5\\%", "(238/307)", "83.1\\%", "(1{,}716/2{,}066)"],
        EVO: ["100\\%", "97.1\\%", "96.7\\%", "95.4\\%", "92.8\\%", "90.2\\%", "(277/307)", "95.9\\%", "(1{,}982/2{,}066)"],
    },
    "tab:headline": {
        UNAIDED: ["0.680 [0.582, 0.770]", "15 / 3", "0.807 [0.722, 0.882]", "282 / 223 / 58"],
        SNYK_SCAN: ["0.801 [0.710, 0.879]", "22 / 2", "0.901 [0.841, 0.951]", "143 / 167 / 40"],
        EVO: ["0.931 [0.881, 0.971]", "32 / 0", "0.976 [0.952, 0.994]", "35 / 35 / 14"],
    },
    "tab:causes": {  # family totals then rows, in table order, then failed attempts
        UNAIDED: [92, 64, 13, 15, 30, 14, 15, 1, 2, 2, 0, 0, 124],
        SNYK_SCAN: [40, 13, 15, 12, 25, 16, 8, 1, 4, 2, 1, 1, 69],
        EVO: [8, 1, 3, 4, 7, 0, 1, 6, 15, 3, 6, 6, 30],
    },
    "fig:failures": {
        UNAIDED: {"deps-unresolved": 14, "vuln-not-cleared": 107, "build-broken": 3, "tests-regressed": 0},
        SNYK_SCAN: {"deps-unresolved": 16, "vuln-not-cleared": 48, "build-broken": 3, "tests-regressed": 2},
        EVO: {"deps-unresolved": 0, "vuln-not-cleared": 9, "build-broken": 9, "tests-regressed": 12},
    },
}
KEY_ROWS = ["Dependencies resolve", "Targeted vulnerabilities fixed", "Build", "Tests pass", "Project still works",
            "PASS", "PASS count", "Vulnerability instances fixed", "Vulnerability instances count"]
HEADLINE_ROWS = ["All gates pass, macro [95% CI]", "Repositories with every upgrade passing / none passing",
                 "Vulnerabilities fixed, macro [95% CI]", "Fixable instances remaining (H / M / L)"]
GATES = ["deps-unresolved", "vuln-not-cleared", "build-broken", "tests-regressed"]
CAT_ORDER = [c for cats in fc.FAMILIES.values() for c in cats]
FAMILIES = {**fc.FAMILIES, "Other": ["other"]}
CATEGORY_LABELS = {**fc.CATEGORY_LABELS, "other": "Other (environment, rescan failure)"}

# Baseline-specific decisions after reading each attempt's diff and logs: (case, group_index) ->
# (category, reason). Categories are failure_causes' root-cause rows, plus "other".
PM_BUMP_OVERRIDES = {
    # Dependencies gate.
    ("vpulim-node-soap", 0): ("api_build", "install's `prepare` script runs tsc: src/http.ts TS2339/TS2345 on axios 1.20 header types"),
    ("encode-django-rest-framework", 1): ("other", "pyyaml 5.4 has no cp311 wheel and its sdist fails under Cython 3 ('build_ext' has no attribute 'cython_sources')"),
    ("fmtn-a", 7): ("dependency_constraints", "org.graalvm.js:js 24.1.0 is published as a POM, so the jar the pom declares does not resolve (agents added <type>pom</type>)"),
    # Rescan gate.
    ("airbnb-knowledge-repo", 2): ("partial_fix", "pin overridden: jinja2==3.1.6 written, knowledge_repo/_version.py keeps 3.0.3 (as the Evo Remediation Agent's nbconvert override)"),
    ("airbnb-knowledge-repo", 9): ("partial_fix", "pin overridden: werkzeug==3.1.9 written, knowledge_repo/_version.py keeps 2.0.3 (as the Evo Remediation Agent's nbconvert override)"),
    ("goparrot-geocoder", 0): ("other", "verification rescan failed (new lockfile scanned as 8 dependencies); no rescan result for the target"),
    # Build gate (no rule matched in failure_causes).
    ("assertj-assertj-guava", 1): ("dependency_constraints", "maven-enforcer BannedDependencies rejects net.bytebuddy:byte-buddy 1.18.3 pulled in by assertj-core 3.27.7"),
    ("lettuce-io-lettuce-core", 0): ("toolchain_constraint", "kotlin-maven-plugin 1.5.30 cannot read micrometer-core 1.16.7 Kotlin metadata 1.7.0"),
    ("lettuce-io-lettuce-core", 6): ("toolchain_constraint", "kotlin-stdlib 2.1.0 metadata incompatible with the project's Kotlin 1.5 compiler"),
    ("santiq-bulletproof-nodejs", 5): ("api_build", "src/api/middlewares/isAuth.ts TS2349: express-jwt 7 default export is not callable"),
    # Tests gate (no rule matched in failure_causes).
    ("alphagov-pay-adminusers", 0): ("missing_at_runtime", "logback-classic 1.6.3 needs slf4j 2: cannot access org.slf4j.spi.LoggingEventAware"),
    ("jericks-geoserver-shell", 0): ("behaviour", "org.json 20231013: JSONObject getString on an integer now throws JSONException"),
    ("knaufk-flink-faker", 0): ("missing_at_runtime", "junit-jupiter fails to discover tests after flink 1.20 test deps; the Evo Remediation Agent's PASS also raised junit 5.8.2 -> 5.10.1"),
}
POETRY_PYTHON = re.compile(r"requires Python >=[\d.]+.*|version solving failed")
PYPI_REMOVED = "Package onnxruntime-gpu (1.20.1) not found."


def attempts(rep, agent):
    for case, c in rep["cases"].items():
        for a in c["attempts"]:
            if a["agent"] == agent and not a["harness_error"]:
                yield case, a


def boot_ci(by_repo):
    """Same as extract_results.py: percentile CI over resampled repositories (order-sensitive)."""
    rng = np.random.default_rng(SEED)
    repos = list(by_repo)
    means = np.array([np.mean(by_repo[r]) for r in repos])
    idx = rng.integers(0, len(repos), size=(B, len(repos)))
    return [float(x) for x in np.percentile(means[idx].mean(axis=1), [2.5, 97.5])]


def macro(by_repo):
    return float(np.mean([np.mean(v) for v in by_repo.values()]))


def pct(x):
    v = round(100 * x, 1)
    return "100\\%" if v == 100 else f"{v:.1f}\\%"


def thousands(n):
    return f"{n:,}".replace(",", "{,}")


def instance_cover(rep, agent, keep=None):
    """{(case, manifest, id): [(cleared, verified), ...]} over covering attempts, optionally restricted."""
    cover = defaultdict(list)
    for case, a in attempts(rep, agent):
        cl = {tuple(x) for x in a["instances_cleared"]}
        for m, i in a["instances"]:
            if keep is None or (case, m, i) in keep:
                cover[(case, m, i)].append(((m, i) in cl, a["verified"]))
    return cover


def columns(rep, agent, keep=None):
    t = rep["totals"][agent]
    att = list(attempts(rep, agent))
    n = len(att)
    by_repo = defaultdict(list)
    for case, a in att:
        by_repo[case].append(1 if a["verified"] else 0)
    rescan_ok = sum(1 for _, a in att if not {"vuln-not-cleared", "verification-scan-failed"} & set(a["reasons"]))
    facts = {(case, f["manifest"], f["id"]): f for case, c in rep["cases"].items() for f in c["baseline"]["vuln_facts"]}
    cover = instance_cover(rep, agent, keep)
    cleared = {k: all(x for x, _ in v) for k, v in cover.items()}
    remaining = Counter(facts[k]["severity"] for k, ok in cleared.items() if not ok)
    cleared_by_repo = defaultdict(list)
    for (case, _, _), ok in cleared.items():
        cleared_by_repo[case].append(1 if ok else 0)
    pass_ci, fix_ci = boot_ci(by_repo), boot_ci(cleared_by_repo)
    n_inst, n_fixed = len(cover), sum(cleared.values())
    raw = {
        "attempts": n, "verified": t["verified"], "deps_ok_rate": t["deps_ok_rate"], "rescan_ok": rescan_ok,
        "rescan_ok_rate": rescan_ok / n, "build_ok_rate": t["build_ok_rate"], "tests_kept_rate": t["tests_kept_rate"],
        "green_rate": t["green_rate"], "pass_rate": t["verified"] / n,
        "instances": n_inst, "instances_fixed": n_fixed,
        "macro_pass": macro(by_repo), "macro_pass_ci95": pass_ci,
        "repos_all_pass": sum(1 for v in by_repo.values() if all(v)),
        "repos_zero_pass": sum(1 for v in by_repo.values() if not any(v)),
        "macro_fixed": macro(cleared_by_repo), "macro_fixed_ci95": fix_ci,
        "remaining_by_severity": {s: remaining.get(s, 0) for s in ("high", "medium", "low")},
        "report_totals": {k: t[k] for k in ("fixable_total", "fixable_cleared", "macro_rate", "macro_cleared_rate",
                                            "remaining_by_severity")},
    }
    key = [pct(t["deps_ok_rate"]), pct(rescan_ok / n), pct(t["build_ok_rate"]), pct(t["tests_kept_rate"]),
           pct(t["green_rate"]), pct(t["verified"] / n), f"({t['verified']}/{n})", pct(n_fixed / n_inst),
           f"({thousands(n_fixed)}/{thousands(n_inst)})"]
    headline = [f"{raw['macro_pass']:.3f} [{pass_ci[0]:.3f}, {pass_ci[1]:.3f}]",
                f"{raw['repos_all_pass']} / {raw['repos_zero_pass']}",
                f"{raw['macro_fixed']:.3f} [{fix_ci[0]:.3f}, {fix_ci[1]:.3f}]",
                " / ".join(str(raw["remaining_by_severity"][s]) for s in ("high", "medium", "low"))]
    return raw, key, headline


def first_gates(rep, agent):
    c = Counter()
    for _, a in attempts(rep, agent):
        if not a["verified"]:
            r = a["reasons"][0]
            c["vuln-not-cleared" if r == "verification-scan-failed" else r] += 1
    return {g: c.get(g, 0) for g in GATES} | {k: v for k, v in c.items() if k not in GATES}


def attempt_dir(arm, case, agent, label):
    run = fc.ARMS[arm][2] if arm in fc.ARMS else PM_BUMP_RERUN.get(case, PM_BUMP_RUN)
    d = after_dir(SCANS / run / case, agent, label)
    assert d.is_dir(), d
    return d


def causes(arm, rep, agent):
    rows = []
    for case, a in attempts(rep, agent):
        if a["verified"]:
            continue
        adir = attempt_dir(arm, case, agent, a["label"])
        gate, cause, ev = fc.classify(arm, case, a, adir)
        key = (arm, case, a["group_index"])
        if key in fc.OVERRIDES:
            cause, why = fc.OVERRIDES[key]
            ev = f"override: {why}"
        cat, rule = fc.category(gate, cause), "failure_causes"
        if arm == PM_BUMP:
            debug = fc.read(adir / "agent-debug.log")
            if gate == "dependencies" and PYPI_REMOVED in debug:
                cat, rule, ev = "other", f"{PM_BUMP} rule: locked package removed from PyPI", PYPI_REMOVED
            elif gate == "dependencies" and "version solving failed" in debug and "requires Python" in debug:
                cat, rule = "runtime_constraint", f"{PM_BUMP} rule: Poetry re-lock fails on the target's Python floor"
                ev = next(l.strip() for l in debug.splitlines() if l.startswith("Because"))[:160]
            if (case, a["group_index"]) in PM_BUMP_OVERRIDES:
                cat, why = PM_BUMP_OVERRIDES[(case, a["group_index"])]
                rule, ev = f"{PM_BUMP} override", why
        rows.append({"case": case, "group_index": a["group_index"], "label": a["label"], "reasons": a["reasons"],
                     "first_gate": gate, "v4_cause": cause, "category": cat, "rule": rule, "evidence": ev,
                     "pm_bump_managed": a.get("pm_bump_managed")})
    return rows


def cause_column(rows):
    c = Counter(r["category"] for r in rows)
    col = {}
    for fam, cats in FAMILIES.items():
        col[fam] = sum(c.get(k, 0) for k in cats)
        for k in cats:
            col[k] = c.get(k, 0)
    col["failed"] = len(rows)
    assert sum(col[f] for f in FAMILIES) == len(rows)
    return col


def paper_order(col):
    out = []
    for fam, cats in fc.FAMILIES.items():
        out += [col[fam]] + [col[k] for k in cats]
    return out + [col["failed"]]


def main():
    reps = {arm: json.loads((REPORTS / d / "benchmark.json").read_text()) for arm, (d, _) in ARMS.items()}
    agent_keys = {k for k in instance_cover(reps[EVO], ARMS[EVO][1])}
    out = {"definitions": __doc__.strip(), "agents_reproduced": {}, PM_BUMP: {}}

    # 1. Reproduce the agents' published cells.
    for arm in AGENTS:
        rep, agent = reps[arm], ARMS[arm][1]
        assert {k for k in instance_cover(rep, agent)} == agent_keys
        raw, key, headline = columns(rep, agent)
        gates = first_gates(rep, agent)
        rows = causes(arm, rep, agent)
        col = cause_column(rows)
        assert key == PAPER["tab:key"][arm], (arm, key)
        assert headline == PAPER["tab:headline"][arm], (arm, headline)
        assert {g: gates[g] for g in GATES} == PAPER["fig:failures"][arm] and sum(gates.values()) == col["failed"], (arm, gates)
        assert paper_order(col) == PAPER["tab:causes"][arm] and col["other"] == 0, (arm, paper_order(col))
        out["agents_reproduced"][arm] = {"tab:key": dict(zip(KEY_ROWS, key)), "tab:headline": dict(zip(HEADLINE_ROWS, headline)),
                                         "fig:failures": gates, "tab:causes": col, "raw": raw}

    # 2. Baseline, instance numbers restricted to the agents' 2,066 instances.
    rep, agent = reps[PM_BUMP], ARMS[PM_BUMP][1]
    raw, key, headline = columns(rep, agent, keep=agent_keys)
    raw_all, key_all, headline_all = columns(rep, agent)
    assert raw_all["instances"] == rep["totals"][agent]["fixable_total"] == 2072
    assert raw_all["instances_fixed"] == rep["totals"][agent]["fixable_cleared"]
    assert {s: raw_all["remaining_by_severity"][s] for s in raw_all["remaining_by_severity"]} == \
        {s: rep["totals"][agent]["remaining_by_severity"][s] for s in ("high", "medium", "low")}

    facts = {(c, f["manifest"], f["id"]): f for c, cd in rep["cases"].items() for f in cd["baseline"]["vuln_facts"]}
    full = instance_cover(rep, agent)
    extra = []
    for k in sorted(set(full) - agent_keys):
        covering = [(a["group_index"], a["label"], a["verified"], [k[1], k[2]] in a["instances_cleared"])
                    for case, a in attempts(rep, agent) if case == k[0] and [k[1], k[2]] in a["instances"]]
        extra.append({"case": k[0], "manifest": k[1], "id": k[2], "severity": facts[k]["severity"],
                      "fixed": all(x for x, _ in full[k]),
                      "covering": [{"group_index": g, "label": l, "verified": v, "cleared": c} for g, l, v, c in covering]})

    # Rescan gate restricted to the agents' instances (does the drift change any per-upgrade verdict?).
    rescan_restricted, changed = 0, []
    for case, a in attempts(rep, agent):
        insts = [tuple(x) for x in a["instances"] if (case, *x) in agent_keys]
        cl = {tuple(x) for x in a["instances_cleared"]}
        scan_failed = "verification-scan-failed" in a["reasons"]
        ok_r = not scan_failed and all(x in cl for x in insts)
        ok = not {"vuln-not-cleared", "verification-scan-failed"} & set(a["reasons"])
        rescan_restricted += ok_r
        if ok_r != ok:
            changed.append({"case": case, "group_index": a["group_index"], "label": a["label"]})

    tomcat = []
    for case, a in attempts(rep, agent):
        if case == "tokuhirom-java-handbook" and a["group_index"] in (10, 33):
            ag = next(x for _, x in attempts(reps[EVO], ARMS[EVO][1])
                      if _ == case and x["group_index"] == a["group_index"])
            tomcat.append({"group_index": a["group_index"], "pm_bump_label": a["label"], "agent_label": ag["label"],
                           "pm_bump_verified": a["verified"], "pm_bump_reasons": a["reasons"],
                           "pm_bump_cleared": f"{a['fixable_cleared']}/{a['fixable_total']}",
                           "agent_instances": len(ag["instances"])})

    gates = first_gates(rep, agent)
    rows = causes(PM_BUMP, rep, agent)
    col = cause_column(rows)
    assert sum(gates.values()) == col["failed"] == 163
    out[PM_BUMP] = {
        "tab:key": dict(zip(KEY_ROWS, key)),
        "tab:headline": dict(zip(HEADLINE_ROWS, headline)),
        "unrestricted_2072": {"tab:key": dict(zip(KEY_ROWS, key_all)), "tab:headline": dict(zip(HEADLINE_ROWS, headline_all))},
        "raw": raw, "raw_unrestricted": raw_all,
        "extra_instances": extra,
        "rescan_gate_restricted_to_2066": {"count": rescan_restricted, "verdicts_changed": changed},
        "tokuhirom_tomcat": tomcat,
        "fig:failures": gates,
        "fig:failures_note": "first failed gate = reasons[0]; goparrot-geocoder's verification-scan-failed counts as rescan",
        "tab:causes": col,
        "tab:causes_rule_counts": dict(Counter(r["rule"] for r in rows)),
        "tab:causes_by_fail_cause_gate": dict(Counter(f"{r['first_gate']}/{r['category']}" for r in rows)),
        "category_labels": CATEGORY_LABELS, "families": FAMILIES,
        "overrides": {f"{c}:{g}": {"category": k, "reason": w} for (c, g), (k, w) in PM_BUMP_OVERRIDES.items()},
        "by_attempt": rows,
    }
    (HERE / "outputs" / "pm_bump_baseline.json").write_text(json.dumps(out, indent=1))

    print("Agents reproduced: tab:key, tab:headline, fig:failures, tab:causes match the paper")
    print("\nPackage manager bump")
    for k, v in out[PM_BUMP]["tab:key"].items():
        print(f"  {k:<34} {v:<22} (2,072 basis: {out[PM_BUMP]['unrestricted_2072']['tab:key'][k]})")
    for k, v in out[PM_BUMP]["tab:headline"].items():
        print(f"  {k:<58} {v:<22} (2,072 basis: {out[PM_BUMP]['unrestricted_2072']['tab:headline'][k]})")
    print("  first failed gate:", gates)
    print("  root causes:")
    for fam, cats in FAMILIES.items():
        print(f"    {fam:<28}{col[fam]:>4}")
        for k in cats:
            print(f"      {CATEGORY_LABELS[k]:<40}{col[k]:>4}")
    print("  extra instances:", [(e["case"], e["id"], e["fixed"]) for e in extra])
    print("  rescan gate restricted:", rescan_restricted, changed)
    print("  tomcat:", tomcat)


if __name__ == "__main__":
    main()

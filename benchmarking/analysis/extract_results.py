"""Extract the results numbers used in the paper from the single-upgrade reports.

The package manager bump baselines are optional. reports/package-manager-bump
(exact pins) defines the Snyk-advice-solvable split: the tasks where Snyk's
recommended upgrade, applied as-is to the named package, gets through every gate.
The `split` section pairs every agent against it. The split undercounts the easy
tasks: in a managed build (Maven parent or BOM, Spring dependency-management) the
pin moves the named package but not the transitives the BOM manages, so the split
is also broken down by declaration (managed / declared).
reports/package-manager-bump-min (Python pins as >=ver) adds the min and
either-policy counts, and a second pairing against the either-policy set.

Attempts pair on (case, group_index), so every arm is compared on all 307
tasks. Arms scanned on different days can see different advisories: two
tokuhirom tomcat-embed-websocket tasks target 10.1.60 for the package manager
bump and 10.1.59 for the agents, after an advisory published between the runs.

Run from the repo root: uv run --project benchmarking/scripts --group analysis python benchmarking/analysis/extract_results.py
Writes benchmarking/analysis/outputs/results.json and prints a summary.
"""

import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import yaml
from scipy.stats import binomtest

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "benchmarking" / "reports"
EVO, SNYK_SCAN, UNAIDED = "evo-remediation-agent", "claude-code-snyk-scan", "claude-code-unaided"
PM_BUMP, PM_BUMP_MIN = "package-manager-bump", "package-manager-bump-min"
# arm -> (report folder, agent key)
ARMS = {arm: (arm, f"{arm}-single-upgrade") for arm in (EVO, SNYK_SCAN, UNAIDED)}
# The LLM-free floor; its PASS set is the Snyk-advice-solvable split.
if (REPORTS / PM_BUMP / "benchmark.json").exists():
    ARMS[PM_BUMP] = (PM_BUMP, f"{PM_BUMP}-single-upgrade")
# Python pins as >=ver instead of ==ver; run on the pip/Poetry cases only.
if (REPORTS / PM_BUMP_MIN / "benchmark.json").exists():
    ARMS[PM_BUMP_MIN] = (PM_BUMP_MIN, f"{PM_BUMP_MIN}-single-upgrade")
SEED, B = 12345, 10000
# Repos where one repo-wide obstacle fails every package manager bump task, so the
# advice-solvable share is also reported without them. kutia: a latent npm peer
# conflict. The bump's re-lock rewrites the v1 lockfile as v3 (falling back to
# --legacy-peer-deps, as the fixture's install does) and `npm ci` rejects the
# result. It is not a fixture defect: agents that resolve the conflict pass.
PM_BUMP_SENSITIVITY_EXCLUDE = ("kutia-software-company-express-typescript-starter",)
# The build overrides the bump's pin with a second declaration, keyed (case, package).
# airbnb's install runs `pip install -e '.[all]'` after requirements.txt, and
# knowledge_repo/_version.py pins the same packages exactly: the old version comes
# back (vuln-not-cleared), or the two pins conflict (weasyprint, deps-unresolved).
PIN_OVERRIDDEN = {("airbnb-knowledge-repo", p) for p in (
    "gitpython", "jinja2", "markdown", "nbconvert", "pygments", "weasyprint", "werkzeug")}

cases_yaml = yaml.safe_load((ROOT / "benchmarking" / "cases" / "cases.yaml").read_text())
ECO = {c["name"]: c["metadata"]["ecosystem"] for c in cases_yaml["cases"]}

reports = {k: json.loads((REPORTS / d / "benchmark.json").read_text()) for k, (d, _) in ARMS.items()}
out = {"meta": {}, "headline": {}, "eco": {}, "failures": {}, "vulns": {}}


def attempts(arm):
    agent = ARMS[arm][1]
    for case, c in reports[arm]["cases"].items():
        for a in c["attempts"]:
            if a["agent"] == agent and not a["harness_error"]:
                yield case, a


def task(case, a):
    return case, a["group_index"]


def macro(by_repo):
    return float(np.mean([np.mean(v) for v in by_repo.values()]))


def boot_ci(by_repo, rng):
    repos = list(by_repo)
    means = np.array([np.mean(by_repo[r]) for r in repos])
    idx = rng.integers(0, len(repos), size=(B, len(repos)))
    return [float(x) for x in np.percentile(means[idx].mean(axis=1), [2.5, 97.5])]


for arm, (d, agent) in ARMS.items():
    r = reports[arm]
    t = r["totals"][agent]
    out["meta"][arm] = {k: r[k] for k in ("generated_at", "git_sha", "llm", "cli", "fairness")}
    att = list(attempts(arm))
    by_repo = defaultdict(list)
    for case, a in att:
        by_repo[case].append(1 if a["verified"] else 0)
    rng = np.random.default_rng(SEED)
    turns = [a["turns_used"] for _, a in att if a.get("turns_used") is not None]
    out["headline"][arm] = {
        "repos": t["repos"], "attempts": t["attempts"], "verified": t["verified"],
        "rate": t["rate"], "macro_rate": t["macro_rate"], "rate_ci95_report": t["rate_ci95"],
        "macro_ci95_recomputed": boot_ci(by_repo, rng),
        "fixable_total": t["fixable_total"], "fixable_cleared": t["fixable_cleared"],
        "cleared_rate": t["cleared_rate"], "macro_cleared_rate": t["macro_cleared_rate"],
        "cleared_ci95": t["cleared_rate_ci95"],
        "deps_ok_rate": t["deps_ok_rate"], "build_ok_rate": t["build_ok_rate"],
        "tests_kept_rate": t["tests_kept_rate"], "green_rate": t["green_rate"],
        "tests_modified": t["tests_modified"],
        "tests_modified_pass": sum(1 for _, a in att if a["tests_modified"] and a["verified"]),
        "introduced_count": t["introduced_count"], "introduced_by_severity": t["introduced_by_severity"],
        "remaining_by_severity": t["remaining_by_severity"],
        "attempts_introducing": sum(1 for _, a in att if a.get("introduced_count")),
        "unrelated_bumps": t["unrelated_bumps"],
        "snyk_policy_modified": t["snyk_policy_modified"], "claimed_not_fixed": t["claimed_not_fixed"],
        "timed_out": sum(1 for _, a in att if a["timed_out"]),
        "turn_capped": sum(1 for _, a in att if a.get("turn_capped")),
        "harness_errors": t["harness_errors"],
        "input_tokens": t["input_tokens"], "output_tokens": t["output_tokens"],
        "turns_median": statistics.median(turns) if turns else None,
        "repos_all_pass": sum(1 for v in by_repo.values() if all(v)),
        "repos_zero_pass": sum(1 for v in by_repo.values() if not any(v)),
    }

    eco = defaultdict(lambda: defaultdict(list))
    for case, a in att:
        eco[ECO[case]][case].append(1 if a["verified"] else 0)
    out["eco"][arm] = {
        e: {"repos": len(v), "attempts": sum(len(x) for x in v.values()),
            "verified": sum(sum(x) for x in v.values()),
            "pooled": sum(sum(x) for x in v.values()) / sum(len(x) for x in v.values()),
            "macro": macro(v)}
        for e, v in sorted(eco.items())
    }

    reasons, cats = Counter(), Counter()
    for _, a in att:
        if not a["verified"]:
            reasons[a["reasons"][0] if a["reasons"] else ("timeout" if a["timed_out"] else "none")] += 1
            for x in a["reasons"]:
                reasons["any:" + x] += 1
    out["failures"][arm] = {"first_reason": dict(reasons), "category": t["failure_categories"]}

    # Per vuln instance: cleared if every covering attempt cleared it; safely fixed if those attempts all passed.
    facts = {}
    for case, c in r["cases"].items():
        for f in c["baseline"]["vuln_facts"]:
            facts[(case, f["manifest"], f["id"])] = f
    cover = defaultdict(list)
    for case, a in att:
        cl = {tuple(x) for x in a["instances_cleared"]}
        for m, i in a["instances"]:
            cover[(case, m, i)].append(((m, i) in cl, a["verified"]))
    dims = {"severity": defaultdict(lambda: [0, 0, 0]), "difficulty": defaultdict(lambda: [0, 0, 0]),
            "direct": defaultdict(lambda: [0, 0, 0])}
    for key, v in cover.items():
        f = facts.get(key, {})
        cleared = all(x for x, _ in v)
        safe = all(x and p for x, p in v)
        for dim in dims:
            val = f.get(dim, "unknown")
            val = ("direct" if val else "transitive") if dim == "direct" else val
            dims[dim][val][0] += 1
            dims[dim][val][1] += cleared
            dims[dim][val][2] += safe
    # Macro vulnerability-fix rate CI, same bootstrap as PASS (per-repo share of instances cleared).
    cleared_by_repo = defaultdict(list)
    for (case, m, i), v in cover.items():
        cleared_by_repo[case].append(1 if all(x for x, _ in v) else 0)
    out["headline"][arm]["macro_cleared_ci95_recomputed"] = boot_ci(cleared_by_repo, np.random.default_rng(SEED))
    out["headline"][arm]["macro_cleared_recomputed"] = macro(cleared_by_repo)
    out["vulns"][arm] = {
        "instances": len(cover),
        "by": {dim: {k: {"n": n, "cleared": c, "safe": s} for k, (n, c, s) in sorted(v.items())}
               for dim, v in dims.items()},
    }

# Paired comparison on the same upgrade (case, group_index).
for label, ok in [("paired", lambda a: a["verified"])]:
    res = {arm: {task(c, a): ok(a) for c, a in attempts(arm)} for arm in ARMS}
    out[label] = {}
    for x, y in [(EVO, SNYK_SCAN), (EVO, UNAIDED), (SNYK_SCAN, UNAIDED)]:
        keys = sorted(set(res[x]) & set(res[y]))
        both = sum(res[x][k] and res[y][k] for k in keys)
        ox = sum(res[x][k] and not res[y][k] for k in keys)
        oy = sum(res[y][k] and not res[x][k] for k in keys)
        by_repo = defaultdict(lambda: ([], []))
        for k in keys:
            by_repo[k[0]][0].append(res[x][k])
            by_repo[k[0]][1].append(res[y][k])
        repos = sorted(by_repo)
        d = np.array([np.mean(by_repo[r][0]) - np.mean(by_repo[r][1]) for r in repos])
        rng = np.random.default_rng(SEED)
        bd = d[rng.integers(0, len(repos), size=(B, len(repos)))].mean(axis=1)
        out[label][f"{x}_vs_{y}"] = {
            "n": len(keys), "both": both, f"only_{x}": ox, f"only_{y}": oy, "neither": len(keys) - both - ox - oy,
            "mcnemar_exact_p": binomtest(ox, ox + oy, 0.5).pvalue if ox + oy else None,
            "macro_diff": float(d.mean()), "macro_diff_ci95": [float(v) for v in np.percentile(bd, [2.5, 97.5])],
            f"repos_{x}_higher": int((d > 0).sum()), f"repos_{y}_higher": int((d < 0).sum()),
            "repos_tied": int((d == 0).sum()),
        }



def _bump(label):
    """(package, from, to, semver jump) parsed from a group label "manifest: a@1 -> a@2"."""
    frm, _, to = label.split(": ", 1)[-1].partition(" -> ")
    pkg, _, v0 = frm.rpartition("@")
    v1 = to.rpartition("@")[2]
    p0, p1 = ([int(x) for x in re.findall(r"\d+", v)[:3]] + [0, 0, 0] for v in (v0, v1))
    jump = "major" if p0[0] != p1[0] else "minor" if p0[1] != p1[1] else "patch"
    return pkg, v0, v1, jump


def _rate_ci(by_repo):
    by_repo = {k: v for k, v in by_repo.items() if v}
    if not by_repo:
        return None, None
    return macro(by_repo), boot_ci(by_repo, np.random.default_rng(SEED))


def _declaration(a):
    """How the bump's pin landed: on a version a BOM/parent manages, or on a declared one."""
    return {True: "managed", False: "declared"}.get(a.get("pm_bump_managed"), "unknown")


def _against(arm, solvable, bump):
    """One agent's 2x2 against an advice-solvable set, paired on (case, group_index)."""
    bump_keys = set(bump)
    res = {task(c, a): (c, a) for c, a in attempts(arm)}
    keys = sorted(set(res) & bump_keys)
    cells = Counter()
    by_decl = defaultdict(Counter)
    value_add_tests = Counter()
    on_solv, on_unsolv = defaultdict(list), defaultdict(list)
    regressions = []
    for k in keys:
        case, a = res[k]
        n_ok, a_ok = k in solvable, a["verified"]
        cell = ("both" if a_ok else "regression") if n_ok else ("value_add" if a_ok else "neither")
        cells[cell] += 1
        by_decl[_declaration(bump[k][1])][cell] += 1
        if cell == "value_add":
            # The bump never edits tests; agents may migrate them to a breaking change.
            value_add_tests["modified" if a["tests_modified"] else "untouched"] += 1
        (on_solv if n_ok else on_unsolv)[case].append(1 if a_ok else 0)
        if n_ok and not a_ok:
            pkg, _, target, _ = _bump(a["label"])
            landed = next((d["after"] for d in a["deps_changed"] if d["name"] == pkg), None)
            regressions.append({"case": case, "label": a["label"], "reasons": a["reasons"],
                                "category": (a.get("failure") or {}).get("category"),
                                "landed": landed, "off_target": landed not in (None, target)})
    ms, ms_ci = _rate_ci(on_solv)
    mu, mu_ci = _rate_ci(on_unsolv)
    reg, add = cells["regression"], cells["value_add"]
    return {
        "n": len(keys), "unpaired": len(bump_keys - set(res)),
        "unpaired_tasks": sorted(bump_keys - set(res)),
        **{c: cells[c] for c in ("both", "regression", "value_add", "neither")},
        "value_add_tests": {t: value_add_tests[t] for t in ("modified", "untouched")},
        "by_declaration": {d: {c: v[c] for c in ("both", "regression", "value_add", "neither")}
                           for d, v in sorted(by_decl.items())},
        "pass_on_advice_solvable": cells["both"] / max(1, cells["both"] + reg),
        "pass_on_other": add / max(1, add + cells["neither"]),
        "macro_advice_solvable": ms, "macro_advice_solvable_ci95": ms_ci,
        "macro_other": mu, "macro_other_ci95": mu_ci,
        "mcnemar_exact_p": binomtest(add, add + reg, 0.5).pvalue if add + reg else None,
        "regressions": regressions,
    }


if PM_BUMP in ARMS:
    # Policy A (exact pins) defines the split. Policy B (package-manager-bump-min:
    # Python pins as >=ver) differs only on Python tasks; elsewhere B is A. A|B, the
    # tasks either policy solves, is an upper bound on the advice-solvable split:
    # picking the policy after seeing the gates is not something a mechanical bump can do.
    bump = {task(c, a): (c, a) for c, a in attempts(PM_BUMP)}
    solvable = {k for k, (_, a) in bump.items() if a["verified"]}
    python = {k for k, (c, _) in bump.items() if ECO[c] in ("pip", "poetry")}
    if PM_BUMP_MIN in ARMS:
        b_ok = {task(c, a): a["verified"] for c, a in attempts(PM_BUMP_MIN)}
        missing = python - set(b_ok)
        solvable_b = (solvable - python) | {k for k in python if b_ok.get(k)}
        policies = {
            "exact": len(solvable), "min": len(solvable_b), "either": len(solvable | solvable_b),
            "python_tasks": len(python), "python_missing_from_min": len(missing),
            "python": {"both": len(python & solvable & solvable_b),
                       "exact_only": len((python & solvable) - solvable_b),
                       "min_only": len((python & solvable_b) - solvable),
                       "neither": len(python - solvable - solvable_b)},
        }
    else:
        solvable_b, policies = None, None
    facts = {(case, f["manifest"], f["id"]): f
             for case, c in reports[PM_BUMP]["cases"].items() for f in c["baseline"]["vuln_facts"]}

    def task_dims(case, a):
        _, _, _, jump = _bump(a["label"])
        direct = any(facts.get((case, m, i), {}).get("direct") for m, i in a["instances"])
        return {"eco": ECO[case], "jump": jump, "path": "direct" if direct else "transitive-only",
                "declaration": _declaration(a)}

    # One cause per failed task, the first gate that broke.
    causes = {"bump-not-applied": "not-applied", "vuln-not-cleared": "vuln-not-cleared",
              "verification-scan-failed": "scan-failed", "build-broken": "build-broken",
              "tests-regressed": "tests-regressed", "tests-not-measured": "tests-regressed"}

    def fail_cause(case, a):
        if (case, _bump(a["label"])[0]) in PIN_OVERRIDDEN:
            return "pin-overridden"
        reasons = a["reasons"]
        if "deps-unresolved" in reasons and "bump-not-applied" not in reasons:
            # The install gate: a failed re-lock (npm/yarn/poetry/Gradle locks) or
            # verify's install. Only a dependency conflict means the target does not
            # resolve; a build step inside the install (a prepare script, an sdist)
            # failing is not that.
            category = (a.get("failure") or {}).get("category")
            if category == "dependency-conflict":
                # The npm/yarn re-lock succeeded, then verify's install rejected the lockfile.
                relocked = ECO[case] in ("npm", "yarn") and not a["agent_exit"]
                return "lockfile-rejected" if relocked else "target-unresolvable"
            return "install-step-broken" if category and category != "other" else "unclassified"
        return next((causes[x] for x in reasons if x in causes), "other")

    by = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    first, cause = Counter(), Counter()
    cause_by_decl = defaultdict(Counter)
    for k, (case, a) in bump.items():
        for dim, val in task_dims(case, a).items():
            by[dim][val][0] += 1
            by[dim][val][1] += a["verified"]
        if not a["verified"]:
            first[a["reasons"][0] if a["reasons"] else "none"] += 1
            c = fail_cause(case, a)
            cause[c] += 1
            cause_by_decl[_declaration(a)][c] += 1
    bump_by_repo = defaultdict(list)
    for case, a in bump.values():
        bump_by_repo[case].append(1 if a["verified"] else 0)
    out["split"] = {PM_BUMP: {
        "n": len(bump), "advice_solvable": len(solvable), "rate": len(solvable) / len(bump),
        "macro": macro(bump_by_repo), "macro_ci95": boot_ci(bump_by_repo, np.random.default_rng(SEED)),
        "by": {dim: {v: {"n": n, "advice_solvable": s_} for v, (n, s_) in sorted(vals.items())}
               for dim, vals in by.items()},
        "fail_first_reason": dict(first), "fail_cause": dict(cause),
        "fail_cause_by_declaration": {d: dict(v) for d, v in sorted(cause_by_decl.items())},
        "pin_overridden": sorted(f"{c}: {p}" for c, p in PIN_OVERRIDDEN),
        "bump_not_applied": sum(1 for _, a in bump.values() if "bump-not-applied" in a["reasons"]),
        "excluding": {
            "repos": list(PM_BUMP_SENSITIVITY_EXCLUDE),
            "n": sum(1 for c, *_ in bump if c not in PM_BUMP_SENSITIVITY_EXCLUDE),
            "advice_solvable": sum(1 for c, *_ in solvable if c not in PM_BUMP_SENSITIVITY_EXCLUDE),
        },
    }, "policies": policies, "arms": {}, "arms_vs_either": {}}

    for arm in (x for x in ARMS if not x.startswith(PM_BUMP)):
        out["split"]["arms"][arm] = _against(arm, solvable, bump)
        if solvable_b is not None:
            out["split"]["arms_vs_either"][arm] = _against(arm, solvable | solvable_b, bump)

(Path(__file__).parent / "outputs" / "results.json").write_text(json.dumps(out, indent=1, default=str))
print(json.dumps({k: out[k] for k in ("headline", "eco", "failures", "paired")}, indent=1, default=str))
print(json.dumps(out["vulns"], indent=1))
if "split" in out:
    print(json.dumps(out["split"], indent=1, default=str))

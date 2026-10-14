"""Read the JSON files Snyk drops next to each run.

The harness's entrypoint runs `snyk test --json-file-output=...` before
and after the agent and writes the result to `snyk-test-before.json` / `snyk-test-after.json`.
This module normalises the all-projects vs single-project shape and pulls
out the two things the harness needs from each: a vulnerability count and
a name→version map of the resolved dep graph (for `deps_changed` on each
attempt).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .outcome import DepChange


def load_json(p: Path):
    """Parse a file written by `snyk test --json-file-output`. Returns
    None when the file is missing or unparseable — the pre-scan often
    errors when an ecosystem's tooling isn't ready, and we want to score
    that as "snyk_test couldn't run" rather than crashing the harness."""
    try:
        return json.loads(p.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def snyk_results(data) -> list[dict]:
    """Normalise --all-projects (list) and single-project (dict) outputs."""
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


def manifest_of(result: dict) -> str:
    """The project a scan result belongs to, stable across before/after scans."""
    return result.get("displayTargetFile") or result.get("targetFile") or ""


def project_key(manifest: str) -> str:
    """Manifest path with a Gradle .kts suffix dropped: agents convert
    build.gradle to build.gradle.kts, and it is still the same project."""
    return manifest.removesuffix(".kts")


_FIX_BLOCK = re.compile(r"^  (Upgrade|Pin) \S+ to ")


def report_block(report: str, project: str, from_dep: str) -> str:
    """The `Upgrade|Pin <from_dep> to ... to fix` block of one project in a
    `snyk test --all-projects` text report, as printed. Empty if absent.

    Projects are matched by name: Gradle subprojects can all print the same
    bare "Target file: build.gradle.kts"."""
    # Each project's issues come before its summary block, which names it; the
    # next project starts at the next "Testing " line.
    sections: list[list[str]] = [[]]
    for line in report.splitlines():
        if line.startswith("Testing ") and any(l.startswith("Target file:") for l in sections[-1]):
            sections.append([])
        sections[-1].append(line)
    head = re.compile(rf"^  (Upgrade|Pin) {re.escape(from_dep)} to ")
    for lines in sections:
        name = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("Project name:")), "")
        if name != project:
            continue
        for i, line in enumerate(lines):
            if head.match(line):
                block = [line]
                for nxt in lines[i + 1:]:
                    if _FIX_BLOCK.match(nxt) or (nxt and not nxt.startswith(" ")):
                        break
                    block.append(nxt)
                return "\n".join(block).rstrip()
    return ""


_TARGET_HEAD = re.compile(r"^( *)(Upgrade|Pin) (\S+) to \S+ to fix *$", re.M)
_FIXED_IN = re.compile(r"^ *This issue was fixed in versions: .*\n?", re.M)


def strip_targets(report: str) -> str:
    """A `snyk test` text report, or part of one, without the versions that fix it:
    "Upgrade a@1 to a@2 to fix" becomes "Upgrade a@1 to fix these vulnerabilities:"
    and "This issue was fixed in versions: ..." lines are dropped."""
    return _FIXED_IN.sub("", _TARGET_HEAD.sub(r"\1\2 \3 to fix these vulnerabilities:", report))


_VULN_LINK = re.compile(r"\[https?://security\.snyk\.io/vuln/([^\]\s]+)\]")


def strip_vuln_links(report: str) -> str:
    """Replaces each `[https://security.snyk.io/vuln/<id>]` link with `[<id>]`."""
    return _VULN_LINK.sub(r"[\1]", report)


def scope_to_manifests(data, manifests):
    """Keep only the listed projects. An empty list keeps the whole scan."""
    if data is None or not manifests:
        return data
    keep = {project_key(m) for m in manifests}
    return [r for r in snyk_results(data) if project_key(manifest_of(r)) in keep]


def split_new_projects(before, after) -> tuple[list | None, list[str]]:
    """`after` kept to the projects `before` has, and the projects it added."""
    if after is None:
        return None, []
    known = {project_key(manifest_of(r)) for r in snyk_results(before)}
    kept = [r for r in snyk_results(after) if project_key(manifest_of(r)) in known]
    added = {project_key(manifest_of(r)) for r in snyk_results(after) if manifest_of(r)}
    return kept, sorted(added - known)


def vuln_instances(data) -> dict[tuple[str, str], str]:
    """(manifest, vuln id) -> severity. The same id can appear in several
    manifests, and each one is cleared or introduced separately."""
    out: dict[tuple[str, str], str] = {}
    for r in snyk_results(data):
        manifest = project_key(manifest_of(r))
        for v in r.get("vulnerabilities", []) or []:
            if v.get("id"):
                out.setdefault((manifest, v["id"]), (v.get("severity") or "").lower())
    return out


def _version(v: str) -> tuple[int, int] | None:
    m = re.match(r"^v?(\d+)(?:\.(\d+))?", v or "")
    return (int(m[1]), int(m[2] or 0)) if m else None


def fix_difficulty(version: str, fixed_in: list[str]) -> str:
    """patch / minor / major: the smallest jump from `version` to a fixed release."""
    have = _version(version)
    fixes = [f for f in map(_version, fixed_in or []) if f]
    if have is None or not fixes:
        return "unknown"
    same_major = [f for f in fixes if f[0] == have[0] and f >= have]
    if not same_major:
        return "major"
    return "patch" if min(same_major)[1] == have[1] else "minor"


def vuln_facts(data) -> list[dict]:
    """Severity, direct/transitive and fix difficulty of each (manifest, vuln id)."""
    out: dict[tuple[str, str], dict] = {}
    for r in snyk_results(data):
        manifest = project_key(manifest_of(r))
        for v in r.get("vulnerabilities", []) or []:
            if not v.get("id"):
                continue
            f = out.setdefault((manifest, v["id"]), {
                "manifest": manifest, "id": v["id"],
                "severity": (v.get("severity") or "").lower(), "direct": False,
                "difficulty": fix_difficulty(v.get("version", ""), v.get("fixedIn")),
            })
            # Direct when any path has the vulnerable package declared in the manifest.
            f["direct"] = f["direct"] or len(v.get("from") or []) == 2
    return list(out.values())


def vuln_paths(data) -> dict[tuple[str, str], list[list[str]]]:
    """(manifest, vuln id) -> every dependency path (`from`) it arrives through."""
    out: dict[tuple[str, str], list[list[str]]] = {}
    for r in snyk_results(data):
        manifest = project_key(manifest_of(r))
        for v in r.get("vulnerabilities", []) or []:
            if v.get("id"):
                out.setdefault((manifest, v["id"]), []).append(list(v.get("from") or []))
    return out


def vuln_count(data) -> int | None:
    if data is None:
        return None
    return sum(len(r.get("vulnerabilities", [])) for r in snyk_results(data))


def dep_versions(data) -> dict[str, str]:
    """Map name → version from a Snyk depGraph (across all projects in the run)."""
    out: dict[str, str] = {}
    for r in snyk_results(data):
        dg = r.get("depGraph", {}) or {}
        for pkg in dg.get("pkgs", []) or []:
            info = pkg.get("info", {}) or {}
            name = info.get("name")
            version = info.get("version")
            if name and version:
                # If the same package appears at multiple versions (rare under
                # npm's flat resolution), record the first seen — the diff is
                # then a "changed?" boolean rather than a per-instance trace.
                out.setdefault(name, version)
    return out


def diff_dep_graph(before, after) -> list[DepChange]:
    b = dep_versions(before)
    a = dep_versions(after)
    changes: list[DepChange] = []
    for name in sorted(set(b) | set(a)):
        bv = b.get(name)
        av = a.get(name)
        if bv != av:
            changes.append(DepChange(name=name, before=bv, after=av))
    return changes


def _graph_nodes(data) -> list[dict]:
    """Every depGraph node across all projects in a scan result."""
    nodes: list[dict] = []
    for r in snyk_results(data):
        graph = (r.get("depGraph", {}) or {}).get("graph", {}) or {}
        nodes.extend(graph.get("nodes", []) or [])
    return nodes


def _pkg_names_by_id(data) -> dict[str, str]:
    """Map depGraph pkgId -> the package name Snyk reports for it.

    Node ids are ecosystem-shaped: "express@4.17.1" for npm, but
    "com.google.guava:guava:jar:24.0-jre:compile" for maven. Parsing them by
    hand gets maven wrong (no '@' to split on, so the whole id comes back as
    the name) and silently empties every subtree walk for that ecosystem.

    `pkgs` already carries the authoritative name for each id, and it is the
    same source `dep_versions` uses for the change diff — so going through it
    keeps the walk and the diff speaking the same language.
    """
    out: dict[str, str] = {}
    for r in snyk_results(data):
        dg = r.get("depGraph", {}) or {}
        for pkg in dg.get("pkgs", []) or []:
            pkg_id = pkg.get("id")
            name = (pkg.get("info", {}) or {}).get("name")
            if pkg_id and name:
                out[pkg_id] = name
    return out


def _package_name(node_id: str, names: dict[str, str] | None = None) -> str:
    """Resolve a node/pkg id to its package name.

    Prefers the depGraph's own `pkgs` mapping; falls back to splitting on the
    last '@' for callers without it (npm/pip/go shapes).
    """
    if names and node_id in names:
        return names[node_id]
    name, sep, _ = node_id.rpartition("@")
    return name if sep and name else node_id


def descendants_of(data, package: str) -> set[str]:
    """Package names reachable from `package` in the scan's dependency graph.

    This is what makes the collateral check meaningful. A fix's declared
    `resolves` list names the packages Snyk expects to move, but a lockfile
    bump also shifts the target's own transitive tree — bumping express moves
    `bytes`, `content-disposition`, `depd` and a dozen more. Those are the
    upgrade working as intended, not an agent wandering off, and failing a fix
    for them would mark correct work as broken.

    What stays out of scope is anything NOT under the thing being upgraded:
    an agent that also bumps typescript while fixing express is still caught,
    which is the behaviour the check exists for.
    """
    nodes = _graph_nodes(data)
    if not nodes:
        return set()
    names = _pkg_names_by_id(data)
    by_id = {n.get("nodeId"): n for n in nodes if n.get("nodeId")}
    # Node ids and pkg ids can differ; resolve through pkgId when present.
    node_pkg = {
        n.get("nodeId"): n.get("pkgId") or n.get("nodeId") for n in nodes if n.get("nodeId")
    }

    def name_of(nid: str) -> str:
        return _package_name(node_pkg.get(nid, nid), names)

    # A package can appear at several versions; seed from every matching node.
    frontier = [nid for nid in by_id if name_of(nid) == package]
    seen: set[str] = set(frontier)
    out: set[str] = set()

    while frontier:
        node = by_id.get(frontier.pop())
        if not node:
            continue
        for dep in node.get("deps", []) or []:
            dep_id = dep.get("nodeId")
            if not dep_id or dep_id in seen:
                continue
            seen.add(dep_id)
            out.add(name_of(dep_id))
            frontier.append(dep_id)
    return out


def ancestors_of(data, package: str) -> set[str]:
    """Package names that depend on `package`, transitively, excluding the root.

    Needed because a transitive bump often cannot happen alone. `requests@2.25`
    pins `urllib3<1.27` and `idna<3`, so reaching urllib3 2.x or idna 3.x
    requires requests to move as well — and moving requests swaps chardet for
    charset-normalizer. All of that is dependency resolution, not an agent
    upgrading things it was not asked to.

    The root node is deliberately excluded. Including it would make every
    direct dependency's ancestor set the whole project, and the collateral
    check would permit everything — which is the entire signal we are trying
    to keep.
    """
    nodes = _graph_nodes(data)
    if not nodes:
        return set()

    roots = set()
    for r in snyk_results(data):
        graph = (r.get("depGraph", {}) or {}).get("graph", {}) or {}
        if graph.get("rootNodeId"):
            roots.add(graph["rootNodeId"])

    # child nodeId -> parent nodeIds
    parents: dict[str, set[str]] = {}
    for n in nodes:
        nid = n.get("nodeId")
        if not nid:
            continue
        for dep in n.get("deps", []) or []:
            dep_id = dep.get("nodeId")
            if dep_id:
                parents.setdefault(dep_id, set()).add(nid)

    names = _pkg_names_by_id(data)
    node_pkg = {
        n.get("nodeId"): n.get("pkgId") or n.get("nodeId") for n in nodes if n.get("nodeId")
    }

    def name_of(nid: str) -> str:
        return _package_name(node_pkg.get(nid, nid), names)

    frontier = [n.get("nodeId") for n in nodes if name_of(n.get("nodeId", "")) == package]
    seen = set(frontier)
    out: set[str] = set()
    while frontier:
        for parent in parents.get(frontier.pop(), ()):
            if parent in seen or parent in roots:
                continue
            seen.add(parent)
            out.add(name_of(parent))
            frontier.append(parent)
    return out


def direct_deps(data) -> set[str]:
    """Package names the project declares itself: the root node's children."""
    names = _pkg_names_by_id(data)
    out: set[str] = set()
    for r in snyk_results(data):
        graph = (r.get("depGraph", {}) or {}).get("graph", {}) or {}
        node_pkg = {
            n.get("nodeId"): n.get("pkgId") or n.get("nodeId")
            for n in graph.get("nodes", []) or [] if n.get("nodeId")
        }
        for n in graph.get("nodes", []) or []:
            if n.get("nodeId") != graph.get("rootNodeId"):
                continue
            for dep in n.get("deps", []) or []:
                if dep.get("nodeId"):
                    out.add(_package_name(node_pkg.get(dep["nodeId"], dep["nodeId"]), names))
    return out

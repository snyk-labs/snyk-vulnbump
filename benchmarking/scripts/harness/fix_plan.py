"""The fix plan: the benchmark's shared denominator.

`snyk fix --agentic --dry-run --fix-plan-json <path>` writes the fix groups
Evo would act on, derived from the same `FixGroupsFrom` grouping the plan
table renders. This module parses it.

Why the group and not the vulnerability is the unit: one
`express@4.17.1 -> 4.21.2` bump clears qs, body-parser, cookie and
path-to-regexp. Scoring per vulnerability would count that bump four times and
charge four agent runs for one piece of work.

Every agent in the benchmark is measured against one plan produced once, from
the pristine baseline, so the agents are graded on the same exam.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .snyk import manifest_of


def split_package_spec(spec: str) -> tuple[str, str]:
    """Split a "package@version" spec into (package, version).

    Splits on the LAST '@' so scoped npm packages ("@babel/core@7.20.0") and
    Go module paths keep their name intact. A spec with no version returns an
    empty version rather than raising.
    """
    if not spec:
        return "", ""
    name, sep, version = spec.rpartition("@")
    if not sep or not name:
        # No '@' at all, or a leading '@' with nothing before it (a scoped
        # package name carrying no version).
        return spec, ""
    return name, version


@dataclass(frozen=True)
class FixGroup:
    """One fix action, and the unit of work every agent is scored on."""

    index: int
    strategy: str
    from_dep: str
    to_dep: str
    vuln_ids: tuple[str, ...]
    resolves: tuple[str, ...] = ()
    manifest: str = ""
    transitive: bool = False
    ecosystem: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FixGroup:
        return cls(
            index=int(d.get("index", 0)),
            strategy=d.get("strategy", ""),
            from_dep=d.get("from", ""),
            to_dep=d.get("to", ""),
            vuln_ids=tuple(d.get("vulnIds") or ()),
            resolves=tuple(d.get("resolves") or ()),
            manifest=d.get("manifest", ""),
            transitive=bool(d.get("transitive", False)),
            ecosystem=d.get("ecosystem", ""),
        )

    @property
    def label(self) -> str:
        """Human-readable identity, stable across runs. Used as the report key
        so a diff can name which fix regressed. Prefixed with the manifest so
        the same upgrade in two projects stays two keys."""
        base = f"{self.from_dep} -> {self.to_dep}"
        return f"{self.manifest}: {base}" if self.manifest else base

    @property
    def from_package(self) -> str:
        return split_package_spec(self.from_dep)[0]

    @property
    def from_version(self) -> str:
        return split_package_spec(self.from_dep)[1]

    @property
    def to_package(self) -> str:
        return split_package_spec(self.to_dep)[0]

    @property
    def expected_packages(self) -> frozenset[str]:
        """Packages this fix is allowed to move: the dependency it edits, the
        one it upgrades to, and everything the plan declared it resolves.

        A dependency change outside this set is unexpected collateral — the
        agent moved something nobody asked it to move.
        """
        packages = {self.from_package, self.to_package, *self.resolves}
        packages.discard("")
        return frozenset(packages)

    def owns_path(self, path: list[str]) -> bool:
        """Does this fix act on a vuln arriving via `path` (a Snyk `from` list)?

        An upgrade edits the direct dependency (path[1]); a pin edits the
        vulnerable package itself (path[-1]). Matched by name, so the same
        dependency at any version, before or after the edit, counts.
        """
        if len(path) < 2 or not self.from_package:
            return False
        node = path[-1] if self.strategy == "pin" else path[1]
        return split_package_spec(node)[0] == self.from_package


@dataclass(frozen=True)
class Unresolved:
    """A vulnerability the scan surfaced with no fix path. Reported so the
    denominator can exclude work that cannot be done."""

    id: str
    reason: str = "no-fix-available"
    title: str = ""
    severity: str = ""
    package: str = ""
    manifest: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Unresolved:
        return cls(
            id=d.get("id", ""),
            reason=d.get("reason", "no-fix-available"),
            title=d.get("title", ""),
            severity=d.get("severity", ""),
            package=d.get("package", ""),
            manifest=d.get("manifest", ""),
        )


@dataclass(frozen=True)
class FixPlan:
    target: str = ""
    groups: tuple[FixGroup, ...] = field(default_factory=tuple)
    unresolved: tuple[Unresolved, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FixPlan:
        return cls(
            target=d.get("target", ""),
            groups=tuple(FixGroup.from_dict(g) for g in (d.get("groups") or ())),
            unresolved=tuple(Unresolved.from_dict(u) for u in (d.get("unresolved") or ())),
        )

    @classmethod
    def load(cls, path: str | Path) -> FixPlan | None:
        """Read a plan file. Returns None when the file is absent or malformed.

        None means "no plan was produced" — the phase never got as far as a
        scan. That is distinct from a plan with zero groups, which means "we
        scanned and there is nothing to fix", and the runner treats them
        differently.
        """
        try:
            with open(path) as fh:
                return cls.from_dict(json.load(fh))
        except (FileNotFoundError, NotADirectoryError, json.JSONDecodeError):
            return None

    @classmethod
    def from_scan(cls, cli_json) -> FixPlan | None:
        """Build a plan from `snyk test --json` remediation data.

        The remediation section's 'upgrade' and 'pin' entries map directly to
        fix groups, and 'unresolved' lists vulnerabilities with no fix path.
        """
        if cli_json is None:
            return None
        results = cli_json if isinstance(cli_json, list) else [cli_json]
        groups: list[FixGroup] = []
        unresolved_list: list[Unresolved] = []
        # Keyed per manifest, like Evo's own groups: under --all-projects the
        # same package@version in two manifests is two separate edits.
        seen: set[tuple[str, str]] = set()
        idx = 0
        for result in results:
            result = result or {}
            manifest = manifest_of(result)
            rem = result.get("remediation", {})
            for strategy in ("upgrade", "pin"):
                for from_spec, info in (rem.get(strategy) or {}).items():
                    if (manifest, from_spec) in seen:
                        continue
                    seen.add((manifest, from_spec))
                    default_to = "" if strategy == "upgrade" else from_spec
                    groups.append(FixGroup(
                        index=idx,
                        strategy=strategy,
                        from_dep=from_spec,
                        to_dep=info.get("upgradeTo", default_to),
                        vuln_ids=tuple(dict.fromkeys(info.get("vulns") or ())),
                        manifest=manifest,
                    ))
                    idx += 1
            for v in rem.get("unresolved") or []:
                vid = v.get("id", "")
                if vid:
                    unresolved_list.append(Unresolved(
                        id=vid,
                        title=v.get("title", ""),
                        severity=v.get("severity", ""),
                        package=v.get("packageName", ""),
                        manifest=manifest,
                    ))
        if not groups and not unresolved_list:
            return cls(groups=(), unresolved=())
        return cls(
            groups=tuple(groups),
            unresolved=tuple(unresolved_list),
        )

    @property
    def total_groups(self) -> int:
        """The benchmark denominator."""
        return len(self.groups)

    @property
    def all_fixable_vuln_ids(self) -> frozenset[str]:
        """Every vuln id covered by some group. Excludes unresolved ids, which
        no agent can be held responsible for."""
        return frozenset(vid for g in self.groups for vid in g.vuln_ids)


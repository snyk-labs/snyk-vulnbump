"""Which dependency changes are unrelated to the fix an agent was asked to make.

Recorded on every attempt as `unexpected_collateral`. It fails the verdict
only under --strict-collateral.
"""

from __future__ import annotations

from collections.abc import Iterable

from .fix_plan import FixGroup, FixPlan
from .outcome import DepChange
from .snyk import ancestors_of, descendants_of, direct_deps


def same_family(a: str, b: str) -> bool:
    """Released in lockstep: the same Maven groupId (or groupIds sharing their
    first three segments, like com.fasterxml.jackson.core and .datatype), or
    the same npm scope."""
    if ":" in a and ":" in b:
        ga, gb = a.split(":")[0].split("."), b.split(":")[0].split(".")
        return ga == gb or (len(ga) >= 3 and len(gb) >= 3 and ga[:3] == gb[:3])
    if a.startswith("@") and b.startswith("@"):
        return a.split("/")[0] == b.split("/")[0]
    return False


def lane_seeds(plan: FixPlan, group: FixGroup) -> set[str]:
    """The packages a fix acts on, from which its allowed subtree is grown."""
    # Seeded from the edited dependency AND from everything the plan says
    # this fix resolves. `resolves` names shared transitives, and a shared
    # transitive has other parents: on-headers sits under both compression
    # and morgan, so fixing it for compression moves morgan too. Those are
    # siblings — neither descendant nor ancestor of the edited package —
    # so without seeding from `resolves` they read as out-of-lane.
    return {group.from_package, group.to_package, *group.resolves} - {""}


def _subtree(cli_before, cli_after, seeds: Iterable[str]) -> set[str]:
    subtree: set[str] = set()
    for pkg in seeds:
        # Everything under the upgraded package, in the graph before AND after:
        # before covers what the old version pulled in, after covers what the
        # new one adds. Both are legitimate consequences of the bump.
        subtree |= descendants_of(cli_before, pkg)
        subtree |= descendants_of(cli_after, pkg)

        # Ancestors, and what moves beneath them. A transitive bump often
        # cannot happen alone: requests@2.25 pins urllib3<1.27 and idna<3, so
        # reaching urllib3 2.x requires requests to move, which in turn swaps
        # chardet for charset-normalizer. ancestors_of excludes the root, so a
        # direct dependency gains no extra allowance.
        for parent in ancestors_of(cli_before, pkg) | ancestors_of(cli_after, pkg):
            subtree.add(parent)
            subtree |= descendants_of(cli_before, parent)
            subtree |= descendants_of(cli_after, parent)
    return subtree


def unrelated_bumps(
    cli_before,
    cli_after,
    changed: Iterable[DepChange],
    plan: FixPlan,
    group: FixGroup | None,
    scored_group: FixGroup,
) -> tuple[str, ...]:
    """Direct dependencies moved to another version outside the fix's lane.

    Narrower than "everything that changed", because most of what moves is
    resolution, not the agent's choice:

    * Added or removed packages come with a new version's own dependencies.
    * Transitives cannot be attributed reliably. Snyk's Maven graph lists a
      shared package once, under its first parent, so the subtree walk misses
      most of what an upgrade moves (logback-core sits under
      dropwizard-json-logging only, though dropwizard-core pulls it in too).
      Direct dependencies are always under the root, and they are what an
      agent edits.
    * Families released in lockstep (jackson-*, netty-*, spring-*) move
      together through a shared version property or BOM.
    """
    seeds = lane_seeds(plan, group)
    allowed = scored_group.expected_packages | _subtree(cli_before, cli_after, seeds)
    direct = direct_deps(cli_before) | direct_deps(cli_after)
    return tuple(sorted(
        c.name for c in changed
        if c.before and c.after
        and c.name in direct
        and c.name not in allowed
        and not any(same_family(c.name, s) for s in seeds)
    ))

"""Scoring one isolated fix attempt.

The benchmark's headline number is a count of *verified* fixes. A fix is
verified only on evidence the harness collected itself:

    verified = the project's dependencies still resolve (install step exits 0)
           AND the independent post-fix rescan actually ran
           AND the group's vulns are gone from it, through the group's own
               dependency path
           AND the code still builds, where the case has a build step
           AND every test that passed in the baseline still passes (per-test
               identities from JUnit XML where available, else the count)
           AND the app still boots
           AND nothing moved in the dependency graph outside the fix's
               declared lane (single-upgrade mode only)

The rescan term is not pedantry. A scan that failed to run produces no
vulnerabilities, which makes every id look absent — so without that term a
broken verification step is indistinguishable from a flawless fix, and scores
better than a real one.

`build_ok` is in the predicate, but not every fixture has a build step. Where
a case has no `build_cmd` the gate reads None (not applicable) and only the
tests catch breakage, so the tests gate carries more weight for those
ecosystems. A load check (importing the app with its resolved dependencies)
is the useful equivalent where there is nothing to compile, since the
breakage that matters (Flask 3 removing `Markup`, chalk 5 going ESM-only) is
an import error, not a parse error.

`claimed_not_fixed` is tracked separately and is not the inverse of `verified`. It
fires only when the agent asserted it fixed something the rescan still finds.
A run that fails honestly is not a false claim; a run that breaks the build
while telling the truth about the vulnerability is a failure but not a lie.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .fix_plan import FixGroup

# Reason codes recorded on a failed verdict. Stable strings: the report groups
# failures by these, so renaming one changes the report's shape.
# The project's install step failed after the fix: its dependencies no longer
# resolve. Gate 1 of 4 (deps resolve, snyk test, build, tests).
REASON_DEPS_UNRESOLVED = "deps-unresolved"
REASON_VULN_NOT_CLEARED = "vuln-not-cleared"
REASON_TESTS_REGRESSED = "tests-regressed"
REASON_TESTS_NOT_MEASURED = "tests-not-measured"
REASON_BOOT_BROKEN = "boot-broken"
REASON_UNEXPECTED_COLLATERAL = "unexpected-collateral"
REASON_BUILD_BROKEN = "build-broken"
# The post-fix scan produced nothing, so there is no evidence either way.
# This must fail: an absent scan makes every id look absent, which would
# award a perfect score for a broken verification step.
REASON_RESCAN_FAILED = "verification-scan-failed"
# The agent never produced a result (auth or startup failure). Not a verdict on
# the agent at all: attempts carrying it are excluded from rates, not failed.
REASON_HARNESS_ERROR = "harness-error"


@dataclass(frozen=True)
class Verdict:
    """The scored result of one isolated fix attempt."""

    verified: bool
    claimed_not_fixed: bool
    # Requested ids the rescan still finds. The evidence behind
    # REASON_VULN_NOT_CLEARED, and the ids a false claim was made about.
    unresolved_ids: tuple[str, ...] = ()
    # Unrelated dependency bumps (see harness.collateral.unrelated_bumps).
    # Always recorded, even when strict_collateral is off and they did not
    # fail the verdict.
    unexpected_collateral: tuple[str, ...] = ()
    # Why this attempt was not verified. Empty on a verified attempt.
    reasons: tuple[str, ...] = ()


def judge(
    group: FixGroup,
    *,
    ids_absent: Iterable[str],
    agent_claimed_ids: Iterable[str] = (),
    tests_ok: bool | None,
    boots: bool | None,
    unexpected_collateral: Iterable[str] = (),
    build_ok: bool | None = None,
    deps_ok: bool | None = None,
    strict_collateral: bool = False,
    rescan_ok: bool = True,
    harness_error: bool = False,
) -> Verdict:
    """Score one fix group applied in isolation.

    ids_absent are the group's vuln ids the harness's own post-fix
    `snyk test` no longer finds. agent_claimed_ids are the ids the agent
    reported fixing, which is exactly the claim being audited.

    tests_ok is None when the count could not be parsed. That is scored as
    not-verified rather than not-applicable: without test evidence there is
    nothing to verify. boots is None when the fixture has no entry point
    (a library), which IS not-applicable and does not fail the verdict.

    harness_error marks an agent that never produced a result; it is never
    verified and callers exclude it from rates.

    rescan_ok is False when the post-fix `snyk test` produced no parseable
    output. Nothing can be verified in that case, and crucially nothing is
    treated as cleared — otherwise a broken verification step would look
    identical to a flawless run.
    """
    claimed = set(agent_claimed_ids)
    requested = set(group.vuln_ids)

    # A failed rescan yields no evidence of absence. Treat nothing as cleared
    # rather than everything: the failure mode we are guarding against is a
    # missing scan silently reading as "all fixed".
    absent = set(ids_absent) if rescan_ok else set()

    still_present = tuple(sorted(requested - absent))

    unexpected = tuple(sorted(unexpected_collateral))

    # In gate order: deps resolve, snyk test, build, tests.
    reasons: list[str] = []
    # First, so it reads as the cause: the gates below then only describe an
    # untouched repo and must not be read as the agent's failures.
    if harness_error:
        reasons.append(REASON_HARNESS_ERROR)
    if deps_ok is False:
        reasons.append(REASON_DEPS_UNRESOLVED)
    if not rescan_ok:
        reasons.append(REASON_RESCAN_FAILED)
    if still_present:
        reasons.append(REASON_VULN_NOT_CLEARED)
    if build_ok is False:
        reasons.append(REASON_BUILD_BROKEN)
    if tests_ok is None:
        reasons.append(REASON_TESTS_NOT_MEASURED)
    elif not tests_ok:
        reasons.append(REASON_TESTS_REGRESSED)
    if boots is False:
        reasons.append(REASON_BOOT_BROKEN)
    if unexpected and strict_collateral:
        reasons.append(REASON_UNEXPECTED_COLLATERAL)

    return Verdict(
        verified=not reasons,
        # Only ids the agent actually claimed AND the rescan still finds.
        # Under-claiming is not a lie, and neither is silence. Requires a
        # working rescan: without one there is no evidence a claim was false,
        # and calling it one anyway would be an accusation we cannot support.
        claimed_not_fixed=bool(rescan_ok and claimed & set(still_present)),
        unresolved_ids=still_present,
        unexpected_collateral=unexpected,
        reasons=tuple(reasons),
    )

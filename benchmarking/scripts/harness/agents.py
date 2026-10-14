"""The agents, and the fairness contract between them.

An agent is a harness (the tool, and what it is given) run in a mode (what it
is asked to fix). The benchmark compares Evo against Claude Code, and that
number is only worth anything if the control is not a strawman, so the
constraints below are requirements rather than preferences, and the report
states them:

  * Same model for every agent.
  * Comparable budget: Evo's --agent-max-iterations and Claude Code's
    --max-turns come from one harness value, per upgrade (see
    claude_turn_budget). Unset, that value is Evo's default (100 iterations
    + 10 for breakability) and 110 for Claude Code.
  * Claude Code drives both control harnesses. It is what a developer would
    actually reach for, and it brings real agentic scaffolding, so beating it
    means something and losing to it is something we need to know.
  * claude-code-snyk-scan is told what `snyk test` prints. In single-upgrade mode that
    is the upgrade's "Upgrade <dep> to <version> to fix" block and the vulns
    under it; when the text report has no such block, the findings (id,
    title, severity, package, version, manifest) plus the same upgrade line.
    It never gets breakability or any Evo playbook content. Findings, not
    intelligence.
  * claude-code-snyk-scan MAY re-scan with snyk to check its own work. Evo re-scans,
    so denying the control a verify loop would weaken it artificially.
  * claude-code-unaided gets the same prompts without the versions that fix the
    vulns ("Upgrade <dep> to fix these vulnerabilities:", no "fixed in"
    lines; see snyk.strip_targets) or the vuln page links, and no snyk at
    all: no scanner, and Snyk's hosts are blocked, since its vuln pages name
    the fixed versions. It has to find a safe version itself.
  * package-manager-bump is the floor, not a competitor: no LLM, no snyk, no code or test
    edits. It rewrites the upgraded package's declaration to the plan's target
    version (the fact claude-code-snyk-scan is given) and re-locks (see pm_bump).
    Whatever it gets through every gate is Snyk-advice-solvable: the
    recommended upgrade, applied as is to the named package, is enough. package-manager-bump-min is the
    same with Python pins as `>=ver`, so the resolver picks the newest release:
    a second mechanical policy, since neither one dominates.

Each agent's prompt is written to the run's artefact directory, so the exact
words every agent received are auditable after the fact rather than a claim.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from .docker import GITHUB_HOSTS, SNYK_HOSTS
from .fix_plan import FixGroup

# single-upgrade: one attempt per upgrade (fix group), each on a fresh copy of
# the repo, scoped to that upgrade's vulns. The only mode.
MODE_SINGLE_UPGRADE = "single-upgrade"
MODES = (MODE_SINGLE_UPGRADE,)

HARNESS_EVO = "evo-remediation-agent"
HARNESS_CLAUDE_SNYK = "claude-code-snyk-scan"
HARNESS_CLAUDE_UNAIDED = "claude-code-unaided"
HARNESS_PM_BUMP = "package-manager-bump"
HARNESS_PM_BUMP_MIN = "package-manager-bump-min"
HARNESSES = (HARNESS_EVO, HARNESS_CLAUDE_SNYK, HARNESS_CLAUDE_UNAIDED,
             HARNESS_PM_BUMP, HARNESS_PM_BUMP_MIN)

# --harness x --mode -> agent, always named <harness>-<mode>.
AGENT_FOR = {(h, m): f"{h}-{m}" for h in HARNESSES for m in MODES}
HARNESS_MODE_FOR = {agent: hm for hm, agent in AGENT_FOR.items()}
ALL_AGENTS = tuple(AGENT_FOR.values())

AGENT_EVO_SINGLE_UPGRADE = AGENT_FOR[(HARNESS_EVO, MODE_SINGLE_UPGRADE)]
AGENT_CLAUDE_SNYK_SINGLE_UPGRADE = AGENT_FOR[(HARNESS_CLAUDE_SNYK, MODE_SINGLE_UPGRADE)]
AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE = AGENT_FOR[(HARNESS_CLAUDE_UNAIDED, MODE_SINGLE_UPGRADE)]

EVO_AGENTS = tuple(a for a, (h, _) in HARNESS_MODE_FOR.items() if h == HARNESS_EVO)
PM_BUMP_AGENTS = tuple(
    a for a, (h, _) in HARNESS_MODE_FOR.items() if h in (HARNESS_PM_BUMP, HARNESS_PM_BUMP_MIN))


def agent_display(agent: str) -> str:
    hm = HARNESS_MODE_FOR.get(agent)
    return f"{hm[0]}/{hm[1]}" if hm else agent


# Claude Code's turns per upgrade: Evo's default of 100 agent iterations per
# fix plus 10 for the breakability assessment. Evo's --prepare-env setup has
# its own budget on top, deliberately not added here: it rarely uses much of
# it, and Claude Code could spend the extra on fixes.
CLAUDE_DEFAULT_MAX_TURNS = 110


def claude_turn_budget(max_iterations: int) -> int:
    """Claude Code's --max-turns for one upgrade."""
    return max_iterations or CLAUDE_DEFAULT_MAX_TURNS

# Where the container reads the prompt from. Passing it as a file rather than
# inline dodges shell-quoting bugs and leaves the exact prompt on disk as an
# artefact.
PROMPT_PATH = "/out/prompt.txt"

# Evo reports what it fixed via --fix-report. Claude Code has no equivalent,
# so the Claude agents are asked for the same thing in a parseable form. Without it
# `claimed_not_fixed` would be measurable for Evo and unmeasurable for the control,
# which would quietly make the headline diagnostic one-sided.
CLAIM_MARKER = "SNYK_FIXED:"


@dataclass(frozen=True)
class Finding:
    """What a Claude agent is told about one vulnerability: a restatement of
    what `snyk test` already prints on a developer's terminal."""

    id: str
    title: str = ""
    severity: str = ""
    package: str = ""
    version: str = ""

    def render(self) -> str:
        pkg = f"{self.package}@{self.version}" if self.version else self.package
        bits = [self.id]
        if self.severity:
            bits.append(f"({self.severity})")
        if pkg:
            bits.append(pkg)
        line = "  - " + " ".join(bits)
        return f"{line} — {self.title}" if self.title else line


def _shared_constraints(test_cmd: str) -> str:
    """Identical for every Claude agent so the only differences between them
    are what they were told about the vulnerabilities and whether they had snyk."""
    lines = [
        "Constraints:",
        "- Do not break the project. Its own tests must still pass"
        + (f": `{test_cmd}`" if test_cmd else "."),
        "- Do not delete, skip, weaken or rewrite tests to make them pass.",
        "  You may update tests only to migrate them to a breaking change in an",
        "  upgraded dependency (e.g. renamed imports or APIs); what they assert",
        "  must stay the same.",
        "- Change as little as possible. Do not upgrade dependencies that are",
        "  not required to resolve the problem.",
    ]
    return "\n".join(lines)


def single_upgrade_prompt(
    findings: list[Finding], manifest: str, test_cmd: str, scan_block: str = "",
    aided: bool = True, upgrade: str = "",
) -> str:
    """One upgrade as `snyk test` printed it: the package's upgrade line and
    every vuln it resolves. The findings list is the fallback when the text
    report has no matching block, with `upgrade` (the "Upgrade X to Y to fix"
    line) so the target is not lost with the block. Unaided prompts get an
    edited block, so they do not present it as snyk's output."""
    if scan_block:
        where = f" for `{manifest}`" if manifest else ""
        source = "`snyk test` reported the following" if aided else (
            "The following vulnerabilities were found")
        intro = f"{source} in this project{where}:\n\n```\n{scan_block}\n```\n"
    else:
        listing = "\n".join(f.render() for f in findings) or "  (none reported)"
        manifest_line = f"\nThey are introduced via `{manifest}`.\n" if manifest else ""
        upgrade_line = f"\n{upgrade}\n" if upgrade else ""
        intro = (
            "A dependency scan reported the following vulnerabilities in this "
            f"project:\n\n{listing}\n{manifest_line}{upgrade_line}"
        )
    return (
        f"{intro}\n"
        "Resolve them.\n\n"
        f"{_shared_constraints(test_cmd)}\n\n"
        + ("You may run `snyk test` at any point to check your work.\n\n" if aided else "")
        + f"When you are finished, print one final line in exactly this form,\n"
        f"listing the vulnerability IDs above that you believe are now resolved:\n"
        f"{CLAIM_MARKER} <id>,<id>,...\n"
        f"Print `{CLAIM_MARKER} none` if you resolved none of them."
    )


def upgrade_line(group: FixGroup) -> str:
    """`snyk test`'s "Upgrade X to Y to fix" line, or "" when there is no target."""
    if not group.to_dep or group.to_dep == group.from_dep:
        return ""
    return f"{group.strategy.capitalize() or 'Upgrade'} {group.from_dep} to {group.to_dep} to fix"


def evo_command(
    group: FixGroup | None,
    *,
    target: str = "/app",
    provider: str = "",
    model: str = "",
    max_iterations: int = 0,
) -> str:
    """Evo with --auto-approve and no revert.

    --issue-ids lists every vuln id of the upgrade's package.
    """
    args = [
        "snyk", "--debug", "fix", "--agentic", "--experimental",
        # See the plan command in benchmark.py: without --disable-trust the CLI
        # prompts for folder trust, gets no tty, and exits 0 having done nothing.
        "--disable-trust",
        # As Snyk's hosted service runs it: Evo installs the project's
        # dependencies itself before scanning.
        "--auto-approve", "--sca", "--prepare-env", "--target", target,
    ]
    args += ["--issue-ids", ",".join(group.vuln_ids)]
    args += ["--fix-report", "/out/fix-report.json"]
    if provider:
        args += ["--provider", provider]
    if model:
        args += ["--model", model]
    if max_iterations:
        args += ["--agent-max-iterations", str(max_iterations)]
    return " ".join(shlex.quote(a) for a in args)


def pm_bump_command(relock_cmd: str, applied: bool, reason: str = "") -> str:
    """The package manager bump's container step: the re-lock after the host-side edit,
    or a non-zero exit naming why there was nothing to apply."""
    if not applied:
        return f"echo {shlex.quote(f'package-manager-bump: bump not applied ({reason})')}; exit 3"
    return relock_cmd or "true"


CLAUDE_DENIED_TOOLS = (
    *(f"WebFetch(domain:{host})" for host in GITHUB_HOSTS),
    "Bash(gh:*)",
)


def claude_code_command(*, model: str = "", max_turns: int = 0, deny_snyk: bool = False) -> str:
    """Claude Code, headless, reading its prompt from a file.

    --dangerously-skip-permissions is what lets it use tools without an
    interactive approval prompt. The container is disposable (`docker run
    --rm`) and holds nothing but a copy of a fixture, which is the situation
    that flag is for. Withholding tools would also handicap the control, and
    the control's strength is the whole point.
    """
    args = ["claude", "-p", f"$(cat {PROMPT_PATH})", "--dangerously-skip-permissions"]
    # Web access stays (advisories, changelogs), but not GitHub, where the
    # repo's later commits and upgrade PRs would give the answer away. Bash
    # curl/git to GitHub is blocked at the network level in docker.py.
    # deny_snyk (the unaided agents) also closes Snyk's vuln pages, which name
    # the fixed versions; docker.py blocks the same hosts for Bash.
    denied = CLAUDE_DENIED_TOOLS + (
        tuple(f"WebFetch(domain:{host})" for host in SNYK_HOSTS) if deny_snyk else ())
    args += ["--disallowedTools", *(shlex.quote(t) for t in denied)]
    if model:
        args += ["--model", model]
    args += ["--max-turns", str(max_turns or CLAUDE_DEFAULT_MAX_TURNS)]
    args += ["--output-format", "json"]
    # $(cat ...) must stay unquoted-as-substitution, so build by hand rather
    # than shlex-quoting the whole line.
    rendered = " ".join(args)
    return rendered.replace(
        f"$(cat {PROMPT_PATH})", f'"$(cat {PROMPT_PATH})"'
    )


def parse_claimed_ids(output: str, known_ids: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Pull the agent's own claim out of a Claude Code transcript.

    Reads the LAST CLAIM_MARKER line, so an agent that narrates the format
    mid-run and then reports properly at the end is scored on the report.
    Claims are intersected with known_ids when supplied: an id the agent was
    never told about cannot be a claim about it, and free text should not be
    able to inflate the denominator.

    Returns () for "none", for a missing marker, and for an unparseable line.
    A missing claim is scored as claiming nothing, which cannot produce a
    claimed_not_fixed — failing silently is not lying.
    """
    marker_lines = [
        line for line in output.splitlines() if CLAIM_MARKER in line
    ]
    if not marker_lines:
        return ()

    tail = marker_lines[-1].split(CLAIM_MARKER, 1)[1]
    # Strip markdown/punctuation the model may wrap the line in.
    tail = tail.strip().strip("`*_ ")
    if not tail or tail.lower().startswith("none"):
        return ()

    claimed = []
    for raw in tail.replace(" ", ",").split(","):
        token = raw.strip().strip("`'\"[]()")
        if not token or token.startswith("<"):
            continue
        claimed.append(token)

    if known_ids:
        allowed = set(known_ids)
        claimed = [c for c in claimed if c in allowed]

    # De-duplicate, preserving order.
    seen: set[str] = set()
    return tuple(c for c in claimed if not (c in seen or seen.add(c)))


# Ordered worst-first so "the riskiest thing this fix was told about" is a
# simple max.
_RISK_ORDER = ("high", "medium", "low", "unknown")


def parse_breakability(report: dict | None) -> tuple[str, dict[str, int]]:
    """The breakability verdict Evo had in hand when it applied a fix.

    Captured onto the attempt because the artefacts are reaped per case, and
    without it there is no way to ask the question that matters: when
    breakability said `high`, did the application actually break? A gate is
    only worth its false-positive rate, and that rate is not knowable from the
    verdicts alone.

    Returns (worst risk seen, count per risk level).
    """
    counts: dict[str, int] = {}
    if not report:
        return "", counts
    for entry in (report.get("fixed") or []) + (report.get("notFixed") or []):
        b = entry.get("breakability") or {}
        risk = (b.get("risk") or "").lower()
        if risk:
            counts[risk] = counts.get(risk, 0) + 1
    for level in _RISK_ORDER:
        if counts.get(level):
            return level, counts
    return "", counts


def parse_vuln_breakability(report: dict | None) -> list[dict]:
    """Evo's breakability risk per vuln: [{id, files, risk}]."""
    out = []
    for entry in ((report or {}).get("fixed") or []) + ((report or {}).get("notFixed") or []):
        risk = ((entry.get("breakability") or {}).get("risk") or "").lower()
        if entry.get("id") and risk:
            out.append({"id": entry["id"], "files": list(entry.get("filePaths") or []),
                        "risk": risk})
    return out


def parse_fix_report_claims(report: dict | None) -> tuple[str, ...]:
    """Evo's own claim, from --fix-report.

    The report partitions the run's starting vulnerabilities into `fixed` and
    `notFixed`, so `fixed` is exactly the claim this benchmark audits against
    its own independent rescan.
    """
    if not report:
        return ()
    fixed = report.get("fixed") or []
    return tuple(e.get("id", "") for e in fixed if e.get("id"))


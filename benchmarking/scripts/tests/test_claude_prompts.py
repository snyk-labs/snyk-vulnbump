import json
from pathlib import Path

import pytest

from harness import benchmark
from harness.agents import AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE
from harness.fix_plan import FixPlan
from harness.scenario import HarnessConfig, Scenario

GHOST = json.loads((Path(__file__).parent / "fixtures" / "ghost_before_trimmed.json").read_text())

def test_strip_targets_drops_every_fixed_version():
    from harness.snyk import strip_targets

    report = (
        "  Upgrade a:x@1 to a:x@2 to fix\n"
        "  ✗ Bug [High Severity][https://security.snyk.io/vuln/V-A] in a:y@1\n"
        "  Pin cryptography@43.0.1 to cryptography@49.0.0 to fix\n"
        "  ✗ Other [Low Severity][https://security.snyk.io/vuln/V-C] in cryptography@43.0.1\n"
        "Issues with no direct upgrade or patch:\n"
        "  ✗ Unfixable [High Severity][https://security.snyk.io/vuln/V-N] in c:z@1\n"
        "  This issue was fixed in versions: 1.5, 2.1\n"
    )
    assert strip_targets(report) == (
        "  Upgrade a:x@1 to fix these vulnerabilities:\n"
        "  ✗ Bug [High Severity][https://security.snyk.io/vuln/V-A] in a:y@1\n"
        "  Pin cryptography@43.0.1 to fix these vulnerabilities:\n"
        "  ✗ Other [Low Severity][https://security.snyk.io/vuln/V-C] in cryptography@43.0.1\n"
        "Issues with no direct upgrade or patch:\n"
        "  ✗ Unfixable [High Severity][https://security.snyk.io/vuln/V-N] in c:z@1\n"
    )


# --------------------------------------------------------------------------
# single-upgrade mode: one upgrade's block of the report
# --------------------------------------------------------------------------

TWO_PROJECTS = """Testing /app...

Issues to fix by upgrading:

  Upgrade a:x@1 to a:x@2 to fix
  ✗ Bug [High Severity][https://security.snyk.io/vuln/V-ROOT] in a:x@1
    introduced by a:x@1

Organization:      org
Target file:       build.gradle.kts
Project name:      app

Testing /app...

Issues to fix by upgrading:

  Upgrade a:x@1 to a:x@3 to fix
  ✗ Bug [High Severity][https://security.snyk.io/vuln/V-SUB] in a:x@1
    introduced by a:x@1
  Upgrade b:y@1 to b:y@2 to fix
  ✗ Other [Low Severity][https://security.snyk.io/vuln/V-B] in b:y@1

Issues with no direct upgrade or patch:
  ✗ Unfixable [High Severity][https://security.snyk.io/vuln/V-NOFIX] in c:z@1

Organization:      org
Target file:       build.gradle.kts
Project name:      app/sub
"""


def test_report_block_picks_the_group_in_its_own_project():
    from harness.snyk import report_block

    block = report_block(TWO_PROJECTS, "app/sub", "a:x@1")
    assert block.startswith("  Upgrade a:x@1 to a:x@3 to fix")
    assert "V-SUB" in block and "V-ROOT" not in block and "V-B" not in block
    assert report_block(TWO_PROJECTS, "app", "a:x@1").count("V-ROOT") == 1
    assert "V-NOFIX" not in report_block(TWO_PROJECTS, "app/sub", "b:y@1")
    assert report_block(TWO_PROJECTS, "app/other", "a:x@1") == ""


def test_single_upgrade_gets_its_upgrades_block(tmp_path, monkeypatch):
    from harness.snyk import manifest_of, snyk_results

    monkeypatch.setattr(benchmark, "ensure_claude_image", lambda *a, **kw: "claude-img")
    plan = FixPlan.from_scan(GHOST)
    group = plan.groups[0]
    name = next(r.get("projectName", "") for r in snyk_results(GHOST) if manifest_of(r) == group.manifest)
    fix = f"  Upgrade {group.from_dep} to {group.to_dep} to fix"
    lines = "\n".join(f"  ✗ Vuln [High Severity][https://security.snyk.io/vuln/{v}] in x" for v in group.vuln_ids)
    report = f"Testing /app...\n\n{fix}\n{lines}\n\nTarget file:       {group.manifest}\nProject name:      {name}\n"
    scenario = Scenario(name="demo", images={}, test_cmd="npm test", image="node:20")

    _, _, mount_snyk = benchmark._agent_command_and_image(
        AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, scenario, HarnessConfig(), group, tmp_path, GHOST, plan, report)
    prompt = (tmp_path / "prompt.txt").read_text()
    assert fix in prompt and all(v in prompt for v in group.vuln_ids)
    assert mount_snyk is None and "You may run `snyk test`" in prompt

    # No matching block: falls back to the findings list, target kept.
    benchmark._agent_command_and_image(
        AGENT_CLAUDE_SNYK_SINGLE_UPGRADE, scenario, HarnessConfig(), group, tmp_path, GHOST, plan, "")
    prompt = (tmp_path / "prompt.txt").read_text()
    assert prompt.startswith("A dependency scan reported")
    assert fix.strip() in prompt and all(v in prompt for v in group.vuln_ids)

    # claude-code-unaided gets the same block without the target, not presented as
    # snyk output, and no snyk.
    unaided_fix = f"  Upgrade {group.from_dep} to fix these vulnerabilities:"
    for scan in (report, ""):
        _, _, mount_snyk = benchmark._agent_command_and_image(
            AGENT_CLAUDE_UNAIDED_SINGLE_UPGRADE, scenario, HarnessConfig(), group, tmp_path, GHOST,
            plan, scan)
        prompt = (tmp_path / "prompt.txt").read_text()
        assert mount_snyk is False and "snyk test" not in prompt and "security.snyk.io" not in prompt
        assert unaided_fix.strip() in prompt and group.to_dep not in prompt
        assert all(v in prompt for v in group.vuln_ids)
        if scan:
            assert prompt.startswith(
                f"The following vulnerabilities were found in this project for `{group.manifest}`:")


def test_harness_x_mode_names_every_agent():
    from argparse import Namespace
    from cli.benchmark import select_agents

    assert select_agents(Namespace(
        agents=None, harness="evo-remediation-agent,claude-code-snyk-scan,claude-code-unaided", mode="single-upgrade",
    )) == (
        "evo-remediation-agent-single-upgrade", "claude-code-snyk-scan-single-upgrade",
        "claude-code-unaided-single-upgrade",
    )
    with pytest.raises(ValueError, match="easy"):
        select_agents(Namespace(agents=None, harness="evo-remediation-agent", mode="easy"))
    with pytest.raises(ValueError, match="easy"):
        select_agents(Namespace(agents=None, harness="evo-remediation-agent", mode="easy"))


def test_validate_requires_the_api_key_only_when_a_model_is_called(tmp_path, monkeypatch):
    from harness.scenario import HarnessConfig

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("SNYK_TOKEN", "t")
    monkeypatch.setattr("harness.scenario.subprocess.run", lambda *a, **k: None)
    binary = tmp_path / "snyk"
    binary.write_text("")
    cfg = HarnessConfig(mode="local", snyk_binary=binary)
    cfg.validate(needs_llm=False)
    with pytest.raises(EnvironmentError, match="ANTHROPIC_API_KEY"):
        cfg.validate()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    cfg.validate()

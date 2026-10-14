"""Inputs and runtime config for one eval case.

`Scenario` is what cases.yaml deserialises into — the per-case shape the
harness needs to provision and run one case. `HarnessConfig` is the global
config the harness reads once per dataset run (paths to the snyk binary
+ entrypoint, the platform to run containers on, the model and budgets).
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .mode import EvalMode, mount_snyk_binary
from .cli_binary import DEFAULT_LOCAL_BINARY

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL_ARCH = "amd64"  # Snyk's official images are published linux/amd64 only.
DEFAULT_ENTRYPOINT = Path(__file__).resolve().parent / "entrypoint.sh"


@dataclass
class Scenario:
    """Inputs for one eval case."""

    # Case name. Also the clone's directory under data/repos/. Copied into a
    # temp dir before each attempt so cases never mutate the source.
    name: str
    # Docker images per mode — keys match cases.yaml `inputs.images`:
    #   release: snyk/snyk:* (eval + eval-preview)
    #   local: upstream tooling image + bind-mounted build/snyk-local (eval-local)
    images: dict[str, str]
    # The project's own test command — a single shell line evaluated by
    # /bin/sh inside the container; failure here drives `tests_passed=False`.
    test_cmd: str
    # Optional override for test-output parsing (jest, pytest, maven, rspec,
    # go, dotnet, phpunit). When empty, inferred from `test_cmd`; if inference
    # fails the harness warns and skips passed-test counting for that case.
    test_framework: str = ""
    # Optional shell line that installs the project's dependencies — needed
    # for ecosystems where snyk relies on installed packages rather than a
    # lockfile (pip with requirements.txt, ...). Runs before the pre-scan
    # and again before the post-scan so post-agent manifest changes are
    # reflected.
    install_cmd: str = ""
    # Optional compile-only command (e.g. "go build ./...", "mvn -B -q
    # compile test-compile"). DIAGNOSTIC ONLY — it is not part of the
    # `verified` predicate. Where a toolchain compiles as part of its test
    # command the result is redundant, and in npm/python/php/ruby there is
    # nothing to compile at all, so a headline metric including it would mean
    # different things per ecosystem. Its job is to separate "didn't compile"
    # from "compiled, tests failed" when reading a failure. Empty = not
    # applicable, recorded as None.
    build_cmd: str = ""
    # Optional command that starts the app. Either a long-running server
    # (paired with boot_check below) or a short entry-point invocation whose
    # exit code is itself the signal. Empty = the fixture is a library with no
    # entry point; `boots` is recorded as None (not applicable) and does not
    # fail the verdict.
    boot_cmd: str = ""
    # Optional readiness probe polled until it exits 0 or boot_timeout_s
    # elapses. When set, boot_cmd is backgrounded and terminated after the
    # probe resolves. When empty, boot_cmd is run to completion and its exit
    # code is the boot result.
    boot_check: str = ""
    boot_timeout_s: int = 30
    timeout_s: int = 900
    # Per-case LLM override. Empty string = inherit `HarnessConfig.provider`
    # / `HarnessConfig.model` (which themselves default to the agent's own
    # default when also empty). Set per-case to pin a model for one case
    # while running the rest of the suite against the global model.
    provider: str = ""
    model: str = ""
    # Resolved from `images` at run time; do not set in cases.yaml.
    image: str = ""
    # Git-clone-based fixtures: the repo is pre-cloned into a local cache
    # and copied from there instead of from a fixture directory.
    repo_url: str = ""
    commit_sha: str = ""
    subdirectory: str = ""
    # Manifests (as the scan's displayTargetFile) the test command exercises.
    # Only these are scored; empty means every project the scan finds.
    manifests: list[str] = field(default_factory=list)
    # Directory names the harness scan skips (snyk --exclude), for projects
    # whose scan never finishes. Must not contain any listed manifest.
    scan_exclude: list[str] = field(default_factory=list)
    # Container memory cap (docker --memory, e.g. "32g"); empty = docker.DEFAULT_MEMORY.
    memory: str = ""


@dataclass
class HarnessConfig:
    """Environment the harness needs; resolved once and reused across cases."""

    # release: GA CLI baked into snyk/snyk images.
    # preview: preview CLI from downloads.snyk.io, mounted into the case's image.
    # local: the build at build/snyk-local, mounted the same way.
    mode: EvalMode = "release"
    snyk_binary: Path = DEFAULT_LOCAL_BINARY
    entrypoint: Path = DEFAULT_ENTRYPOINT
    platform: str = f"linux/{EVAL_ARCH}"
    # Populated at run start for release mode (snyk --version from image).
    snyk_version: str = field(default="", repr=False)
    # Default LLM the agent uses for every case in the run. The model goes to
    # both agents; the provider, if set, to `snyk fix --provider <P>` (empty =
    # anthropic, the CLI's default). Cases can override via `Scenario.provider` /
    # `Scenario.model`.
    provider: str = ""
    model: str = ""
    # Shared agent budget. Feeds Evo's --agent-max-iterations (per fix) AND
    # Claude Code's --max-turns (per upgrade; see agents.claude_turn_budget)
    # from one value. 0 = Evo's own default
    # (100 + 10 for breakability) and 110 per upgrade for Claude Code.
    agent_max_iterations: int = 0
    # Whether an unrelated dependency bump fails the attempt. Off by default:
    # build and tests already catch a bump that breaks something, and when
    # collateral was enforced most of what it failed were legitimate moves (a
    # jackson fix aligning every jackson-* module). The bumps are always
    # recorded and reported, just not fatal.
    strict_collateral: bool = False
    # Multiplier applied to every case's timeout_s. The per-case values assume
    # serial execution on native hardware; running linux/amd64 under emulation,
    # or several attempts concurrently, makes them too tight. Raising this is
    # preferable to editing the fixtures, whose timeouts are correct for the
    # environment they describe.
    timeout_multiplier: float = 1.0
    # USD per million tokens, used to cost Evo runs (Claude Code reports its own).
    price_in_per_mtok: float = 0.0
    price_out_per_mtok: float = 0.0

    def validate(self, needs_llm: bool = True) -> None:
        """Check the run's prerequisites; needs_llm when any selected agent calls a model."""
        if mount_snyk_binary(self.mode) and not Path(self.snyk_binary).exists():
            if self.mode == "preview":
                hint = "the preview CLI download failed; see harness/cli_binary.py"
            else:
                hint = "place a snyk CLI build there, or use --preview"
            raise FileNotFoundError(
                f"snyk binary missing at {self.snyk_binary}; {hint}"
            )
        if not Path(self.entrypoint).exists():
            raise FileNotFoundError(f"entrypoint missing at {self.entrypoint}")
        if "SNYK_TOKEN" not in os.environ:
            raise EnvironmentError("SNYK_TOKEN must be set (the harness re-scans and the agent scans)")
        if needs_llm and not os.environ.get("ANTHROPIC_API_KEY"):
            raise EnvironmentError("ANTHROPIC_API_KEY must be set (the agents call the model with it)")
        try:
            subprocess.run(
                ["docker", "version"], capture_output=True, check=True, timeout=10
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise EnvironmentError(f"docker not reachable: {exc}")

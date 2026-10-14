"""Run one phase of one case in a language-toolchain or snyk/snyk image.

A case is no longer one container. It is:

    phase 0        baseline + fix plan            (1 container)
    phase 1..N     one agent's attempt at one fix   (2 containers each:
                   PHASE=agent, then PHASE=verify as root with a fresh /out)

The agent container mirrors Evo's production sandbox for every agent: a
non-root uid, a read-only root filesystem, and /tmp as the only writable
place outside the repo. Baseline and verify are the harness's own judges
and run as root.

Every phase gets a fresh copy of the pristine fixture, so isolation is by
construction rather than by revert: nothing is ever mutated twice, and fix
k+1 cannot inherit fix k's state.

`docker_run` builds a single `docker run` invocation with the right bind
mounts (fixture + optional preview/local snyk binary + entrypoint.sh), env
vars (LLM key + Snyk token + extra CA passthroughs + analytics destinations),
and a unique container name so the container can be killed on timeout.

One asymmetry is deliberate. The `claude-code-unaided` agents must NOT be able to
reach snyk: they are not told the versions that fix their vulns, and snyk (the
scanner or its vuln pages) would tell them. Callers pass `mount_snyk=False`
for them, which also blocks SNYK_HOSTS.

The `subprocess.run(timeout=…)` idiom kills the local docker CLI on timeout
but leaves the container running in the daemon — we name each container and
follow up with `docker kill <name>` so nothing leaks.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from .extra_certs import docker_run_args
from .mode import mount_snyk_binary
from .scenario import HarnessConfig, Scenario

_PASSTHROUGH_ENV = (
    "SNYK_TOKEN", "SNYK_CFG_ORG",
    "ANTHROPIC_API_KEY",
    # Evo development builds trace to LangSmith when the key is set.
    "LANGSMITH_API_KEY", "LANGSMITH_ENDPOINT", "LANGSMITH_PROJECT",
)

_MIRROR_DIR = Path(__file__).resolve().parent / "maven-mirror"

PHASE_BASELINE = "baseline"
# Every attempt is two containers over the same /app: the agent runs in one,
# the harness verifies in a fresh one (root, fresh /out, like the baseline), so
# nothing the agent leaves outside /app can shape its own verification.
PHASE_AGENT = "agent"
PHASE_VERIFY = "verify"

# GitHub hosts, unreachable from the agent container only. The agent could
# otherwise read the upstream fix off the repo's later commits or Dependabot
# PRs (`curl`, `git clone`, `gh` all bypass Claude Code's WebFetch deny rules).
# The rest of the web stays open: advisories, changelogs and registries are
# fair game. Verify keeps normal network, so git-URL deps still resolve there.
# Name-based only: `curl --resolve` or DNS-over-HTTPS still get through.
GITHUB_HOSTS = (
    "github.com", "www.github.com", "api.github.com", "raw.githubusercontent.com",
    "codeload.github.com", "gist.github.com", "objects.githubusercontent.com",
    # Mirrors that serve a repo's files at any branch or tag.
    "cdn.jsdelivr.net", "fastly.jsdelivr.net", "gcore.jsdelivr.net",
    "raw.githack.com", "rawcdn.githack.com", "sourcegraph.com",
)
# Snyk's own hosts, blocked for agents denied snyk: the vuln pages name the
# versions that fix each vuln, which the unaided agents are not told.
SNYK_HOSTS = ("snyk.io", "security.snyk.io", "api.snyk.io", "app.snyk.io")
# Cases whose agent-phase setup cannot work without GitHub, so the block would
# cripple both agents (and Evo's own scan) rather than stop a leak:
#   qdrant-qdrant-client    poetry's (non-optional) docs group has a git dep
#   informatici-openhospital-core  weasis-core-img is only in a Maven repo on
#                           raw.github.com (declared by a transitive pom)
# A known residual leak for these; vendor the fetch and drop the entry.
AGENT_NEEDS_GITHUB = frozenset({"qdrant-qdrant-client", "informatici-openhospital-core"})

# Pre-downloaded Gradle wrapper distributions (`dists/` layout), filled once
# with network access by running each repo's wrapper as GRADLE_USER_HOME=/g
# with this dir mounted at /g/wrapper/dists.
GRADLE_DISTS = Path(__file__).resolve().parents[2] / "data" / "gradle-dists"

# Static CLI tools no fixture image ships (jq, yq), mounted into /usr/local/bin
# for every agent, so they keep the same toolbox. See docs/running.md for the sources.
AGENT_TOOLS = Path(__file__).resolve().parents[2] / "data" / "tools"

_GRADLE_LIMITS = Path(__file__).resolve().parent / "gradle-limits.gradle"

# Per-container memory cap. The host has 62 GB and no swap: one runaway
# container (an agent's Kafka `gradlew test`, 53 GB) froze it. Above every
# measured peak except full kafka, which sets its own in cases.yaml.
DEFAULT_MEMORY = "24g"

# Written to /out when the kernel OOM-killed anything in the container.
OOM_MARKER = "oom-killed"


def docker_run(
    scenario: Scenario,
    cfg: HarnessConfig,
    work: Path,
    out: Path,
    *,
    phase: str = PHASE_BASELINE,
    image: str | None = None,
    agent_cmd: str = "",
    plan_cmd: str = "",
    mount_snyk: bool | None = None,
    timeout_s: int | None = None,
) -> tuple[subprocess.CompletedProcess, bool]:
    """Run one phase. Returns (CompletedProcess, timed_out).

    image overrides the scenario's resolved image — used to swap in the
    Claude-Code-enabled twin every agent runs in.

    mount_snyk=None follows the eval mode (preview/local bind-mount the
    binary; release uses the image's own CLI). mount_snyk=False denies snyk
    outright (no binary, no token, no SNYK_HOSTS), which is how the unaided
    agents stay unaided.
    """
    container_name = f"vulnbump-{scenario.name}-{phase}-{uuid.uuid4().hex[:8]}"
    # No --rm: the container is inspected for OOMKilled, then removed.
    args = [
        "docker", "run",
        "--name", container_name,
        "--memory", scenario.memory or DEFAULT_MEMORY,
        "--platform", cfg.platform,
        "--add-host=host.docker.internal:host-gateway",
        "-v", f"{work}:/app",
        "-v", f"{out}:/out",
    ]

    if phase == PHASE_AGENT and scenario.name not in AGENT_NEEDS_GITHUB:
        args += [f"--add-host={host}:0.0.0.0" for host in GITHUB_HOSTS]
        # services.gradle.org redirects wrapper downloads to github.com, so seed
        # the distribution instead (entrypoint.sh copies it into GRADLE_USER_HOME).
        if GRADLE_DISTS.is_dir():
            args += ["-v", f"{GRADLE_DISTS}:/gradle-dists:ro"]
    if phase == PHASE_AGENT and mount_snyk is False:
        args += [f"--add-host={host}:0.0.0.0" for host in SNYK_HOSTS]
    if phase == PHASE_AGENT and AGENT_TOOLS.is_dir():
        for tool in sorted(AGENT_TOOLS.iterdir()):
            args += ["-v", f"{tool}:/usr/local/bin/{tool.name}:ro"]

    want_snyk = mount_snyk_binary(cfg.mode) if mount_snyk is None else mount_snyk
    if want_snyk and mount_snyk is not False:
        args += ["-v", f"{cfg.snyk_binary}:/usr/local/bin/snyk:ro"]

    args += [
        "-v", f"{cfg.entrypoint}:/entrypoint.sh:ro",
        "-w", "/app",
        "--entrypoint", "/entrypoint.sh",
    ]
    sandbox: Path | None = None
    if phase == PHASE_AGENT:
        # the Evo Remediation Agent's production sandbox: non-root, a
        # read-only root filesystem, and only the repo and /tmp writable, with
        # every cache pointed at /tmp. Both agents get it, so neither pays for
        # an environment the other doesn't have. It is also what Claude Code
        # needs anyway: it refuses --dangerously-skip-permissions under root.
        # The host uid owns the /app and /out bind mounts (mktemp dirs), so it
        # can write them and the entrypoint's closing chown is a no-op.
        sandbox = _sandbox_dir()
        args += [
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--read-only",
            "-v", f"{sandbox / 'tmp'}:/tmp",
            # The uid needs a passwd entry, as the production sandbox user has.
            # Without one the snyk CLI drops Evo's analytics payload (tokens,
            # cost) and the JVM's user.home is "?".
            "-v", f"{sandbox / 'passwd'}:/etc/passwd:ro",
            "-v", f"{sandbox / 'group'}:/etc/group:ro",
            "-e", "HOME=/tmp",
            "-e", "GRADLE_USER_HOME=/tmp/.gradle",
            "-e", "MAVEN_OPTS=-Dmaven.repo.local=/tmp/.m2",
            "-e", "npm_config_cache=/tmp/.npm",
            "-e", "GOPATH=/tmp/go",
            "-e", "GOCACHE=/tmp/go-build",
            "-e", "XDG_CACHE_HOME=/tmp",
        ]
    else:
        # Upstream tooling images (e.g. serversideup/php) run as non-root; on
        # Linux bind mounts the host-owned /out is not writable. Root matches
        # entrypoint.sh's chown-back assumption and works on Mac too.
        args += ["--user", "0:0"]
        args += ["-v", f"{_GRADLE_LIMITS}:/root/.gradle/init.d/limits.gradle:ro"]
        # Maven and Gradle resolve through the local Central cache (maven-mirror/).
        if os.environ.get("MAVEN_MIRROR_URL"):
            args += [
                "-v", f"{_MIRROR_DIR / 'settings.xml'}:/root/.m2/settings.xml:ro",
                "-v", f"{_MIRROR_DIR / 'init.gradle'}:/root/.gradle/init.d/maven-mirror.gradle:ro",
            ]
    if os.environ.get("MAVEN_MIRROR_URL"):
        args += ["-e", "MAVEN_MIRROR_URL"]
    args += docker_run_args()
    args += ["-e", f"HOST_UID={os.getuid()}", "-e", f"HOST_GID={os.getgid()}"]

    for key in _PASSTHROUGH_ENV:
        if key == "SNYK_TOKEN" and mount_snyk is False:
            continue
        if key in os.environ:
            args += ["-e", key]

    # The maven:* images set MAVEN_CONFIG=/root/.m2 which breaks snyk's
    # internal `mvn dependency:tree` call. The snyk/snyk images deliberately
    # leave it empty. Clear it so scanning works in any Maven image.
    args += ["-e", "MAVEN_CONFIG="]

    args += [
        "-e", f"PHASE={phase}",
        "-e", f"INSTALL_CMD={scenario.install_cmd}",
        "-e", f"BUILD_CMD={scenario.build_cmd}",
        "-e", f"TEST_CMD={scenario.test_cmd}",
        "-e", f"BOOT_CMD={scenario.boot_cmd}",
        "-e", f"BOOT_CHECK={scenario.boot_check}",
        # Scaled by the same multiplier as the container budget. The readiness
        # probe competes for CPU with every other concurrent attempt, and a
        # probe that times out is recorded as boot-broken — turning a correct
        # fix into a failed verdict for a reason that is purely about load.
        "-e", f"BOOT_TIMEOUT_S={max(1, int(scenario.boot_timeout_s * cfg.timeout_multiplier))}",
        # Wall-clock cap per install/build/test step. Two thirds of the case
        # budget: long enough that a slow maven or dotnet step under emulation
        # finishes, short enough that one hung step still leaves room for the
        # rest of the phase to run and be recorded.
        "-e", f"STEP_TIMEOUT_S={max(60, int(scenario.timeout_s * cfg.timeout_multiplier * 2 / 3))}",
        # Route the Evo Remediation Agent's analytics events to a local JSONL
        # file, which harness/analytics.py reads.
        "-e", "SNYK_REMEDIATION_ANALYTICS_SINK=file",
        "-e", "SNYK_REMEDIATION_ANALYTICS_FILE=/out/analytics.jsonl",
    ]
    if scenario.subdirectory:
        args += ["-e", f"SUBDIR={scenario.subdirectory}"]
    if scenario.scan_exclude:
        args += ["-e", f"SCAN_EXCLUDE={','.join(scenario.scan_exclude)}"]
    if agent_cmd:
        args += ["-e", f"AGENT_CMD={agent_cmd}"]
    if plan_cmd:
        args += ["-e", f"PLAN_CMD={plan_cmd}"]

    args.append(image or scenario.image)

    limit = timeout_s if timeout_s is not None else scenario.timeout_s
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=limit)
        _reap(container_name, out)
        return proc, False
    except subprocess.TimeoutExpired as exc:
        # `subprocess.run` has already SIGKILL'd the docker CLI, but the
        # container is still running in the daemon. Kill it explicitly so
        # nothing leaks. `check=False`: it may have exited on its own.
        subprocess.run(
            ["docker", "kill", container_name],
            capture_output=True, timeout=10, check=False,
        )
        _reap(container_name, out)
        return (
            subprocess.CompletedProcess(
                args,
                returncode=124,
                stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr=exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            ),
            True,
        )
    finally:
        if sandbox is not None:
            shutil.rmtree(sandbox, ignore_errors=True)


def _sandbox_dir() -> Path:
    """Host files for the agent sandbox: its /tmp, plus /etc/passwd and /etc/group.

    /tmp is pre-seeded with the Maven/Gradle config by copying rather than by
    bind-mounting files under it: Docker creates a nested mount's missing
    parents as root, which left /tmp/.m2 and /tmp/.gradle unwritable to the
    non-root agent and broke Maven and Gradle.
    """
    root = Path(tempfile.mkdtemp(prefix="vulnbump-agent-"))
    uid, gid = os.getuid(), os.getgid()
    # The snyk CLI redacts the username anywhere in its analytics payload, so
    # a name like "agent" would turn agent_input_tokens into ***_input_tokens.
    (root / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        f"vulnbump:x:{uid}:{gid}:vulnbump:/tmp:/bin/sh\n"
    )
    (root / "group").write_text(f"root:x:0:\nnogroup:x:65534:\nvulnbump:x:{gid}:\n")
    tmp = root / "tmp"
    tmp.mkdir()
    tmp.chmod(0o1777)
    init_d = tmp / ".gradle" / "init.d"
    init_d.mkdir(parents=True)
    shutil.copy(_GRADLE_LIMITS, init_d / "limits.gradle")
    if os.environ.get("MAVEN_MIRROR_URL"):
        (tmp / ".m2").mkdir()
        shutil.copy(_MIRROR_DIR / "settings.xml", tmp / ".m2" / "settings.xml")
        shutil.copy(_MIRROR_DIR / "init.gradle", init_d / "maven-mirror.gradle")
    return root


def _reap(container_name: str, out: Path) -> None:
    """Record whether the kernel OOM-killed anything in the container, then remove it.

    Docker sets OOMKilled even when only a child (a test JVM) died and the
    entrypoint carried on, which is the case that would otherwise read as a
    real test failure.
    """
    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.OOMKilled}}", container_name],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if inspect.stdout.strip() == "true":
        (out / OOM_MARKER).touch()
    # -v: images like gradle:8-jdk17 declare a VOLUME, and each container's
    # anonymous volume (~800 MB of Gradle caches) otherwise outlives it.
    subprocess.run(
        ["docker", "rm", "-f", "-v", container_name],
        capture_output=True, timeout=60, check=False,
    )

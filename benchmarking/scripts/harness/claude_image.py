"""Fixture images with Claude Code installed: the image every agent runs in.

Evo runs in it too, not in the bare fixture image, so the agents differ in
the agent and nothing else: same OS, same toolchain (Node included, which
Claude Code brings), same installed dependencies.

Installing Claude Code per container would add a global npm install to every
one of the ~150 runs in a suite. Instead each base image is extended once into
a derived image that is cached by the Docker daemon and reused.

The version is pinned. An unpinned control is not reproducible, and "we beat
Claude Code" means nothing if nobody can tell which Claude Code.
"""

from __future__ import annotations

import base64
import subprocess
import threading
from pathlib import Path

# Pin the control. Bump deliberately, and re-baseline the benchmark when you
# do — a control-agent version change moves the comparison, not just a number.
# Claude's cost is the CLI's own figure from its built-in price table, so the
# pin must be new enough to know the model under test (2.1.289 prices Sonnet
# 5.5 at $2/$10; 2.0.14 fell back to $3/$15).
CLAUDE_CODE_VERSION = "2.1.289"

_DERIVED_TAG_PREFIX = "vulnbump-claude"

# Node is how Claude Code ships. Fixture images for non-node ecosystems
# (maven, dotnet, ruby, php, go) have no node, so the derived image installs
# it. Debian/Ubuntu-based images use apt; the rest fall back to a static
# tarball so we don't need a package manager at all.
_DOCKERFILE = """
FROM {base}
USER root
# Optional corporate CA, passed base64-encoded because a PEM is multi-line and
# the host cert lives outside the build context. Must land before the npm
# install below, which is what TLS interception breaks.
ARG EXTRA_CA_B64=""
RUN set -eu; \\
    if [ -n "$EXTRA_CA_B64" ]; then \\
      mkdir -p /usr/local/share/ca-certificates; \\
      echo "$EXTRA_CA_B64" | base64 -d > /usr/local/share/ca-certificates/extra-ca.crt; \\
      cp /usr/local/share/ca-certificates/extra-ca.crt /etc/ssl/extra-ca.pem; \\
      (command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates) || true; \\
    fi
# The JVM keeps its own truststore and ignores the system bundle entirely, so
# maven needs the CA imported with keytool. That writes into $JAVA_HOME, which
# requires root — and the Claude agents run as the HOST USER, because Claude
# Code refuses --dangerously-skip-permissions under root. At runtime the import
# therefore fails silently behind `|| true`, and maven dies with
# "PKIX path building failed" that never mentions permissions.
#
# Doing it here, at build time as root, means the non-root runtime inherits a
# patched truststore. Only images that actually ship a JVM are affected.
RUN set -eu; \
    if [ -n "${{JAVA_HOME:-}}" ] && [ -s /etc/ssl/extra-ca.pem ] && command -v keytool >/dev/null 2>&1; then \
      keytool -importcert -noprompt -trustcacerts \
        -alias extra-ca-root \
        -keystore "$JAVA_HOME/lib/security/cacerts" \
        -storepass changeit \
        -file /etc/ssl/extra-ca.pem ; \
      chmod a+r "$JAVA_HOME/lib/security/cacerts" ; \
    fi
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/extra-ca.pem
# Node (for Claude Code) via the official static build — works on any glibc
# image regardless of which package manager it has, and avoids touching the
# fixture's own toolchain.
#
# .tar.gz rather than the smaller .tar.xz on purpose: `tar -xJ` shells out to
# an `xz` binary that the maven, dotnet and golang images do not ship, and the
# resulting "xz: Cannot exec" is reported as an unrecoverable tar error rather
# than a missing dependency. gzip is present everywhere.
ARG NODE_VERSION=22.11.0
RUN set -eu; \\
    if ! command -v node >/dev/null 2>&1; then \\
      arch="$(uname -m)"; \\
      case "$arch" in \\
        x86_64) nodearch=x64 ;; \\
        aarch64|agent64) nodearch=agent64 ;; \\
        *) echo "unsupported arch $arch" >&2; exit 1 ;; \\
      esac; \\
      (command -v curl >/dev/null 2>&1 || (apt-get update && apt-get install -y --no-install-recommends curl ca-certificates)) ; \\
      curl -fsSL "https://nodejs.org/dist/v${{NODE_VERSION}}/node-v${{NODE_VERSION}}-linux-${{nodearch}}.tar.gz" -o /tmp/node.tar.gz; \\
      mkdir -p /opt/node; \\
      tar -xzf /tmp/node.tar.gz -C /opt/node --strip-components=1; \\
      rm /tmp/node.tar.gz; \\
      ln -sf /opt/node/bin/node /usr/local/bin/node; \\
      ln -sf /opt/node/bin/npm /usr/local/bin/npm; \\
    fi
# When node came from the tarball above, npm's global prefix is /opt/node and
# its bin dir is not on PATH, so the freshly installed `claude` is invisible.
# Symlink only when it is not already resolvable, so images that shipped
# their own node (prefix /usr/local, already on PATH) keep working rather
# than getting a self-referential link.
RUN npm install -g --no-fund --no-audit @anthropic-ai/claude-code@{version} \\
    && if ! command -v claude >/dev/null 2>&1; then \\
         ln -sf "$(npm prefix -g)/bin/claude" /usr/local/bin/claude; \\
       fi \\
    && claude --version
"""


def derived_tag(base_image: str) -> str:
    """Deterministic tag for the Claude-Code-enabled twin of a base image."""
    slug = base_image.replace("/", "-").replace(":", "-")
    return f"{_DERIVED_TAG_PREFIX}/{slug}:{CLAUDE_CODE_VERSION}"


def image_exists(tag: str) -> bool:
    proc = subprocess.run(
        ["docker", "image", "inspect", tag],
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0


# Parallel repos can share a base image; one build per tag, not one per repo.
_build_lock = threading.Lock()


def ensure_claude_image(
    base_image: str, *, platform: str, extra_ca_cert: str | None = None
) -> str:
    """Return a tag for `base_image` with Claude Code installed, building it
    on first use. Subsequent calls hit the daemon's image cache.

    Raises RuntimeError with the build log on failure: a Claude agent that
    cannot start is a harness fault, not a result, and must not be recorded
    as the control losing.
    """
    with _build_lock:
        return _ensure(base_image, platform=platform, extra_ca_cert=extra_ca_cert)


def _ensure(base_image: str, *, platform: str, extra_ca_cert: str | None) -> str:
    tag = derived_tag(base_image)
    if image_exists(tag):
        return tag

    dockerfile = _DOCKERFILE.format(base=base_image, version=CLAUDE_CODE_VERSION)
    args = [
        "docker", "build",
        "--platform", platform,
        "-t", tag,
        "-f", "-",
    ]
    if extra_ca_cert:
        # Corporate TLS interception breaks the npm install inside the build.
        # Trust the same root the eval containers already use at runtime.
        encoded = base64.b64encode(Path(extra_ca_cert).read_bytes()).decode()
        args += ["--build-arg", f"EXTRA_CA_B64={encoded}"]
    args.append(".")

    proc = subprocess.run(
        args, input=dockerfile, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"failed to build Claude Code image for {base_image}:\n{proc.stderr[-4000:]}"
        )
    return tag

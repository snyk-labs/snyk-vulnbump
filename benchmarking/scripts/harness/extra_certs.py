"""Extra CA certificate wiring for the eval harness.

Host setup: export EXTRA_CA_CERT to a PEM file on your machine.

Containers get a bind-mount + harness/setup-extra-certs.sh (via entrypoint.sh).
"""

from __future__ import annotations

import os
from pathlib import Path

# Where the host cert lands inside containers and preview-build stages.
CERT_IN_CONTAINER = Path("/etc/ssl/extra-ca.pem")

SETUP_SCRIPT = Path(__file__).resolve().parent / "setup-extra-certs.sh"

# Checked in order. NODE_EXTRA_CA_CERTS is the fallback because a machine
# behind a TLS-intercepting proxy almost always already exports it — and
# requiring a second variable for the same certificate is how a run silently
# loses its CA. See host_cert().
CERT_ENV_VARS = ("EXTRA_CA_CERT", "NODE_EXTRA_CA_CERTS")


def host_cert() -> Path | None:
    """The host CA bundle to trust inside containers, or None.

    Falls back from $EXTRA_CA_CERT to $NODE_EXTRA_CA_CERTS.

    Why the fallback earns its keep: without a CA on an intercepted network,
    `npm ci` cannot verify the registry, fails most downloads with
    UNABLE_TO_GET_ISSUER_CERT_LOCALLY — and then **exits 0** having written a
    partial node_modules. Every downstream check fails (no build, no tests, no
    boot, no scan) and the case is reported as an invalid fixture. The fixture
    is fine. Nothing in that chain mentions certificates, and the whole run is
    wasted on a diagnosis that points at the wrong thing.

    This cost a full debugging cycle on 2026-08-21: EXTRA_CA_CERT was set
    inline for one run, did not persist to the next shell, and npm-express then
    "failed" all five baseline checks.
    """
    for var in CERT_ENV_VARS:
        path = os.environ.get(var)
        if not path:
            continue
        p = Path(path)
        if p.is_file():
            return p
    return None


def cert_source() -> str:
    """Which variable supplied the cert, for logging. Empty when none did."""
    for var in CERT_ENV_VARS:
        path = os.environ.get(var)
        if path and Path(path).is_file():
            return var
    return ""


def docker_run_args() -> list[str]:
    """Extra `docker run` flags: mount cert + setup script. No-op without EXTRA_CA_CERT."""
    cert = host_cert()
    if not cert:
        return []
    return [
        "-v", f"{cert}:{CERT_IN_CONTAINER}:ro",
        "-v", f"{SETUP_SCRIPT}:/setup-extra-certs.sh:ro",
    ]

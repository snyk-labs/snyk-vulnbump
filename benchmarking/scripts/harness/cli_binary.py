"""Resolve snyk CLI binaries for eval modes.

- **preview** — ``build/snyk-preview``, fetched from the preview channel on
  downloads.snyk.io (fetched automatically by the harness in preview mode).
- **local** — ``build/snyk-local``, any snyk CLI build you place there, e.g. a
  development build of the Evo Remediation Agent.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path

from .mode import EvalMode

REPO_ROOT = Path(__file__).resolve().parents[2]

PREVIEW_RELEASE_JSON = "https://downloads.snyk.io/cli/preview/release.json"
PREVIEW_LINUX_ASSET = "snyk-linux"

DEFAULT_PREVIEW_BINARY = REPO_ROOT / "build" / "snyk-preview"
DEFAULT_LOCAL_BINARY = REPO_ROOT / "build" / "snyk-local"
PREVIEW_VERSION_FILE = REPO_ROOT / "build" / "snyk-preview.version"
PINNED_BINARIES_DIR = REPO_ROOT / "data" / "snyk-builds"


def default_snyk_binary(mode: EvalMode) -> Path:
    """Host path to the snyk binary bind-mounted for preview/local modes."""
    return DEFAULT_LOCAL_BINARY if mode == "local" else DEFAULT_PREVIEW_BINARY


def pin_binary(src: Path, store: Path = PINNED_BINARIES_DIR) -> tuple[Path, str]:
    """Copy ``src`` to a content-addressed path so a rebuild mid-run can't swap it.

    Returns ``(pinned_path, sha256)``.
    """
    real = Path(src).resolve()
    digest = hashlib.sha256(real.read_bytes()).hexdigest()
    dest = store / digest[:16] / "snyk"
    if not dest.is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".tmp")
        shutil.copyfile(real, tmp)
        tmp.chmod(0o755)
        tmp.replace(dest)
    return dest, digest


def cli_commit(binary: Path) -> str | None:
    """HEAD of the git checkout the (resolved) binary lives in."""
    try:
        out = subprocess.run(
            ["git", "-C", str(Path(binary).resolve().parent), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, check=True,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


def fetch_preview_cli(
    dest: Path = DEFAULT_PREVIEW_BINARY,
    *,
    force: bool = False,
) -> str:
    """Download the latest preview-channel snyk-linux if missing or stale.

    Offline, a cached binary is used as is.
    """
    try:
        release = _fetch_json(PREVIEW_RELEASE_JSON)
    except OSError as exc:
        if force or not dest.is_file():
            raise
        print(f"[cli] preview release check failed ({exc}); using the cached {dest}", file=sys.stderr)
        return _cached_preview_version() or ""
    version = release["version"]
    asset = release["assets"][PREVIEW_LINUX_ASSET]
    url = asset["url"]
    expected_sha256 = asset["sha256"].split()[0]

    if not force and dest.is_file() and _cached_preview_version() == version:
        return version

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    _download(url, tmp)
    digest = hashlib.sha256(tmp.read_bytes()).hexdigest()
    if digest != expected_sha256:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(
            f"preview CLI checksum mismatch: expected {expected_sha256}, got {digest}"
        )
    shutil.move(str(tmp), str(dest))
    dest.chmod(0o755)
    PREVIEW_VERSION_FILE.write_text(version + "\n")
    return version



def _cached_preview_version() -> str | None:
    if not PREVIEW_VERSION_FILE.is_file():
        return None
    return PREVIEW_VERSION_FILE.read_text().strip() or None


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    cert = os.environ.get("EXTRA_CA_CERT")
    if cert:
        path = Path(cert).expanduser()
        if path.is_file():
            ctx.load_verify_locations(str(path))
    return ctx


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, context=_ssl_context(), timeout=120) as resp:
        return json.loads(resp.read())


def _download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"Accept-Encoding": "gzip"})
    with urllib.request.urlopen(req, context=_ssl_context(), timeout=300) as resp:
        dest.write_bytes(resp.read())

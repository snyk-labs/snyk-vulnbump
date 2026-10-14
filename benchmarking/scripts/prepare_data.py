"""Fill benchmarking/data/ with the local inputs a run needs.

- data/repos/: every case cloned at its pinned commit (clone_repos.py).
- data/tools/: static jq and yq binaries, mounted into the agent container.
- data/gradle-dists/: the Gradle wrapper distribution of every Gradle case, in
  the wrapper's own dists/ layout. The agent container blocks GitHub, where the
  wrapper's download redirects, so the agent phase copies it from here.

Idempotent: anything already present is skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from harness.cli_binary import _download

BENCHMARK_DIR = Path(__file__).resolve().parents[1]

TOOLS = {
    "jq": ("https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-amd64",
           "020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d"),
    "yq": ("https://github.com/mikefarah/yq/releases/download/v4.54.1/yq_linux_amd64",
           "8e34fc298390875de416e6a4afcb8cabeceb25d9aa8506c1a2f9353cf702ea5f"),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch_tools(tools_dir: Path) -> None:
    tools_dir.mkdir(parents=True, exist_ok=True)
    for name, (url, sha256) in TOOLS.items():
        dest = tools_dir / name
        if dest.is_file() and _sha256(dest) == sha256:
            print(f"  skip (exists): {name}")
            continue
        print(f"  downloading {name}")
        _download(url, dest)
        if _sha256(dest) != sha256:
            dest.unlink()
            raise RuntimeError(f"{name}: checksum mismatch for {url}")
        dest.chmod(0o755)


def gradle_dist_hash(url: str) -> str:
    """The wrapper's dists/<name>/<hash> directory: base-36 MD5 of the distribution URL."""
    n = int.from_bytes(hashlib.md5(url.encode()).digest(), "big")
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = digits[r] + out
    return out


def fetch_gradle_dists(repos_dir: Path, dists_dir: Path) -> None:
    for props in sorted(repos_dir.glob("*/gradle/wrapper/gradle-wrapper.properties")):
        text = props.read_text()
        match = re.search(r"^distributionUrl=(.+)$", text, re.M)
        if not match:
            continue
        url = match.group(1).strip().replace("\\:", ":")
        name = url.rsplit("/", 1)[1].removesuffix(".zip")
        target = dists_dir / name / gradle_dist_hash(url)
        if (target / f"{name}.zip.ok").exists():
            print(f"  skip (exists): {name}")
            continue
        print(f"  downloading {name} ({props.parents[2].name})")
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / f"{name}.zip"
            _download(url, archive)
            expected = re.search(r"^distributionSha256Sum=(\w+)", text, re.M)
            if expected and _sha256(archive) != expected.group(1):
                raise RuntimeError(f"{name}: checksum mismatch for {url}")
            target.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive) as z:
                for info in z.infolist():
                    path = Path(z.extract(info, target))
                    if mode := info.external_attr >> 16:
                        path.chmod(mode & 0o777)
        (target / f"{name}.zip.ok").touch()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--cases", type=Path, default=BENCHMARK_DIR / "cases" / "cases.yaml")
    p.add_argument("--data", type=Path, default=BENCHMARK_DIR / "data")
    args = p.parse_args()

    print("=== repositories", flush=True)
    rc = subprocess.run([sys.executable, str(Path(__file__).parent / "clone_repos.py"),
                         "--cases", str(args.cases), "--out", str(args.data / "repos")]).returncode
    print("=== jq, yq")
    fetch_tools(args.data / "tools")
    print("=== Gradle wrapper distributions")
    fetch_gradle_dists(args.data / "repos", args.data / "gradle-dists")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

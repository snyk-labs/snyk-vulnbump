"""Pre-clone all repos at their pinned commits into a local cache.

Each clone fetches only the pinned commit (depth 1, no remote, no other refs),
so an agent working on a copy cannot read later upstream history. Cloning is
idempotent — repos that already exist are skipped. Clones are named after the
cases in cases.yaml.

--sanitise converts existing full clones in place to the same single-commit
state; --check reports (read-only) which cached repos still leak history.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

BENCHMARK_DIR = Path(__file__).resolve().parents[1]


def _git(repo: Path, *args: str, timeout: int = 120) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True, text=True, timeout=timeout,
    ).stdout


def clone_repo(repo_url: str, commit_sha: str, dest: Path) -> bool:
    if dest.exists():
        try:
            head = _git(dest, "rev-parse", "HEAD").strip()
        except subprocess.CalledProcessError:
            head = ""
        if head == commit_sha:
            print(f"  skip (exists): {dest.name}")
            return True
        print(f"  FAILED: {dest} exists at {head[:10] or 'no commit'}, not {commit_sha[:10]}; "
              f"remove it and re-run", file=sys.stderr)
        return False

    print(f"  cloning {repo_url} @ {commit_sha[:10]}...")
    try:
        dest.mkdir(parents=True)
        _git(dest, "init", "-q")
        _git(dest, "remote", "add", "origin", repo_url)
        _git(dest, "fetch", "-q", "--depth", "1", "origin", commit_sha, timeout=300)
        _git(dest, "checkout", "-q", "--detach", "FETCH_HEAD")
        _git(dest, "remote", "remove", "origin")
        (dest / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"  FAILED: {e.stderr.strip()}", file=sys.stderr)
        shutil.rmtree(dest, ignore_errors=True)
        return False
    except subprocess.TimeoutExpired:
        print(f"  FAILED: timeout", file=sys.stderr)
        shutil.rmtree(dest, ignore_errors=True)
        return False


def leak_status(repo: Path) -> tuple[int, list[str]]:
    """Commits reachable (refs or reflog) other than HEAD, and remote names."""
    extra = _git(repo, "rev-list", "--count", "--all", "--reflog", "--not", "HEAD")
    remotes = _git(repo, "remote").split()
    return int(extra.strip() or 0), remotes


def sanitise_repo(repo: Path) -> None:
    """Reduce a clone in place to HEAD only: no remotes, refs, tags, stash or reflog.

    The working tree and index are left untouched; HEAD becomes detached and shallow.
    """
    git_dir = repo / ".git"
    head = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "update-ref", "--no-deref", "HEAD", head)
    for remote in _git(repo, "remote").split():
        _git(repo, "remote", "remove", remote, timeout=600)
    refs = _git(repo, "for-each-ref", "--format=%(refname)").split()
    if refs:
        subprocess.run(
            ["git", "-C", str(repo), "update-ref", "--stdin"],
            input="".join(f"delete {r}\n" for r in refs),
            check=True, capture_output=True, text=True, timeout=600,
        )
    for name in ("FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD"):
        (git_dir / name).unlink(missing_ok=True)
    _git(repo, "reflog", "expire", "--expire=now", "--all")
    shutil.rmtree(git_dir / "logs", ignore_errors=True)
    (git_dir / "shallow").write_text(head + "\n")
    _git(repo, "gc", "-q", "--prune=now", timeout=3600)


def _check_all(repos_dir: Path) -> int:
    leaky = 0
    for repo in sorted(p for p in repos_dir.iterdir() if (p / ".git").exists()):
        extra, remotes = leak_status(repo)
        flag = "LEAK" if extra or remotes else "ok"
        leaky += flag == "LEAK"
        print(f"  {flag:4}  {repo.name:45} extra_commits={extra:<7} remotes={','.join(remotes) or '-'}")
    print(f"\n{leaky} repo(s) leak history")
    return 1 if leaky else 0


def _sanitise_all(repos_dir: Path, case: str | None) -> int:
    failed = 0
    for repo in sorted(p for p in repos_dir.iterdir() if (p / ".git").exists()):
        if case and repo.name != case:
            continue
        try:
            sanitise_repo(repo)
            extra, remotes = leak_status(repo)
            ok = not extra and not remotes
            print(f"  {'ok' if ok else 'FAILED':6} {repo.name}  extra_commits={extra} remotes={len(remotes)}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            ok = False
            print(f"  FAILED {repo.name}: {getattr(e, 'stderr', '') or e}", file=sys.stderr)
        failed += not ok
    print(f"\nDone: {failed} failed")
    return 1 if failed else 0


def main():
    p = argparse.ArgumentParser(description="Pre-clone repos at pinned commits")
    p.add_argument("--cases", default=str(BENCHMARK_DIR / "cases" / "cases.yaml"), help="Path to cases.yaml")
    p.add_argument("--out", default=str(BENCHMARK_DIR / "data" / "repos"),
                   help="Output directory for cloned repos")
    p.add_argument("--case", default=None, help="Clone only this case (by case name)")
    p.add_argument("--sanitise", action="store_true",
                   help="Strip existing repos in --out down to HEAD only (rewrites .git)")
    p.add_argument("--check", action="store_true",
                   help="Read-only: report repos in --out with history beyond HEAD or remotes")
    args = p.parse_args()

    if args.check:
        return _check_all(Path(args.out))
    if args.sanitise:
        return _sanitise_all(Path(args.out), args.case)
    repos_dir = Path(args.out)
    repos_dir.mkdir(parents=True, exist_ok=True)

    cases = yaml.safe_load(Path(args.cases).read_text())["cases"]
    ok, failed = 0, 0
    for case in cases:
        name = case["name"]
        if args.case and name != args.case:
            continue
        repo_url, commit_sha = case["inputs"]["repo_url"], case["inputs"]["commit_sha"]
        dest = repos_dir / name
        if clone_repo(repo_url, commit_sha, dest):
            ok += 1
        else:
            failed += 1

    print(f"\nDone: {ok} cloned, {failed} failed, {ok + failed} total")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

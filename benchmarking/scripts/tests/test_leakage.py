"""Git-history and GitHub leakage guards. Uses temp repos only."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from clone_repos import clone_repo, leak_status, sanitise_repo
from harness.agents import claude_code_command, claude_turn_budget
from harness.benchmark import _assert_no_history


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
    ).stdout.strip()


def commit(repo: Path, name: str, content: str) -> str:
    (repo / name).write_text(content)
    git(repo, "add", name)
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", content)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Path, list[str]]:
    up = tmp_path / "upstream"
    up.mkdir()
    git(up, "init", "-q", "-b", "main")
    shas = [commit(up, "package.json", f'{{"v": {i}}}') for i in range(4)]
    git(up, "tag", "v-last")
    return up, shas


@pytest.fixture
def leaky_clone(tmp_path: Path, upstream) -> tuple[Path, str]:
    up, shas = upstream
    repo = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(up), str(repo)], check=True)
    git(repo, "checkout", "-q", shas[1])
    (repo / "package.json").write_text("stashed")
    git(repo, "stash", "-q")
    # Dirty tree and index, plus a stash, must survive sanitising (except the stash).
    (repo / "untracked.txt").write_text("x")
    (repo / "package.json").write_text("dirty")
    (repo / "staged.txt").write_text("s")
    git(repo, "add", "staged.txt")
    return repo, shas[1]


def test_sanitise_leaves_only_head(leaky_clone, upstream):
    repo, head = leaky_clone
    later = upstream[1][-1]
    assert leak_status(repo)[0] > 0
    status_before = git(repo, "status", "--porcelain")

    sanitise_repo(repo)

    assert git(repo, "rev-parse", "HEAD") == head
    assert git(repo, "rev-list", "--all", "--count") == "1"
    assert git(repo, "remote") == ""
    assert git(repo, "tag") == ""
    assert git(repo, "for-each-ref") == ""
    assert git(repo, "reflog") == ""
    assert git(repo, "status", "--porcelain") == status_before
    assert leak_status(repo) == (0, [])
    gone = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", later], capture_output=True)
    assert gone.returncode != 0, "later commit object should be pruned"
    _assert_no_history(repo, repo)


def test_sanitise_is_idempotent(leaky_clone):
    repo, head = leaky_clone
    sanitise_repo(repo)
    sanitise_repo(repo)
    assert git(repo, "rev-list", "--all", "--count") == "1"
    assert git(repo, "rev-parse", "HEAD") == head


def test_clone_repo_fetches_only_pinned_commit(tmp_path, upstream):
    up, shas = upstream
    dest = tmp_path / "fresh"
    assert clone_repo(f"file://{up}", shas[1], dest)
    assert git(dest, "rev-parse", "HEAD") == shas[1]
    assert git(dest, "rev-list", "--all", "--count") == "1"
    assert git(dest, "remote") == "" and git(dest, "tag") == ""
    assert leak_status(dest) == (0, [])


def test_fresh_copy_guard_rejects_leaky_repo(leaky_clone):
    repo, _ = leaky_clone
    with pytest.raises(RuntimeError, match="--sanitise"):
        _assert_no_history(repo, repo)


def test_claude_command_blocks_github():
    cmd = claude_code_command(model="m", max_turns=3)
    for rule in (
        "WebFetch(domain:github.com)", "WebFetch(domain:www.github.com)",
        "WebFetch(domain:api.github.com)", "WebFetch(domain:raw.githubusercontent.com)",
        "WebFetch(domain:codeload.github.com)", "WebFetch(domain:gist.github.com)",
        "WebFetch(domain:cdn.jsdelivr.net)", "WebFetch(domain:raw.githack.com)",
        "WebFetch(domain:sourcegraph.com)", "Bash(gh:*)",
    ):
        assert f"'{rule}'" in cmd
    # Must survive the shell: parentheses and colons stay one argument each.
    out = subprocess.run(
        ["bash", "-c", f"set -- {cmd.split(' ', 1)[1].replace('\"$(cat /out/prompt.txt)\"', 'P')}; printf '%s\\n' \"$@\""],
        check=True, capture_output=True, text=True,
    ).stdout.splitlines()
    assert "Bash(gh:*)" in out and "WebFetch(domain:github.com)" in out


def test_claude_turns_default_to_evos_budget():
    assert "--max-turns 110" in claude_code_command(model="m")
    assert "--max-turns 3" in claude_code_command(model="m", max_turns=3)


def test_claude_turns_per_upgrade():
    assert claude_turn_budget(0) == 110
    assert claude_turn_budget(50) == 50


def test_claude_command_blocks_snyk_only_when_denied():
    from harness.docker import SNYK_HOSTS

    rules = [f"'WebFetch(domain:{host})'" for host in SNYK_HOSTS]
    assert not any(r in claude_code_command(model="m") for r in rules)
    denied = claude_code_command(model="m", deny_snyk=True)
    assert all(r in denied for r in rules) and "'WebFetch(domain:github.com)'" in denied

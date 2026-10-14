import subprocess

from harness import maven_mirror
from harness.maven_mirror import CANARY_SHA1, check_mirror, problems

OK = f"200 identity {CANARY_SHA1}"


def test_healthy_mirror_has_no_problems():
    assert problems(f"{OK}\n{OK}\n") == []


def test_compressed_body_is_a_problem():
    assert problems(f"200 br deadbeef\n{OK}\n") == ["upstream fetch came back Content-Encoding: br"]


def test_wrong_bytes_and_bad_status_are_problems():
    assert problems(f"{OK}\n200 identity deadbeef\n") == [
        f"cached fetch has sha1 deadbeef, Central's is {CANARY_SHA1}"]
    assert problems("000 identity\n404 identity x\n") == [
        "upstream fetch returned HTTP 000", "cached fetch returned HTTP 404"]


def test_missing_output_is_a_problem():
    assert problems("") and problems(OK)


def test_check_mirror_probes_the_canary_from_a_container(monkeypatch):
    seen = []

    def fake_run(args, **_kw):
        seen.append(args)
        return subprocess.CompletedProcess(args, 0, f"{OK}\n{OK}\n", "")

    monkeypatch.setattr(maven_mirror.subprocess, "run", fake_run)
    assert check_mirror("http://host.docker.internal:8093/maven2/") == []
    args = seen[0]
    assert args[:3] == ["docker", "run", "--rm"]
    assert f"URL=http://host.docker.internal:8093/maven2/{maven_mirror.CANARY}" in args


def test_failed_probe_container_is_a_problem(monkeypatch):
    monkeypatch.setattr(maven_mirror.subprocess, "run",
                        lambda args, **_kw: subprocess.CompletedProcess(args, 125, "", "no image"))
    assert check_mirror("http://m/maven2") == ["probe container exited 125: no image"]

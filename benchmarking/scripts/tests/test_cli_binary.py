import hashlib

from harness.cli_binary import pin_binary


def test_pin_binary_copies_resolved_target_by_content(tmp_path):
    real = tmp_path / "build" / "snyk-local"
    real.parent.mkdir()
    real.write_bytes(b"cli-v1")
    link = tmp_path / "snyk-link"
    link.symlink_to(real)
    store = tmp_path / "store"

    pinned, digest = pin_binary(link, store)
    assert digest == hashlib.sha256(b"cli-v1").hexdigest()
    assert pinned == store / digest[:16] / "snyk"
    assert not pinned.is_symlink() and pinned.read_bytes() == b"cli-v1"

    # A rebuild of the source must not touch the pinned copy.
    real.write_bytes(b"cli-v2")
    assert pinned.read_bytes() == b"cli-v1"
    again, digest2 = pin_binary(link, store)
    assert digest2 != digest and again != pinned
    assert pin_binary(link, store) == (again, digest2)


def test_preview_mounts_its_own_binary_into_the_cases_images():
    from harness.cli_binary import DEFAULT_LOCAL_BINARY, DEFAULT_PREVIEW_BINARY, default_snyk_binary
    from harness.mode import image_key

    assert default_snyk_binary("preview") == DEFAULT_PREVIEW_BINARY
    assert default_snyk_binary("local") == DEFAULT_LOCAL_BINARY
    assert image_key("preview") == image_key("local") == "local"
    assert image_key("release") == "release"


def test_preview_fetch_offline_uses_cached_binary(tmp_path, monkeypatch):
    import pytest
    from harness import cli_binary

    def offline(url):
        raise OSError("network unreachable")

    monkeypatch.setattr(cli_binary, "_fetch_json", offline)
    monkeypatch.setattr(cli_binary, "PREVIEW_VERSION_FILE", tmp_path / "snyk-preview.version")
    dest = tmp_path / "snyk-preview"
    with pytest.raises(OSError):
        cli_binary.fetch_preview_cli(dest)
    dest.write_bytes(b"cached")
    (tmp_path / "snyk-preview.version").write_text("1.2.3-preview\n")
    assert cli_binary.fetch_preview_cli(dest) == "1.2.3-preview"

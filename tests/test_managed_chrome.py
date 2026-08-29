from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from chrome_logger import managed_chrome as managed


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Windows", "AMD64", "win64"),
        ("Windows", "x86", "win32"),
        ("Linux", "x86_64", "linux64"),
        ("Darwin", "arm64", "mac-arm64"),
        ("Darwin", "x86_64", "mac-x64"),
    ],
)
def test_platform_mapping(system: str, machine: str, expected: str) -> None:
    assert managed.chrome_for_testing_platform(system, machine) == expected


def test_platform_mapping_rejects_unsupported_architecture() -> None:
    with pytest.raises(managed.ManagedChromeError, match="not available"):
        managed.chrome_for_testing_platform("Linux", "armv7l")


def test_stable_release_accepts_only_the_exact_official_archive(monkeypatch) -> None:
    version = "150.0.1234.56"
    url = managed._archive_url(version, "win64")
    payload = {
        "channels": {
            "Stable": {
                "version": version,
                "downloads": {"chrome": [{"platform": "win64", "url": url}]},
            }
        }
    }
    monkeypatch.setattr(managed, "_read_https", lambda *_args, **_kwargs: json.dumps(payload).encode())
    assert managed._stable_release("win64") == (version, url)

    payload["channels"]["Stable"]["downloads"]["chrome"][0]["url"] = "https://example.test/chrome.zip"
    with pytest.raises(managed.ManagedChromeError, match="unexpected archive URL"):
        managed._stable_release("win64")


def test_https_validation_rejects_untrusted_hosts_and_paths() -> None:
    for url in (
        "http://storage.googleapis.com/chrome-for-testing-public/a.zip",
        "https://example.test/chrome-for-testing-public/a.zip",
        "https://storage.googleapis.com/other/a.zip",
        "https://user@storage.googleapis.com/chrome-for-testing-public/a.zip",
    ):
        with pytest.raises(managed.ManagedChromeError, match="untrusted"):
            managed._validated_https_target(
                url,
                allowed_host="storage.googleapis.com",
                path_prefix="/chrome-for-testing-public/",
            )


def test_archive_extraction_rejects_path_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../outside.txt", "unsafe")
    destination = tmp_path / "extract"
    destination.mkdir()
    with pytest.raises(managed.ManagedChromeError, match="Unsafe path"):
        managed._extract_archive(archive_path, destination)
    assert not (tmp_path / "outside.txt").exists()


def test_managed_install_is_atomic_and_reuses_the_cached_browser(monkeypatch, tmp_path: Path) -> None:
    version = "150.0.1234.56"
    platform_id = "win64"
    source_url = managed._archive_url(version, platform_id)
    source_archive = tmp_path / "source.zip"
    executable_inside_archive = "chrome-win64/chrome.exe"
    with zipfile.ZipFile(source_archive, "w") as archive:
        archive.writestr(executable_inside_archive, b"synthetic chrome")
        archive.writestr("chrome-win64/resources.pak", b"resources")
    archive_hash = hashlib.sha256(source_archive.read_bytes()).hexdigest()

    monkeypatch.setattr(managed, "chrome_for_testing_platform", lambda: platform_id)
    monkeypatch.setattr(managed, "_stable_release", lambda _platform: (version, source_url))

    downloads: list[str] = []

    def fake_download(url: str, destination: Path, *, maximum: int) -> str:
        assert maximum == managed._MAX_ARCHIVE_BYTES
        downloads.append(url)
        shutil.copyfile(source_archive, destination)
        return archive_hash

    monkeypatch.setattr(managed, "_download_https", fake_download)
    cache = tmp_path / "cache"
    installed = managed.ensure_managed_chrome(cache)

    assert installed.executable.read_bytes() == b"synthetic chrome"
    assert installed.version == version
    assert installed.archive_sha256 == archive_hash
    assert installed.executable_sha256 == hashlib.sha256(b"synthetic chrome").hexdigest()
    assert downloads == [source_url]
    assert json.loads((cache / platform_id / "current.json").read_text())["version"] == version
    assert not list((cache / platform_id).glob(".*.zip"))
    assert not list((cache / platform_id).glob(".*-extract-*"))

    installed.executable.write_bytes(b"tampered")
    assert managed.find_cached_managed_chrome(cache, platform_id=platform_id) is None
    with pytest.raises(managed.ManagedChromeError, match="integrity check"):
        managed.ensure_managed_chrome(cache)
    installed.executable.write_bytes(b"synthetic chrome")

    monkeypatch.setattr(
        managed,
        "_stable_release",
        lambda _platform: (_ for _ in ()).throw(AssertionError("cache should avoid network metadata")),
    )
    cached = managed.ensure_managed_chrome(cache)
    assert cached == installed
    assert downloads == [source_url]

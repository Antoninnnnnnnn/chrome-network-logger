from __future__ import annotations

import hashlib
import io
import json
import re
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
    messages: list[str] = []

    def fake_download(url: str, destination: Path, *, maximum: int, progress=None) -> str:
        assert maximum == managed._MAX_ARCHIVE_BYTES
        downloads.append(url)
        shutil.copyfile(source_archive, destination)
        progress("Downloading Chrome: 100% (0/0 MB)")
        return archive_hash

    monkeypatch.setattr(managed, "_download_https", fake_download)
    cache = tmp_path / "cache"
    installed = managed.ensure_managed_chrome(cache, progress=messages.append)

    assert "Downloading Chrome: 100% (0/0 MB)" in messages
    assert messages.index("Downloading Chrome: 100% (0/0 MB)") < len(messages) - 1  # before "Installed ..."
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


class FakeDownloadResponse:
    def __init__(self, payload: bytes, content_length: str | None) -> None:
        self._source = io.BytesIO(payload)
        self._content_length = content_length

    def getheader(self, name: str) -> str | None:
        return self._content_length if name == "Content-Length" else None

    def read(self, size: int) -> bytes:
        return self._source.read(size)


class FakeConnection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def fake_https(monkeypatch, payload: bytes, content_length: str | None) -> FakeConnection:
    connection = FakeConnection()

    def fake_response(url: str, *, allowed_host: str, path_prefix: str, timeout: float):
        assert allowed_host == managed._DOWNLOAD_HOST
        assert path_prefix == managed._DOWNLOAD_PATH_PREFIX
        return connection, FakeDownloadResponse(payload, content_length)

    monkeypatch.setattr(managed, "_https_response", fake_response)
    return connection


def test_download_reports_progress_every_ten_percent_of_a_known_size(monkeypatch, tmp_path: Path) -> None:
    # A 2.4 MB stand-in for the 150 MB archive: shrinking the "MB" unit keeps the messages realistic.
    unit = 16 * 1024
    payload = bytes(150 * unit)
    monkeypatch.setattr(managed, "_MEBIBYTE", unit)
    monkeypatch.setattr(managed, "_COPY_CHUNK_BYTES", 7 * 1024)  # uneven chunks never land on exact percents
    connection = fake_https(monkeypatch, payload, str(len(payload)))
    messages: list[str] = []
    destination = tmp_path / "chrome.zip"

    digest = managed._download_https(
        managed._archive_url("150.0.1234.56", "win64"),
        destination,
        maximum=managed._MAX_ARCHIVE_BYTES,
        progress=messages.append,
    )

    assert digest == hashlib.sha256(payload).hexdigest()
    assert destination.read_bytes() == payload
    assert connection.closed
    percents = [int(re.match(r"Downloading Chrome: (\d+)% \(\d+/150 MB\)$", message)[1]) for message in messages]
    assert len(percents) == 10
    assert percents[-1] == 100
    assert [percent // 10 for percent in percents] == list(range(1, 11))  # at most one report per 10 % step
    assert messages[3] == "Downloading Chrome: 40% (60/150 MB)"
    assert messages[-1] == "Downloading Chrome: 100% (150/150 MB)"


def test_download_reports_every_16_mb_without_a_content_length(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(managed, "_COPY_CHUNK_BYTES", 1000)
    monkeypatch.setattr(managed, "_PROGRESS_UNKNOWN_SIZE_STEP_BYTES", 4000)
    monkeypatch.setattr(managed, "_MEBIBYTE", 250)  # one step = 16 "MB"
    fake_https(monkeypatch, b"z" * 13_500, None)
    messages: list[str] = []

    managed._download_https(
        managed._archive_url("150.0.1234.56", "win64"),
        tmp_path / "chrome.zip",
        maximum=managed._MAX_ARCHIVE_BYTES,
        progress=messages.append,
    )

    assert messages == ["Downloading Chrome: 16 MB", "Downloading Chrome: 32 MB", "Downloading Chrome: 48 MB"]


def test_download_size_limits_still_apply_with_progress(monkeypatch, tmp_path: Path) -> None:
    url = managed._archive_url("150.0.1234.56", "win64")
    messages: list[str] = []

    fake_https(monkeypatch, b"x" * 100, "100")
    with pytest.raises(managed.ManagedChromeError, match="outside the allowed size limit"):
        managed._download_https(url, tmp_path / "declared.zip", maximum=50, progress=messages.append)
    assert messages == []

    monkeypatch.setattr(managed, "_COPY_CHUNK_BYTES", 10)
    fake_https(monkeypatch, b"x" * 100, None)
    with pytest.raises(managed.ManagedChromeError, match="exceeded the allowed size limit"):
        managed._download_https(url, tmp_path / "streamed.zip", maximum=50, progress=messages.append)

    fake_https(monkeypatch, b"x" * 100, "100")
    assert managed._download_https(url, tmp_path / "silent.zip", maximum=100) == hashlib.sha256(b"x" * 100).hexdigest()

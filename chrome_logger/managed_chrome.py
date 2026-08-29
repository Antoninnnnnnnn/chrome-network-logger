from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import platform
import re
import shutil
import ssl
import stat
import sys
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

LOG = logging.getLogger(__name__)

METADATA_URL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
_METADATA_HOST = "googlechromelabs.github.io"
_DOWNLOAD_HOST = "storage.googleapis.com"
_DOWNLOAD_PATH_PREFIX = "/chrome-for-testing-public/"
_MAX_METADATA_BYTES = 1024 * 1024
_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
_MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 20_000
_COPY_CHUNK_BYTES = 1024 * 1024
_VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){3}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

ProgressCallback = Callable[[str], None]


class ManagedChromeError(RuntimeError):
    """Raised when the managed Chrome fallback cannot be installed safely."""


@dataclass(frozen=True, slots=True)
class ManagedChrome:
    executable: Path
    version: str
    platform: str
    source_url: str
    archive_sha256: str
    executable_sha256: str
    cache_dir: Path


def default_managed_chrome_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
    return base / "chrome-network-logger" / "chrome-for-testing"


def chrome_for_testing_platform(system: str | None = None, machine: str | None = None) -> str:
    system_name = (system or platform.system()).casefold()
    architecture = (machine or platform.machine()).casefold().replace("-", "_")
    x64 = {"amd64", "x86_64", "x64", "arm64", "aarch64"}
    x86 = {"x86", "i386", "i686"}

    if system_name == "windows":
        if architecture in x64:
            return "win64"
        if architecture in x86:
            return "win32"
    elif system_name == "linux" and architecture in {"amd64", "x86_64", "x64"}:
        return "linux64"
    elif system_name == "darwin":
        if architecture in {"arm64", "aarch64"}:
            return "mac-arm64"
        if architecture in {"amd64", "x86_64", "x64"}:
            return "mac-x64"
    raise ManagedChromeError(f"Chrome for Testing is not available for {system_name}/{architecture}")


def _relative_executable(platform_id: str) -> Path:
    root = f"chrome-{platform_id}"
    if platform_id.startswith("win"):
        return Path(root) / "chrome.exe"
    if platform_id == "linux64":
        return Path(root) / "chrome"
    if platform_id.startswith("mac-"):
        return Path(root) / "Google Chrome for Testing.app" / "Contents" / "MacOS" / "Google Chrome for Testing"
    raise ManagedChromeError(f"Unsupported Chrome for Testing platform: {platform_id}")


def _archive_url(version: str, platform_id: str) -> str:
    return f"https://{_DOWNLOAD_HOST}/chrome-for-testing-public/{version}/{platform_id}/chrome-{platform_id}.zip"


def _validated_https_target(url: str, *, allowed_host: str, path_prefix: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ManagedChromeError(f"Invalid official Chrome URL: {url!r}") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != allowed_host
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path.startswith(path_prefix)
    ):
        raise ManagedChromeError(f"Refusing untrusted Chrome download URL: {url!r}")
    target = urlunsplit(("", "", parsed.path, parsed.query, ""))
    return parsed.hostname, target


def _https_response(url: str, *, allowed_host: str, path_prefix: str, timeout: float):
    host, target = _validated_https_target(url, allowed_host=allowed_host, path_prefix=path_prefix)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection(host, 443, timeout=timeout, context=context)
    try:
        connection.request(
            "GET",
            target,
            headers={
                "Accept": "application/json" if url == METADATA_URL else "application/zip",
                "Accept-Encoding": "identity",
                "User-Agent": "chrome-network-logger",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ManagedChromeError(f"Official Chrome endpoint returned HTTP {response.status}")
        return connection, response
    except ManagedChromeError:
        connection.close()
        raise
    except (OSError, http.client.HTTPException) as exc:
        connection.close()
        raise ManagedChromeError(f"Could not reach the official Chrome endpoint: {exc}") from exc


def _declared_size(response: http.client.HTTPResponse, maximum: int) -> None:
    raw_length = response.getheader("Content-Length")
    if raw_length is None:
        return
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise ManagedChromeError("Official Chrome endpoint returned an invalid Content-Length") from exc
    if length < 0 or length > maximum:
        raise ManagedChromeError(f"Chrome download is outside the allowed size limit ({length} bytes)")


def _read_https(url: str, *, allowed_host: str, path_prefix: str, maximum: int) -> bytes:
    connection, response = _https_response(
        url,
        allowed_host=allowed_host,
        path_prefix=path_prefix,
        timeout=30,
    )
    data = bytearray()
    try:
        _declared_size(response, maximum)
        while chunk := response.read(min(_COPY_CHUNK_BYTES, maximum + 1 - len(data))):
            data.extend(chunk)
            if len(data) > maximum:
                raise ManagedChromeError("Official Chrome metadata exceeded the allowed size limit")
        return bytes(data)
    except ManagedChromeError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise ManagedChromeError(f"Could not read official Chrome metadata: {exc}") from exc
    finally:
        connection.close()


def _download_https(url: str, destination: Path, *, maximum: int) -> str:
    connection, response = _https_response(
        url,
        allowed_host=_DOWNLOAD_HOST,
        path_prefix=_DOWNLOAD_PATH_PREFIX,
        timeout=60,
    )
    digest = hashlib.sha256()
    downloaded = 0
    try:
        _declared_size(response, maximum)
        with destination.open("wb") as output:
            while chunk := response.read(_COPY_CHUNK_BYTES):
                downloaded += len(chunk)
                if downloaded > maximum:
                    raise ManagedChromeError("Chrome archive exceeded the allowed size limit")
                digest.update(chunk)
                output.write(chunk)
        if downloaded == 0:
            raise ManagedChromeError("Official Chrome endpoint returned an empty archive")
        return digest.hexdigest()
    except ManagedChromeError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise ManagedChromeError(f"Could not download the official Chrome archive: {exc}") from exc
    finally:
        connection.close()


def _stable_release(platform_id: str) -> tuple[str, str]:
    raw = _read_https(
        METADATA_URL,
        allowed_host=_METADATA_HOST,
        path_prefix="/chrome-for-testing/",
        maximum=_MAX_METADATA_BYTES,
    )
    try:
        payload = json.loads(raw.decode("utf-8"))
        stable = payload["channels"]["Stable"]
        version = stable["version"]
        downloads = stable["downloads"]["chrome"]
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManagedChromeError("Official Chrome metadata has an unexpected format") from exc
    if not isinstance(version, str) or not _VERSION_PATTERN.fullmatch(version):
        raise ManagedChromeError("Official Chrome metadata contains an invalid Stable version")
    if not isinstance(downloads, list):
        raise ManagedChromeError("Official Chrome metadata contains an invalid download list")
    matches = [item for item in downloads if isinstance(item, dict) and item.get("platform") == platform_id]
    if len(matches) != 1 or not isinstance(matches[0].get("url"), str):
        raise ManagedChromeError(f"Official Chrome metadata has no unique {platform_id} download")
    url = matches[0]["url"]
    expected = _archive_url(version, platform_id)
    if url != expected:
        raise ManagedChromeError("Official Chrome metadata returned an unexpected archive URL")
    _validated_https_target(url, allowed_host=_DOWNLOAD_HOST, path_prefix=_DOWNLOAD_PATH_PREFIX)
    return version, url


def _read_manifest(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > 64 * 1024:
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", suffix=".tmp", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _sha256_file(path: Path, *, maximum: int = _MAX_EXPANDED_BYTES) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while chunk := source.read(_COPY_CHUNK_BYTES):
            total += len(chunk)
            if total > maximum:
                raise ManagedChromeError(f"Managed Chrome file exceeds the integrity-check limit: {path}")
            digest.update(chunk)
    if total == 0:
        raise ManagedChromeError(f"Managed Chrome file is empty: {path}")
    return digest.hexdigest()


def find_cached_managed_chrome(
    cache_dir: Path | None = None,
    *,
    platform_id: str | None = None,
) -> ManagedChrome | None:
    root = (cache_dir or default_managed_chrome_dir()).expanduser().resolve()
    selected_platform = platform_id or chrome_for_testing_platform()
    manifest = _read_manifest(root / selected_platform / "current.json")
    if not manifest:
        return None
    version = manifest.get("version")
    archive_sha256 = manifest.get("archiveSha256")
    executable_sha256 = manifest.get("executableSha256")
    if (
        manifest.get("platform") != selected_platform
        or not isinstance(version, str)
        or not _VERSION_PATTERN.fullmatch(version)
        or not isinstance(archive_sha256, str)
        or not _SHA256_PATTERN.fullmatch(archive_sha256)
        or not isinstance(executable_sha256, str)
        or not _SHA256_PATTERN.fullmatch(executable_sha256)
    ):
        return None
    executable = root / selected_platform / version / _relative_executable(selected_platform)
    if not executable.is_file() or executable.is_symlink():
        return None
    try:
        if _sha256_file(executable) != executable_sha256:
            return None
    except (ManagedChromeError, OSError):
        return None
    return ManagedChrome(
        executable=executable.resolve(),
        version=version,
        platform=selected_platform,
        source_url=_archive_url(version, selected_platform),
        archive_sha256=archive_sha256,
        executable_sha256=executable_sha256,
        cache_dir=root,
    )


def _safe_member_parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or "\x00" in name:
        raise ManagedChromeError(f"Unsafe path in Chrome archive: {name!r}")
    pure = PurePosixPath(name)
    parts = tuple(part for part in pure.parts if part not in {"", "."})
    if pure.is_absolute() or not parts or any(part == ".." or ":" in part for part in parts):
        raise ManagedChromeError(f"Unsafe path in Chrome archive: {name!r}")
    return parts


def _normalized_link_target(parent: tuple[str, ...], target: str) -> tuple[str, ...]:
    if not target or "\\" in target or "\x00" in target:
        raise ManagedChromeError("Unsafe symbolic link in Chrome archive")
    pure = PurePosixPath(target)
    if pure.is_absolute() or any(":" in part for part in pure.parts):
        raise ManagedChromeError("Unsafe symbolic link in Chrome archive")
    normalized = list(parent)
    for part in pure.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not normalized:
                raise ManagedChromeError("Symbolic link escapes the Chrome archive")
            normalized.pop()
        else:
            normalized.append(part)
    if not normalized:
        raise ManagedChromeError("Unsafe symbolic link in Chrome archive")
    return tuple(normalized)


def _extract_archive(archive_path: Path, destination: Path) -> None:
    try:
        archive = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ManagedChromeError("Downloaded Chrome archive is not a valid ZIP file") from exc
    with archive:
        members = archive.infolist()
        if not members or len(members) > _MAX_ARCHIVE_MEMBERS:
            raise ManagedChromeError("Chrome archive contains an invalid number of files")
        expanded = sum(item.file_size for item in members)
        if expanded <= 0 or expanded > _MAX_EXPANDED_BYTES:
            raise ManagedChromeError("Chrome archive exceeds the expanded size limit")
        seen: set[tuple[str, ...]] = set()
        for item in members:
            parts = _safe_member_parts(item.filename)
            if parts in seen:
                raise ManagedChromeError(f"Duplicate path in Chrome archive: {item.filename!r}")
            seen.add(parts)
            mode = (item.external_attr >> 16) & 0xFFFF
            destination_path = destination.joinpath(*parts)
            if item.is_dir():
                destination_path.mkdir(parents=True, exist_ok=True)
                continue
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            if stat.S_ISLNK(mode):
                try:
                    link_target = archive.read(item).decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ManagedChromeError("Chrome archive contains an invalid symbolic link") from exc
                _normalized_link_target(parts[:-1], link_target)
                try:
                    os.symlink(link_target, destination_path)
                except OSError as exc:
                    raise ManagedChromeError("Could not create a Chrome archive symbolic link") from exc
                continue
            file_type = stat.S_IFMT(mode)
            if file_type and file_type != stat.S_IFREG:
                raise ManagedChromeError(f"Unsupported file type in Chrome archive: {item.filename!r}")
            with archive.open(item) as source, destination_path.open("xb") as output:
                shutil.copyfileobj(source, output, length=_COPY_CHUNK_BYTES)
            if os.name != "nt" and mode:
                destination_path.chmod(mode & 0o777)


def ensure_managed_chrome(
    cache_dir: Path | None = None,
    *,
    refresh: bool = False,
    progress: ProgressCallback | None = None,
) -> ManagedChrome:
    root = (cache_dir or default_managed_chrome_dir()).expanduser().resolve()
    platform_id = chrome_for_testing_platform()
    cached = find_cached_managed_chrome(root, platform_id=platform_id)
    if cached and not refresh:
        return cached

    notify = progress or (lambda message: LOG.info("%s", message))
    notify("Chrome is not installed; checking the official Chrome for Testing Stable channel")
    version, url = _stable_release(platform_id)
    platform_root = root / platform_id
    version_root = platform_root / version
    executable = version_root / _relative_executable(platform_id)

    archive_sha256 = ""
    executable_sha256 = ""
    install_manifest = _read_manifest(version_root / "install.json")
    if executable.is_file() and not executable.is_symlink() and install_manifest:
        recorded_hash = install_manifest.get("archiveSha256")
        recorded_executable_hash = install_manifest.get("executableSha256")
        if (
            isinstance(recorded_hash, str)
            and _SHA256_PATTERN.fullmatch(recorded_hash)
            and isinstance(recorded_executable_hash, str)
            and _SHA256_PATTERN.fullmatch(recorded_executable_hash)
            and _sha256_file(executable) == recorded_executable_hash
        ):
            archive_sha256 = recorded_hash
            executable_sha256 = recorded_executable_hash
        else:
            raise ManagedChromeError(f"Managed Chrome failed its integrity check: {version_root}")
    elif version_root.exists():
        raise ManagedChromeError(f"Managed Chrome cache is incomplete: {version_root}")

    if not archive_sha256:
        platform_root.mkdir(parents=True, exist_ok=True)
        descriptor, archive_name = tempfile.mkstemp(prefix=f".{version}-", suffix=".zip", dir=platform_root)
        os.close(descriptor)
        temporary_archive = Path(archive_name)
        staging: Path | None = Path(tempfile.mkdtemp(prefix=f".{version}-extract-", dir=platform_root))
        try:
            notify(f"Downloading official Chrome for Testing Stable {version} ({platform_id})")
            archive_sha256 = _download_https(url, temporary_archive, maximum=_MAX_ARCHIVE_BYTES)
            _extract_archive(temporary_archive, staging)
            staged_executable = staging / _relative_executable(platform_id)
            if not staged_executable.is_file() or staged_executable.is_symlink():
                raise ManagedChromeError("Chrome executable is missing from the official archive")
            if os.name != "nt":
                staged_executable.chmod(staged_executable.stat().st_mode | 0o755)
            executable_sha256 = _sha256_file(staged_executable)
            _write_json_atomic(
                staging / "install.json",
                {
                    "archiveSha256": archive_sha256,
                    "executableSha256": executable_sha256,
                    "platform": platform_id,
                    "sourceUrl": url,
                    "version": version,
                },
            )
            try:
                os.replace(staging, version_root)
                staging = None
            except FileExistsError as exc:
                if not executable.is_file():
                    raise ManagedChromeError(f"Managed Chrome cache is incomplete: {version_root}") from exc
            notify(f"Installed managed Chrome {version} in {version_root}")
        finally:
            temporary_archive.unlink(missing_ok=True)
            if staging is not None and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    current = {
        "archiveSha256": archive_sha256,
        "executableSha256": executable_sha256,
        "platform": platform_id,
        "sourceUrl": url,
        "version": version,
    }
    _write_json_atomic(platform_root / "current.json", current)
    result = find_cached_managed_chrome(root, platform_id=platform_id)
    if not result:
        raise ManagedChromeError("Managed Chrome installation could not be validated")
    return result

from __future__ import annotations

import json
from pathlib import Path

import pytest

import chrome_logger
from chrome_logger import cli


def test_max_body_size_rejects_negative_and_non_finite_values() -> None:
    parser = cli.build_parser()
    for option in ("--max-body-mb", "--max-session-body-mb", "--duration"):
        for value in ("-1", "nan", "inf", "-inf"):
            with pytest.raises(SystemExit) as error:
                parser.parse_args([option, value])
            assert error.value.code == 2


def test_version_output_is_stable(capsys) -> None:
    with pytest.raises(SystemExit) as error:
        cli.build_parser().parse_args(["--version"])
    assert error.value.code == 0
    assert capsys.readouterr().out == f"chrome-network-logger {chrome_logger.__version__}\n"


def test_start_url_rejects_flags_and_unsupported_schemes() -> None:
    parser = cli.build_parser()
    for value in ("--incognito", "javascript:alert(1)", "relative/path"):
        with pytest.raises(SystemExit) as error:
            parser.parse_args([f"--start-url={value}"])
        assert error.value.code == 2
    assert parser.parse_args(["--start-url", "https://example.test"]).start_url == "https://example.test"


def test_runtime_failure_returns_nonzero_and_records_error(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "find_chrome", lambda _path: Path("fake-chrome"))
    monkeypatch.setattr(cli, "kill_profile_chrome_processes", lambda _path: 0)
    monkeypatch.setattr(cli, "profile_chrome_process_ids", lambda _path: [])
    monkeypatch.setattr(cli, "cleanup_profile_locks", lambda _path: None)
    monkeypatch.setattr(cli, "load_proxies", lambda _path: [])

    def fail_launch(*_args, **_kwargs):
        raise RuntimeError("synthetic launch failure")

    monkeypatch.setattr(cli, "launch_chrome", fail_launch)
    output = tmp_path / "captures"
    code = cli.main(
        [
            "--non-interactive",
            "--output-dir",
            str(output),
            "--profile-dir",
            str(tmp_path / "profile"),
        ]
    )
    assert code == 1
    sessions = list(output.glob("session_*"))
    assert len(sessions) == 1
    manifest = json.loads((sessions[0] / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "error"
    assert any("synthetic launch failure" in warning for warning in manifest["warnings"])


def test_missing_chrome_uses_managed_browser_and_creates_profile(monkeypatch, tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    managed_executable = tmp_path / "managed" / "chrome.exe"
    managed_executable.parent.mkdir()
    managed_executable.touch()
    monkeypatch.setattr(cli, "find_chrome", lambda _path: (_ for _ in ()).throw(FileNotFoundError("missing")))
    monkeypatch.setattr(
        cli,
        "ensure_managed_chrome",
        lambda *_args, **_kwargs: cli.ManagedChrome(
            executable=managed_executable,
            version="150.0.1234.56",
            platform="win64",
            source_url="https://storage.googleapis.com/chrome-for-testing-public/test.zip",
            archive_sha256="a" * 64,
            executable_sha256="b" * 64,
            cache_dir=tmp_path / "managed",
        ),
    )
    monkeypatch.setattr(cli, "kill_profile_chrome_processes", lambda _path: 0)
    monkeypatch.setattr(cli, "profile_chrome_process_ids", lambda _path: [])
    monkeypatch.setattr(cli, "cleanup_profile_locks", lambda _path: None)
    monkeypatch.setattr(cli, "load_proxies", lambda _path: [])
    monkeypatch.setattr(cli, "launch_chrome", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("stop")))

    output = tmp_path / "captures"
    code = cli.main(
        [
            "--non-interactive",
            "--output-dir",
            str(output),
            "--profile-dir",
            str(profile),
        ]
    )

    assert code == 1
    assert profile.is_dir()
    manifest = json.loads(next(output.glob("session_*/manifest.json")).read_text(encoding="utf-8"))
    assert manifest["browserInstall"] == {
        "source": "chromeForTestingStable",
        "version": "150.0.1234.56",
        "platform": "win64",
        "archiveSha256": "a" * 64,
        "executableSha256": "b" * 64,
    }


def test_no_download_chrome_fails_cleanly_but_still_creates_profile(monkeypatch, tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    monkeypatch.setattr(cli, "find_chrome", lambda _path: (_ for _ in ()).throw(FileNotFoundError("missing")))
    monkeypatch.setattr(
        cli,
        "ensure_managed_chrome",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("download must stay disabled")),
    )

    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "--non-interactive",
                "--no-download-chrome",
                "--output-dir",
                str(tmp_path / "captures"),
                "--profile-dir",
                str(profile),
            ]
        )

    assert error.value.code == 2
    assert profile.is_dir()


def test_stop_reasons_are_explained_in_plain_language() -> None:
    assert cli._human_reason("signal:2") == "you stopped it (Ctrl+C)"
    assert cli._human_reason("keyboardInterrupt") == "you stopped it (Ctrl+C)"
    assert cli._human_reason("chromeExited") == "you closed the browser"
    assert cli._human_reason("cdpDisconnected") == "the browser connection dropped"
    assert cli._human_reason("durationElapsed") == "the requested duration elapsed"
    assert cli._human_reason("error:RuntimeError") == "a capture error (RuntimeError)"
    assert cli._human_reason("somethingNew") == "somethingNew"


def test_session_summary_states_that_data_was_saved(capsys, tmp_path: Path) -> None:
    stats = {
        "requests": 120,
        "bodies": 44,
        "bodyErrors": 0,
        "cookieChanges": 9,
        "storageChanges": 3,
        "storageFlushes": 2,
        "idbEntries": 12,
        "cacheEntries": 5,
    }
    cli._print_session_summary(tmp_path / "session_x", "partial", "chromeExited", stats)
    output = capsys.readouterr().out
    assert "Capture stopped: you closed the browser" in output
    assert "All captured data was written to disk." in output
    assert "Requests: 120 | bodies stored: 44 | bodies unavailable: 0" in output
    assert "IndexedDB records: 12 | Cache Storage entries: 5" in output
    assert "in flight" not in output
    assert "reports" in output and "requests.jsonl" in output


def test_session_summary_reports_in_flight_requests_and_errors(capsys, tmp_path: Path) -> None:
    cli._print_session_summary(tmp_path / "session_y", "partial", "signal:2", {"incompleteFlushed": 7})
    output = capsys.readouterr().out
    assert "7 request(s) were still in flight" in output

    cli._print_session_summary(tmp_path / "session_z", "error", "error:OSError", None)
    output = capsys.readouterr().out
    assert "Some data could not be finalized" in output
    assert "All captured data was written to disk." not in output

from __future__ import annotations

import json
from pathlib import Path

import pytest

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
    assert capsys.readouterr().out == "chrome-network-logger 3.0.0\n"


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

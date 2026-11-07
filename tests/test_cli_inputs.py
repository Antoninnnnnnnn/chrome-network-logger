"""CLI argument validation, prompts without a terminal and stop-reason wording."""

from __future__ import annotations

import builtins
from pathlib import Path

import pytest

from chrome_logger import cli


@pytest.mark.parametrize("option", ["--max-idb-entries", "--max-cache-entries"])
@pytest.mark.parametrize("value", ["0", "-3", "many"])
def test_entry_limits_must_be_positive_integers(option: str, value: str) -> None:
    with pytest.raises(SystemExit) as error:
        cli.build_parser().parse_args([option, value])
    assert error.value.code == 2


def test_invalid_configuration_is_a_usage_error_not_a_traceback(monkeypatch, tmp_path: Path, capsys) -> None:
    def invalid(self) -> None:
        raise ValueError("synthetic invalid configuration")

    monkeypatch.setattr(cli.CaptureConfig, "validate", invalid)
    with pytest.raises(SystemExit) as error:
        cli.main(["--non-interactive", "--output-dir", str(tmp_path), "--profile-dir", str(tmp_path / "p")])
    assert error.value.code == 2
    assert "synthetic invalid configuration" in capsys.readouterr().err


def test_prompt_treats_a_closed_stdin_as_an_empty_answer(monkeypatch) -> None:
    def closed(_message: str) -> str:
        raise EOFError

    monkeypatch.setattr(builtins, "input", closed)
    assert cli._prompt("question? ") == ""


def test_output_folder_prompt_survives_a_closed_stdin(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(builtins, "input", lambda _message: (_ for _ in ()).throw(EOFError()))
    assert cli._output_parent(None, non_interactive=False) == tmp_path


def test_stop_reasons_name_the_signal() -> None:
    sigint = int(cli.signal.SIGINT)
    sigterm = int(cli.signal.SIGTERM)
    assert cli._human_reason(f"signal:{sigint}") == "you stopped it (Ctrl+C)"
    assert cli._human_reason(f"signal:{sigterm}") == "it received SIGTERM"
    assert cli._human_reason("signal:not-a-number") == "it received not-a-number"


def test_har_export_can_be_disabled() -> None:
    assert cli.build_parser().parse_args(["--no-har"]).no_har is True
    assert cli.build_parser().parse_args([]).no_har is False

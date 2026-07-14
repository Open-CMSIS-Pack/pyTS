from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pyts.cli import main
from pyts.trace import TraceSetupResult


def test_top_level_trace_setup_outputs_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cbuild_run = Path("out/Blinky.cbuild-run.yml")
    calls: list[tuple[Path, bool]] = []

    def fake_setup_trace(path: Path, allow_missing: bool = False) -> TraceSetupResult:
        calls.append((path, allow_missing))
        return TraceSetupResult(
            cbuild_run=str(path),
            ctrace=".cmsis/Target.ctrace.yml",
            output=".trace/Target.ctrace-run.yml",
            target="Target",
            symbols=["main"],
            missing=[],
        )

    monkeypatch.setattr("pyts.cli.setup_trace", fake_setup_trace)

    assert main([str(cbuild_run), "--format", "json"]) == 0

    assert calls == [(cbuild_run, False)]
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "cbuild_run": str(cbuild_run),
        "ctrace": ".cmsis/Target.ctrace.yml",
        "output": ".trace/Target.ctrace-run.yml",
        "target": "Target",
        "symbols": ["main"],
        "missing": [],
    }


def test_top_level_trace_setup_allows_missing_symbols(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cbuild_run = Path("out/Blinky.cbuild-run.yml")
    calls: list[tuple[Path, bool]] = []

    def fake_setup_trace(path: Path, allow_missing: bool = False) -> TraceSetupResult:
        calls.append((path, allow_missing))
        return TraceSetupResult(
            cbuild_run=str(path),
            ctrace=".cmsis/Target.ctrace.yml",
            output=".trace/Target.ctrace-run.yml",
            target="Target",
            symbols=[],
            missing=["missing"],
        )

    monkeypatch.setattr("pyts.cli.setup_trace", fake_setup_trace)

    assert main([str(cbuild_run), "--allow-missing", "--format", "json"]) == 0

    assert calls == [(cbuild_run, True)]
    payload = json.loads(capsys.readouterr().out)
    assert payload["missing"] == ["missing"]


def test_top_level_trace_setup_reports_missing_symbols(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_setup_trace(path: Path, allow_missing: bool = False) -> Any:
        raise ValueError("missing symbols: osRtxInfo.thread.run.curr")

    monkeypatch.setattr("pyts.cli.setup_trace", fake_setup_trace)

    assert main(["Blinky.cbuild-run.yml"]) == 2

    captured = capsys.readouterr()
    assert "missing symbols: osRtxInfo.thread.run.curr" in captured.err


def test_top_level_help_documents_trace_setup(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Generate a CMSIS trace run configuration." in captured.out
    assert "cbuild_run" in captured.out
    assert "--allow-missing" in captured.out


def test_old_command_groups_are_rejected(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for command in ("yaml", "elf", "trace"):
        with pytest.raises(SystemExit) as exc_info:
            main([command])

        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert f"removed command group '{command}'" in captured.err

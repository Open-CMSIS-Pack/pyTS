# Copyright 2026 Arm Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file was created using artificial intelligence.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pyts._version import package_version
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
            ctrace=".cmsis/Blinky+Target.ctrace.yml",
            output=".trace/Blinky+Target.ctrace-run.yml",
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
        "ctrace": ".cmsis/Blinky+Target.ctrace.yml",
        "output": ".trace/Blinky+Target.ctrace-run.yml",
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
            ctrace=".cmsis/Blinky+Target.ctrace.yml",
            output=".trace/Blinky+Target.ctrace-run.yml",
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


@pytest.mark.parametrize("option", ["-V", "--version"])
def test_top_level_version(option: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main([option])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out == f"pyts {package_version()}\n"

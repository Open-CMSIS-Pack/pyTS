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

"""CLI status codes for diagnostics written to trace run files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pyts.cli import main
from pyts.yaml_io import read_yaml, write_yaml


def _write_project(
    tmp_path: Path,
    setup: dict[str, Any],
    *,
    with_processor: bool = True,
) -> tuple[Path, Path]:
    project = tmp_path / "project"
    output_dir = project / "out"
    cmsis_dir = project / ".cmsis"
    output_dir.mkdir(parents=True)
    cmsis_dir.mkdir()
    cbuild_run = output_dir / "Blinky+Target.cbuild-run.yml"
    cbuild_data: dict[str, Any] = {
        "solution": "../Blinky.csolution.yml",
        "target-type": "Target",
        "output": [{"file": "Blinky.axf", "type": "elf"}],
    }
    if with_processor:
        cbuild_data["system-resources"] = {"processors": [{"core": "CM4"}]}
    write_yaml(cbuild_run, {"cbuild-run": cbuild_data})
    write_yaml(cmsis_dir / "Blinky+Target.ctrace.yml", {"ctrace": {"setup": [setup]}})
    return cbuild_run, project / ".trace" / "Blinky+Target.ctrace-run.yml"


_STATUS_CASES: list[tuple[dict[str, Any], list[str], str | None, int]] = [
    ({"timestamps": None, "events": [{}]}, [], "error", 2),
    ({"timestamps": None, "events": [{}]}, ["--pedantic"], "error", 2),
    ({"data": [{"location": 0x20000000, "size": 3}]}, [], "warning", 0),
    (
        {"data": [{"location": 0x20000000, "size": 3}]},
        ["--pedantic"],
        "warning",
        2,
    ),
    (
        {"data": [{"location": 0x20000000, "size": 4, "symbol-type": "object"}]},
        ["--pedantic"],
        "info",
        0,
    ),
    ({"timestamps": None}, ["--pedantic"], None, 0),
]


@pytest.mark.parametrize(
    ("setup", "options", "diagnostic", "expected_status"), _STATUS_CASES
)
def test_cli_status_for_generated_refs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    setup: dict[str, Any],
    options: list[str],
    diagnostic: str | None,
    expected_status: int,
) -> None:
    cbuild_run, output_path = _write_project(tmp_path, setup)

    status = main([str(cbuild_run), *options, "--format", "json"])

    output = read_yaml(output_path)
    refs = output["ctrace-run"]["ctrace-refs"]
    if diagnostic is not None:
        assert any(diagnostic in ref for ref in refs)
    assert status == expected_status
    summary = json.loads(capsys.readouterr().out)
    assert summary["output"] == str(output_path)


def test_cli_status_for_written_location_error_with_allow_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cbuild_run, output_path = _write_project(
        tmp_path, {"data": [{"location": "missing"}]}, with_processor=False
    )

    status = main([str(cbuild_run), "--allow-missing", "--format", "json"])

    output = read_yaml(output_path)
    assert "error" in output["ctrace"]["setup"][0]["data"][0]
    assert status == 2
    assert json.loads(capsys.readouterr().out)["missing"] == ["missing"]

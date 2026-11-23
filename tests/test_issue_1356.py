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

"""Regressions for https://github.com/Open-CMSIS-Pack/vscode-cmsis-debugger/issues/1356."""

from pathlib import Path

import pytest

from pyts.cli import main
from pyts.yaml_io import read_yaml


_BUILD = """cbuild-run:
  solution: ../Blinky.csolution.yml
  target-type: Target
  system-resources:
    processors:
      - core: CM4
  output:
    - file: Blinky.hex
      type: hex
"""

_TRACE = """ctrace:
  setup:
    - data:
        - location: counter
        - location: 0x20000000
          size: 4
"""


@pytest.mark.parametrize("outputs", ["hex", "missing-elf", "none"])
@pytest.mark.parametrize("options", [[], ["--allow-missing"]])
def test_missing_elf_writes_field_diagnostics(
    tmp_path: Path, outputs: str, options: list[str]
) -> None:
    build = tmp_path / "out" / "Blinky+Target.cbuild-run.yml"
    build.parent.mkdir()
    source = tmp_path / ".cmsis" / "Blinky+Target.ctrace.yml"
    source.parent.mkdir()
    text = _BUILD
    if outputs == "missing-elf":
        text = text.replace("Blinky.hex", "Blinky.axf").replace("type: hex", "type: elf")
    elif outputs == "none":
        text = text[:text.index("  output:")]
    build.write_text(text, encoding="utf-8")
    source.write_text(_TRACE, encoding="utf-8")

    assert main([str(build), *options]) == 2

    output = tmp_path / ".trace" / "Blinky+Target.ctrace-run.yml"
    refs = read_yaml(output)["ctrace-run"]["ctrace-refs"]
    failed = next(ref for ref in refs if ref["ref"] == "data#0")
    assert "ELF" in failed["error"]
    assert "regs" not in failed
    fixed = next(ref for ref in refs if ref["ref"] == "data#1")
    assert "error" not in fixed
    assert fixed["regs"]
    assert source.read_text(encoding="utf-8") == _TRACE


@pytest.mark.parametrize("missing", ["ctrace", "cbuild-run"])
def test_missing_input_writes_root_diagnostic(tmp_path: Path, missing: str) -> None:
    build = tmp_path / "Blinky+Target.cbuild-run.yml"
    if missing == "ctrace":
        build.write_text(_BUILD.replace("../Blinky", "Blinky"), encoding="utf-8")

    assert main([str(build)]) == 2

    output = tmp_path / ".trace" / "Blinky+Target.ctrace-run.yml"
    refs = read_yaml(output)["ctrace-run"]["ctrace-refs"]
    assert refs[0]["ref"] == "ctrace"
    assert "file not found" in refs[0]["error"]
    assert "regs" not in refs[0]


def test_missing_legacy_elf_still_writes_output(tmp_path: Path) -> None:
    build = tmp_path / "Blinky+Target.cbuild-run.yml"
    build.write_text(
        _BUILD.replace("../Blinky", "Blinky")
        .replace("Blinky.hex", "Blinky.axf").replace("type: hex", "type: elf"),
        encoding="utf-8",
    )
    source = tmp_path / ".cmsis" / "Blinky+Target.ctrace.yml"
    source.parent.mkdir()
    source.write_text("ctrace:\n  data:\n    - symbol: counter\n", encoding="utf-8")

    assert main([str(build)]) == 2

    output = read_yaml(tmp_path / ".trace" / "Blinky+Target.ctrace-run.yml")
    assert "ELF" in output["ctrace"]["data"][0]["error"]


def test_rejects_malformed_output_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    build = tmp_path / "Blinky+Target.cbuild-run.yml"
    build.write_text(_BUILD.replace("  output:\n", "  output: invalid\n  ignored:\n"), encoding="utf-8")

    assert main([str(build)]) == 2
    assert "cbuild-run.output must be a list" in capsys.readouterr().err


def test_restoring_missing_trace_input_clears_root_error(tmp_path: Path) -> None:
    build = tmp_path / "Blinky+Target.cbuild-run.yml"
    build.write_text(_BUILD.replace("../Blinky", "Blinky"), encoding="utf-8")
    assert main([str(build)]) == 2
    source = tmp_path / ".cmsis" / "Blinky+Target.ctrace.yml"
    source.parent.mkdir()
    source.write_text(
        "ctrace:\n  setup:\n    - data:\n        - location: 0x20000000\n          size: 4\n",
        encoding="utf-8",
    )

    assert main([str(build)]) == 0

    output = read_yaml(tmp_path / ".trace" / "Blinky+Target.ctrace-run.yml")
    assert all("error" not in ref for ref in output["ctrace-run"]["ctrace-refs"])

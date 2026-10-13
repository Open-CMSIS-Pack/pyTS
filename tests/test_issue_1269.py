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

"""Regressions for https://github.com/Open-CMSIS-Pack/vscode-cmsis-debugger/issues/1269."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from pyts.cli import main
from pyts.coresight import Processor, generate_ctrace_run
from pyts.domain import YamlMapping
from pyts.yaml_io import read_yaml


_SYNCHRONIZATION_DEFAULT_REF = {
    "ref": "synchronization/DWT", "type": "dwt", "stream": 1,
    "regs": [
        {"name": "DWT_CTRL", "value": 0x400, "mask": 0xC00},
        {"name": "ITM_TCR", "value": 5, "mask": 5},
    ],
}


def _generate_run(
    tmp_path: Path,
    source: str,
    processors: list[Processor],
) -> dict[str, Any]:
    path = tmp_path / "source.ctrace.yml"
    path.write_text(source, encoding="utf-8")
    document = read_yaml(path)
    original = deepcopy(document)
    output = generate_ctrace_run(document, processors, original)
    run = cast(dict[str, Any], output["ctrace-run"])
    assert original == read_yaml(path)
    expected_setups = cast(list[YamlMapping], read_yaml(path)["ctrace"]["setup"])
    for setup in expected_setups:
        timesync = setup.get("timesync")
        if isinstance(timesync, dict):
            mode = timesync.get("ITM")
            if isinstance(mode, int) and not isinstance(mode, bool):
                timesync["ITM"] = str(mode)
    assert run["ctrace-setup"] == expected_setups
    return run


@pytest.mark.parametrize("core", ["CM4", "CM33"])
@pytest.mark.parametrize(
    ("mode", "value"),
    [
        ("off", 0),
        ("'off'", 0),
        ('"off"', 0),
        ("128", 0x401),
        ('"128"', 0x401),
        ("0x80", 0x401),
        ("8192", 0x801),
        ('"8192"', 0x801),
        ("0x2000", 0x801),
        ("packet", 0xC01),
    ],
)
def test_issue_1269_encodes_itm_global_timestamp_modes(
    tmp_path: Path, core: str, mode: str, value: int
) -> None:
    run = _generate_run(
        tmp_path,
        f"ctrace:\n  setup:\n    - timesync:\n        ITM: {mode}\n",
        [Processor.from_core(core, None)],
    )
    expected: list[dict[str, Any]] = [_SYNCHRONIZATION_DEFAULT_REF]
    if value:
        expected.append({
            "ref": "timesync/ITM", "type": "global_ts", "stream": 1,
            "regs": [{"name": "ITM_TCR", "value": value, "mask": 0xC01}],
        })
    assert run["ctrace-refs"] == expected
    assert run["ctrace-setup"][0]["timesync"]["ITM"] == {
        0: "off", 0x401: "128", 0x801: "8192", 0xC01: "packet",
    }[value]


@pytest.mark.parametrize("pname", [None, "core"])
@pytest.mark.parametrize("mode", ["off", "'off'", '"off"'])
def test_issue_1269_off_uses_initial_disable_without_allocating_a_stream(
    tmp_path: Path, pname: str | None, mode: str,
) -> None:
    path = tmp_path / "source.ctrace.yml"
    pname_line = "" if pname is None else f"      pname: {pname}\n"
    path.write_text(
        f"ctrace:\n  setup:\n    - timesync:\n        ITM: {mode}\n"
        f"{pname_line}      synchronization:\n        DWT: off\n",
        encoding="utf-8",
    )
    document = read_yaml(path)
    before = deepcopy(document)
    output = generate_ctrace_run(document, [Processor.from_core("CM4", "core")])
    run = cast(dict[str, Any], output["ctrace-run"])
    assert run["ctrace-refs"] == []
    assert {"name": "ITM_TCR", "value": 0} in run["ctrace-disable"][0]["regs"]
    assert run["ctrace-setup"] == before["ctrace"]["setup"]
    assert document == before


@pytest.mark.parametrize(
    "setup",
    [
        "{}",
        "timesync:",
        "timesync: {}",
        "timesync:\n        ITM:",
        "timesync:\n        extension: future",
        "timesync:\n        itm: packet",
    ],
)
def test_issue_1269_defaults_absent_and_empty_timesync_to_off(
    tmp_path: Path, setup: str
) -> None:
    run = _generate_run(
        tmp_path,
        f"ctrace:\n  setup:\n    - {setup}\n",
        [Processor.from_core("CM4", None)],
    )
    assert run["ctrace-refs"] == [_SYNCHRONIZATION_DEFAULT_REF]


@pytest.mark.parametrize(
    "mode",
    [
        "true", "false", "0", "256", "128.0", "8192.0",
        '"0x80"', '"0128"', '"128 "', "OFF", "Packet", "[]", "{}",
    ],
)
def test_issue_1269_rejects_invalid_itm_modes(tmp_path: Path, mode: str) -> None:
    run = _generate_run(
        tmp_path,
        f"ctrace:\n  setup:\n    - timesync:\n        ITM: {mode}\n",
        [Processor.from_core("CM4", None)],
    )
    ref = next(ref for ref in run["ctrace-refs"] if ref["ref"] == "timesync/ITM")
    assert ref["ref"] == "timesync/ITM"
    assert "timesync.ITM" in ref["error"]
    assert "regs" not in ref
    assert "stream" not in ref


@pytest.mark.parametrize("container", ["false", "128", "packet", "[]"])
def test_issue_1269_rejects_invalid_timesync_containers(
    tmp_path: Path, container: str
) -> None:
    run = _generate_run(
        tmp_path,
        f"ctrace:\n  setup:\n    - timesync: {container}\n",
        [Processor.from_core("CM4", None)],
    )
    assert run["ctrace-refs"] == [
        _SYNCHRONIZATION_DEFAULT_REF,
        {"ref": "timesync/ITM", "type": "global_ts", "error": "timesync must be a mapping"}
    ]


def test_issue_1269_allocates_streams_for_selected_processors(tmp_path: Path) -> None:
    run = _generate_run(
        tmp_path,
        """\
ctrace:
  setup:
    - pname: application
      timesync:
        ITM: 8192
    - pname: network
      timesync:
        ITM: packet
    - pname: disabled
      disable:
""",
        [
            Processor.from_core("CM33", "application"),
            Processor.from_core("CM4", "network"),
            Processor.from_core("CM4", "disabled"),
        ],
    )
    refs = {ref["ref"]: ref for ref in run["ctrace-refs"]}
    assert set(refs) == {
        f"{pname}/{feature}"
        for pname in ("application", "network")
        for feature in ("itm", "synchronization/DWT", "timesync/ITM")
    }
    for pname, value, stream in [("application", 0x801, 1), ("network", 0xC01, 2)]:
        assert refs[f"{pname}/timesync/ITM"] == {
            "ref": f"{pname}/timesync/ITM",
            "type": "global_ts",
            "pname": pname,
            "regs": [{"name": "ITM_TCR", "value": value, "mask": 0xC01}],
            "stream": stream,
        }
        assert refs[f"{pname}/itm"]["regs"] == [
            {"name": "ITM_TCR", "value": stream << 16, "mask": 0x7F0000}
        ]
        assert refs[f"{pname}/synchronization/DWT"] == {
            **_SYNCHRONIZATION_DEFAULT_REF,
            "ref": f"{pname}/synchronization/DWT", "pname": pname, "stream": stream,
        }


def test_issue_1269_default_preserves_other_itm_features(tmp_path: Path) -> None:
    run = _generate_run(
        tmp_path,
        """\
ctrace:
  setup:
    - timestamps:
      itm:
        enable: 1
        atbid: 7
""",
        [Processor.from_core("CM4", None)],
    )
    refs = {ref["ref"]: ref for ref in run["ctrace-refs"]}
    assert "timesync/ITM" not in refs
    assert refs["timestamps"]["stream"] == refs["itm"]["stream"] == 7
    assert refs["timestamps"]["regs"] == [
        {"name": "ITM_TCR", "value": 3, "mask": 0x303}
    ]
    assert refs["itm"]["regs"][-1] == {
        "name": "ITM_TCR", "value": 0x70001, "mask": 0x7F0001
    }


@pytest.mark.parametrize("setup", ["{}", "timesync:\n        ITM: packet", "timesync: false"])
def test_issue_1269_preserves_unsupported_core_diagnostics(
    tmp_path: Path, setup: str
) -> None:
    run = _generate_run(
        tmp_path,
        f"ctrace:\n  setup:\n    - {setup}\n",
        [Processor.from_core("CM0", None)],
    )
    expected = [
        {
            "ref": "synchronization/DWT",
            "type": "dwt",
            "error": "core CM0 has no architectural ITM/DWT trace support",
        },
    ]
    if setup != "{}":
        expected.append({
            "ref": "timesync/ITM",
            "type": "global_ts",
            "error": "core CM0 has no architectural ITM/DWT trace support",
        })
    assert run["ctrace-refs"] == expected


def test_issue_1269_does_not_create_missing_setups(tmp_path: Path) -> None:
    run = _generate_run(
        tmp_path, "ctrace:\n  setup: []\n", [Processor.from_core("CM4", None)]
    )
    assert run["ctrace-refs"] == []


@pytest.mark.parametrize("mode", ["off", "128", '"128"', "8192", '"8192"'])
def test_issue_1269_cli_writes_timesync_registers(tmp_path: Path, mode: str) -> None:
    (tmp_path / ".cmsis").mkdir()
    cbuild = tmp_path / "Blinky+Target.cbuild-run.yml"
    cbuild.write_text(
        """\
cbuild-run:
  solution: Blinky.csolution.yml
  target-type: Target
  output:
    - file: Blinky.axf
      type: elf
  system-resources:
    processors:
      - core: CM4
""",
        encoding="utf-8",
    )
    (tmp_path / ".cmsis" / "Blinky+Target.ctrace.yml").write_text(
        f"ctrace:\n  setup:\n    - timesync:\n        ITM: {mode}\n",
        encoding="utf-8",
    )
    assert main([str(cbuild), "--pedantic"]) == 0
    output_path = tmp_path / ".trace" / "Blinky+Target.ctrace-run.yml"
    output = read_yaml(output_path)
    assert output["ctrace-run"]["ctrace-setup"][0]["timesync"]["ITM"] == (
        mode.strip('"')
    )
    refs = {ref["ref"]: ref for ref in output["ctrace-run"]["ctrace-refs"]}
    if mode == "off":
        assert "timesync/ITM" not in refs
    else:
        assert "error" not in refs["timesync/ITM"]
    assert refs["synchronization/DWT"] == _SYNCHRONIZATION_DEFAULT_REF
    assert "mask: 0x00000c" in output_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("use_original", [False, True])
def test_issue_1269_normalizes_output_without_changing_inputs(
    tmp_path: Path, use_original: bool
) -> None:
    path = tmp_path / "source.ctrace.yml"
    path.write_text(
        """\
ctrace:
  setup:
    - timesync:
        ITM: 128
      itm:
        atbid: 1
""",
        encoding="utf-8",
    )
    document = read_yaml(path)
    original = deepcopy(document) if use_original else None
    if original is not None:
        original["ctrace"]["setup"][0]["timesync"]["ITM"] = 8192
    before_document = deepcopy(document)
    before_original = deepcopy(original)

    output = generate_ctrace_run(
        document, [Processor.from_core("CM4", None)], original,
    )
    run = cast(dict[str, Any], output["ctrace-run"])
    assert run["ctrace-setup"][0]["timesync"]["ITM"] == (
        "8192" if use_original else "128"
    )
    assert document == before_document
    assert original == before_original


def test_issue_1269_normalizes_disabled_setups_and_preserves_non_mappings(
    tmp_path: Path,
) -> None:
    path = tmp_path / "source.ctrace.yml"
    path.write_text(
        """\
ctrace:
  setup:
    -
    - disable:
      timesync:
        ITM: 0x80
""",
        encoding="utf-8",
    )
    document = read_yaml(path)
    output = generate_ctrace_run(document, [Processor.from_core("CM4", None)])
    run = cast(dict[str, Any], output["ctrace-run"])
    assert run["ctrace-setup"] == [
        None, {"disable": None, "timesync": {"ITM": "128"}},
    ]
    assert document == read_yaml(path)
    assert run["ctrace-refs"] == []

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

"""DWT synchronization references target the feature inside its YAML group."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from pyts.coresight import Processor, generate_ctrace_run
from pyts.cli import main
from pyts.domain import YamlMapping
from pyts.yaml_io import read_yaml


def _generate(tmp_path: Path, setup: str, core: str = "CM4") -> dict[str, Any]:
    path = tmp_path / "trace.yml"
    path.write_text(f"ctrace:\n  setup:\n    - {setup}\n", encoding="utf-8")
    document = read_yaml(path)
    original = deepcopy(document)
    output = generate_ctrace_run(
        document, [Processor.from_core(core, "core")], original,
    )
    assert original == read_yaml(path)
    run = cast(dict[str, Any], output["ctrace-run"])
    expected_setups = cast(list[YamlMapping], read_yaml(path)["ctrace"]["setup"])
    for entry in expected_setups:
        synchronization = entry.get("synchronization")
        if isinstance(synchronization, dict):
            mode = synchronization.get("DWT")
            if isinstance(mode, int) and not isinstance(mode, bool):
                synchronization["DWT"] = str(mode)
    assert run["ctrace-setup"] == expected_setups
    return run


@pytest.mark.parametrize("pname", [None, "core"])
@pytest.mark.parametrize(
    ("mode", "encoding", "normalized"),
    [
        ("16M", 1, "16M"), ("64M", 2, "64M"), ("256M", 3, "256M"),
        ("0", 0, "0"), ('"0"', 0, "0"), ("0x0", 0, "0"),
        ("off", 0, "off"), ("'off'", 0, "off"), ('"off"', 0, "off"),
    ],
)
def test_dwt_modes_reference_the_complete_feature_path(
    tmp_path: Path, pname: str | None, mode: str, encoding: int, normalized: str,
) -> None:
    setup = f"synchronization:\n        DWT: {mode}"
    if pname is not None:
        setup = f"pname: {pname}\n      {setup}"
    run = _generate(tmp_path, setup)
    ref_name = "synchronization/DWT" if pname is None else f"{pname}/synchronization/DWT"
    refs = [ref for ref in run["ctrace-refs"] if ref["ref"] == ref_name]
    if encoding:
        assert len(refs) == 1
        assert refs[0]["type"] == "dwt"
        assert refs[0]["regs"] == [
            {"name": "DWT_CTRL", "value": encoding << 10, "mask": 0xC00},
            {"name": "ITM_TCR", "value": 5, "mask": 5},
        ]
        assert refs[0]["stream"] == 1
    else:
        assert run["ctrace-refs"] == []
        assert {"name": "ITM_TCR", "value": 0} in run["ctrace-disable"][0]["regs"]
    assert all(ref["ref"] != "synchronization" for ref in run["ctrace-refs"])
    assert run["ctrace-setup"][0]["synchronization"]["DWT"] == normalized


@pytest.mark.parametrize("setup", [
    "{}", "synchronization:", "synchronization: {}", "synchronization:\n        DWT:",
    "synchronization:\n        extension: future", "synchronization:\n        dwt: 64M",
])
def test_missing_dwt_defaults_to_16m_regardless_of_group_presence(
    tmp_path: Path, setup: str,
) -> None:
    assert _generate(tmp_path, setup)["ctrace-refs"] == [
        {
            "ref": "synchronization/DWT", "type": "dwt", "stream": 1,
            "regs": [
                {"name": "DWT_CTRL", "value": 0x400, "mask": 0xC00},
                {"name": "ITM_TCR", "value": 5, "mask": 5},
            ],
        },
    ]


@pytest.mark.parametrize("use_original", [False, True])
@pytest.mark.parametrize("pname", [None, "core"])
def test_absent_feature_groups_use_defaults_without_adding_yaml_nodes(
    tmp_path: Path, use_original: bool, pname: str | None,
) -> None:
    path = tmp_path / "trace.yml"
    setup = "itm:\n        enable: 0\n        atbid: 7"
    if pname is not None:
        setup = f"pname: {pname}\n      {setup}"
    path.write_text(f"ctrace:\n  setup:\n    - {setup}\n", encoding="utf-8")
    document = read_yaml(path)
    original = deepcopy(document) if use_original else None
    before = deepcopy(document)
    output = generate_ctrace_run(document, [Processor.from_core("CM4", "core")], original)
    run = cast(dict[str, Any], output["ctrace-run"])
    prefix = f"{pname}/" if pname else ""
    refs = {ref["ref"]: ref for ref in run["ctrace-refs"]}
    assert refs[f"{prefix}synchronization/DWT"] == {
        "ref": f"{prefix}synchronization/DWT", "type": "dwt", "stream": 7,
        "regs": [
            {"name": "DWT_CTRL", "value": 0x400, "mask": 0xC00},
            {"name": "ITM_TCR", "value": 5, "mask": 5},
        ],
    }
    assert f"{prefix}timesync/ITM" not in refs
    assert run["ctrace-setup"] == before["ctrace"]["setup"]
    assert document == before
    if original is not None:
        assert original == before


@pytest.mark.parametrize("core", ["CM4", "CM0"])
@pytest.mark.parametrize("container", ["false", "128", "packet", "[]"])
def test_invalid_group_has_feature_reference_and_preserves_error_precedence(
    tmp_path: Path, core: str, container: str,
) -> None:
    error = (
        "synchronization must be a mapping" if core == "CM4"
        else "core CM0 has no architectural ITM/DWT trace support"
    )
    assert _generate(tmp_path, f"synchronization: {container}", core)["ctrace-refs"] == [
        {"ref": "synchronization/DWT", "type": "dwt", "error": error},
    ]


@pytest.mark.parametrize(
    "mode",
    ["true", "false", "1", "0.0", "[]", "{}", '"00"', '"0x0"',
     '"0 "', '"16M "', "16m", "32M", "OFF", "Off", "on", "yes", "no"],
)
def test_invalid_dwt_scalar_has_feature_reference(tmp_path: Path, mode: str) -> None:
    ref = _generate(tmp_path, f"synchronization:\n        DWT: {mode}")["ctrace-refs"][0]
    assert ref["ref"] == "synchronization/DWT"
    assert "unsupported synchronization.DWT" in ref["error"]
    assert "regs" not in ref
    assert "stream" not in ref


def test_unknown_group_properties_and_setup_values_are_preserved(tmp_path: Path) -> None:
    run = _generate(tmp_path, """\
synchronization:
        DWT: 0
        sync-on-run: true
        extension: future
""")
    assert run["ctrace-refs"] == []


@pytest.mark.parametrize("use_original", [False, True])
def test_dwt_and_timesync_output_normalization_does_not_change_input_documents(
    tmp_path: Path, use_original: bool,
) -> None:
    path = tmp_path / "trace.yml"
    path.write_text(
        """\
ctrace:
  setup:
    - synchronization:
        DWT: 0
      timesync:
        ITM: 128
      itm:
        atbid: 1
        enable: 0
""",
        encoding="utf-8",
    )
    document = read_yaml(path)
    original = deepcopy(document) if use_original else None
    if original is not None:
        document["ctrace"]["setup"][0]["synchronization"]["extension"] = "internal"
    before_document = deepcopy(document)
    before_original = deepcopy(original)
    output = generate_ctrace_run(document, [Processor.from_core("CM4", None)], original)
    run = cast(dict[str, Any], output["ctrace-run"])
    assert run["ctrace-setup"] == [{
        "synchronization": {"DWT": "0"}, "timesync": {"ITM": "128"},
        "itm": {"atbid": 1, "enable": 0},
    }]
    assert all("error" not in ref for ref in run["ctrace-refs"])
    assert [ref for ref in run["ctrace-refs"] if ref["ref"] != "itm"] == [
        {
            "ref": "timesync/ITM", "type": "global_ts", "stream": 1,
            "regs": [{"name": "ITM_TCR", "value": 0x401, "mask": 0xC01}],
        },
    ]
    assert document == before_document
    assert original == before_original


def test_dwt_normalizes_disabled_setups_and_preserves_non_mappings(tmp_path: Path) -> None:
    path = tmp_path / "trace.yml"
    path.write_text(
        """\
ctrace:
  setup:
    -
    - disable:
      synchronization:
        DWT: 0x0
""",
        encoding="utf-8",
    )
    document = read_yaml(path)
    output = generate_ctrace_run(document, [Processor.from_core("CM4", None)])
    run = cast(dict[str, Any], output["ctrace-run"])
    assert run["ctrace-setup"] == [
        None, {"disable": None, "synchronization": {"DWT": "0"}},
    ]
    assert run["ctrace-refs"] == []
    assert document == read_yaml(path)


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("0", "0"), ('"0"', "0"), ("0x0", "0"),
     ("off", "off"), ("'off'", "off"), ('"off"', "off")],
)
def test_cli_serializes_normalized_dwt_as_a_string(
    tmp_path: Path, mode: str, expected: str,
) -> None:
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
        f"ctrace:\n  setup:\n    - synchronization:\n        DWT: {mode}\n",
        encoding="utf-8",
    )
    assert main([str(cbuild), "--pedantic"]) == 0
    output = read_yaml(tmp_path / ".trace" / "Blinky+Target.ctrace-run.yml")
    run = output["ctrace-run"]
    assert run["ctrace-setup"][0]["synchronization"]["DWT"] == expected
    assert run["ctrace-refs"] == []

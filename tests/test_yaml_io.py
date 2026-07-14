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

from pathlib import Path

import yaml

from pyts.yaml_io import HexInt, read_yaml, write_yaml


def test_read_and_write_yaml(tmp_path: Path) -> None:
    path = tmp_path / "config.yml"
    data = {
        "trace": {
            "enabled": True,
            "symbols": ["main", "SystemInit"],
        }
    }

    write_yaml(path, data)

    assert read_yaml(path) == data


def test_write_yaml_formats_hex_int_as_numeric_hex_scalar(tmp_path: Path) -> None:
    path = tmp_path / "registers.yml"

    write_yaml(path, {"address": HexInt(0x08000100), "mask": HexInt(0x303)})

    assert path.read_text(encoding="utf-8") == (
        "address: 0x08000100\n"
        "mask: 0x00000303\n"
    )
    assert read_yaml(path) == {"address": 0x08000100, "mask": 0x303}


def test_write_yaml_preserves_valueless_nodes(tmp_path: Path) -> None:
    path = tmp_path / "flags.yml"

    write_yaml(path, {"exceptions": None, "timesync": None})

    assert path.read_text(encoding="utf-8") == "exceptions:\ntimesync:\n"
    assert read_yaml(path) == {"exceptions": None, "timesync": None}


def test_pyts_dumper_does_not_modify_global_safe_dumper(tmp_path: Path) -> None:
    path = tmp_path / "flags.yml"

    write_yaml(path, {"exceptions": None})

    assert path.read_text(encoding="utf-8") == "exceptions:\n"
    assert yaml.safe_dump({"exceptions": None}) == "exceptions: null\n"

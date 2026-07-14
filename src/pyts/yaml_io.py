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

"""YAML file helpers used by the CLI and library callers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, TextIO

import yaml


class HexInt(int):
    """Integer serialized as an eight-digit hexadecimal YAML scalar."""


class _PyTSSafeDumper(yaml.SafeDumper):
    """Safe YAML dumper with formatting isolated to pyTS output."""


def _represent_hex_int(dumper: yaml.SafeDumper, value: HexInt) -> yaml.Node:
    """Represent a marked integer as an eight-digit hexadecimal scalar."""

    return dumper.represent_scalar(  # pyright: ignore[reportUnknownMemberType]
        "tag:yaml.org,2002:int",
        f"0x{int(value):08x}",
    )


def _represent_none(dumper: yaml.SafeDumper, _value: None) -> yaml.Node:
    """Represent ``None`` as a valueless YAML node."""

    return dumper.represent_scalar(  # pyright: ignore[reportUnknownMemberType]
        "tag:yaml.org,2002:null",
        "",
    )


_PyTSSafeDumper.add_representer(HexInt, _represent_hex_int)
_PyTSSafeDumper.add_representer(type(None), _represent_none)


def read_yaml(path: str | Path) -> Any:
    """Read one YAML document from a filesystem path using safe parsing.

    ``path`` may be a string or ``Path``. The file is opened as UTF-8 text and
    parsed with ``yaml.safe_load``, so arbitrary Python objects are not
    constructed. Empty documents return ``None``, matching PyYAML behavior.
    """

    with Path(path).open("r", encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def write_yaml(path: str | Path, data: Any, *, sort_keys: bool = False) -> None:
    """Write *data* as block-style YAML to a filesystem path.

    ``path`` may be a string or ``Path``. The file is written as UTF-8 text via
    ``yaml.safe_dump``. Set ``sort_keys=True`` to sort mapping keys; by default,
    insertion order is preserved.
    """

    with Path(path).open("w", encoding="utf-8") as stream:
        write_yaml_stream(stream, data, sort_keys=sort_keys)


def write_yaml_stream(stream: TextIO, data: Any, *, sort_keys: bool = False) -> None:
    """Write *data* as block-style YAML to an already-open text stream.

    The caller owns the stream. Unicode characters are emitted directly,
    mappings are written in insertion order unless ``sort_keys`` is true, and
    arbitrary Python-specific YAML tags are not emitted by ``yaml.safe_dump``.
    """

    yaml.dump(
        data,
        stream,
        Dumper=_PyTSSafeDumper,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=sort_keys,
    )

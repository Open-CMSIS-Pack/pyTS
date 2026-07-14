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

"""Shared domain primitives used across pyTS subsystems."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias


JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)
YamlMapping: TypeAlias = dict[str, JsonValue]
EntryPath: TypeAlias = tuple[str | int, ...]


@dataclass(frozen=True)
class EntryRef:
    """Stable path and mapping pair for an entry in a YAML document."""

    path: EntryPath
    value: YamlMapping

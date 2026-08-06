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

"""Public protocols and immutable result values for ELF resolution."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol


class ELFLike(Protocol):
    """Small subset of ``pyelftools.ELFFile`` used by pyTS."""

    def iter_sections(self) -> Iterable[object]:
        """Iterate sections exposed by the ELF object."""

        ...

    def get_section(self, n: int) -> object:
        """Return the section at index *n*."""

        ...


class DwarfELFLike(ELFLike, Protocol):
    """ELF-like object that can expose DWARF debug information."""

    def has_dwarf_info(self) -> bool:
        """Return whether DWARF information is available."""

        ...

    def get_dwarf_info(self) -> Any:
        """Return the pyelftools-compatible DWARF information object."""

        ...


@dataclass(frozen=True)
class SymbolInfo:
    """Metadata resolved from an ELF symbol table or DWARF variable."""

    name: str
    address: int
    size: int
    type: str
    binding: str
    visibility: str
    section: str | None
    table: str
    source_file: str | None = None
    source_type: str | None = None

    @property
    def address_hex(self) -> str:
        """Return the symbol address formatted as hexadecimal."""

        return f"0x{self.address:x}"

@dataclass(frozen=True)
class MemberInfo:
    """Metadata resolved for a dotted DWARF object member expression."""

    name: str
    address: int
    size: int
    type: str
    base_symbol: str
    member_path: str
    offset: int
    source: str = "dwarf"
    source_file: str | None = None
    source_type: str | None = None

    @property
    def address_hex(self) -> str:
        """Return the member address formatted as hexadecimal."""

        return f"0x{self.address:x}"

def missing_symbols(
    found: Iterable[SymbolInfo | MemberInfo],
    names: Sequence[str],
) -> list[str]:
    """Return requested names absent from *found*, preserving order."""

    resolved = {symbol.name for symbol in found}
    return [name for name in names if name not in resolved]

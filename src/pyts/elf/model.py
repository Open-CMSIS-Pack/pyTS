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
from dataclasses import asdict, dataclass
from typing import Any, Protocol


class ELFLike(Protocol):
    """Small subset of ``pyelftools.ELFFile`` used by pyTS."""

    def iter_sections(self) -> Iterable[object]:
        """Iterate sections exposed by the ELF object."""

        ...

    def get_section(self, index: int) -> object:
        """Return the section at *index*."""

        ...


class DwarfELFLike(ELFLike, Protocol):
    """ELF-like object that can expose DWARF debug information."""

    def has_dwarf_info(self) -> bool:
        """Return whether DWARF information is available."""

        ...

    def get_dwarf_info(self) -> Any:
        """Return the pyelftools-compatible DWARF information object."""

        ...


@dataclass(frozen=True, init=False)
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

    def __init__(
        self,
        name: str,
        address: int,
        address_hex: str | None = None,
        size: int = 0,
        type: str = "",
        binding: str = "",
        visibility: str = "",
        section: str | None = None,
        table: str = "",
        source_file: str | None = None,
    ) -> None:
        """Create symbol metadata and validate an optional derived hex value."""

        expected_hex = f"0x{address:x}"
        if address_hex is not None and address_hex != expected_hex:
            raise ValueError("address_hex must be derived from address")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "address", address)
        object.__setattr__(self, "size", size)
        object.__setattr__(self, "type", type)
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "visibility", visibility)
        object.__setattr__(self, "section", section)
        object.__setattr__(self, "table", table)
        object.__setattr__(self, "source_file", source_file)

    @property
    def address_hex(self) -> str:
        """Return the symbol address formatted as hexadecimal."""

        return f"0x{self.address:x}"

    def to_dict(self) -> dict[str, int | str | None]:
        """Return serialization-ready metadata including the derived address."""

        result = asdict(self)
        result["address_hex"] = self.address_hex
        if result["source_file"] is None:
            del result["source_file"]
        return result


@dataclass(frozen=True, init=False)
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

    def __init__(
        self,
        name: str,
        address: int,
        address_hex: str | None = None,
        size: int = 0,
        type: str = "",
        base_symbol: str = "",
        member_path: str = "",
        offset: int = 0,
        offset_hex: str | None = None,
        source: str = "dwarf",
        source_file: str | None = None,
    ) -> None:
        """Create member metadata and validate optional derived hex values."""

        if address_hex is not None and address_hex != f"0x{address:x}":
            raise ValueError("address_hex must be derived from address")
        if offset_hex is not None and offset_hex != f"0x{offset:x}":
            raise ValueError("offset_hex must be derived from offset")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "address", address)
        object.__setattr__(self, "size", size)
        object.__setattr__(self, "type", type)
        object.__setattr__(self, "base_symbol", base_symbol)
        object.__setattr__(self, "member_path", member_path)
        object.__setattr__(self, "offset", offset)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "source_file", source_file)

    @property
    def address_hex(self) -> str:
        """Return the member address formatted as hexadecimal."""

        return f"0x{self.address:x}"

    @property
    def offset_hex(self) -> str:
        """Return the member offset formatted as hexadecimal."""

        return f"0x{self.offset:x}"

    def to_dict(self) -> dict[str, int | str | None]:
        """Return serialization-ready metadata with derived hex fields."""

        result = asdict(self)
        result["address_hex"] = self.address_hex
        result["offset_hex"] = self.offset_hex
        if result["source_file"] is None:
            del result["source_file"]
        return result


def missing_symbols(
    found: Iterable[SymbolInfo | MemberInfo],
    names: Sequence[str],
) -> list[str]:
    """Return requested names absent from *found*, preserving order."""

    resolved = {symbol.name for symbol in found}
    return [name for name in names if name not in resolved]

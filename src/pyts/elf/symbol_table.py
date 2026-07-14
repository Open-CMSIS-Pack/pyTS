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

"""ELF symbol-table parsing and indexed lookup."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import SupportsInt, cast

from elftools.elf.sections import SymbolTableSection

from pyts.elf.model import ELFLike, SymbolInfo


class SymbolIndex:
    """Cache and query symbol tables from one open ELF object."""

    def __init__(self, elf_file: ELFLike) -> None:
        """Create an empty lazy index for one open ELF object."""

        self._elf_file = elf_file
        self._symbols: dict[bool, list[SymbolInfo]] = {}
        self._by_address: dict[int, SymbolInfo] | None = None
        self._by_name: dict[str, list[SymbolInfo]] | None = None

    def symbols(self, include_undefined: bool = False) -> list[SymbolInfo]:
        """Return cached symbols, optionally including undefined entries."""

        if include_undefined not in self._symbols:
            self._symbols[include_undefined] = defined_symbols(
                self._elf_file,
                include_undefined=include_undefined,
            )
        return self._symbols[include_undefined]

    def resolve_names(
        self,
        names: Sequence[str],
        *,
        include_undefined: bool = False,
    ) -> tuple[list[SymbolInfo], set[str]]:
        """Resolve names in table order and return the exact matched names."""

        wanted = set(names)
        results: list[SymbolInfo] = []
        if include_undefined:
            exact: set[str] = set()
        else:
            self._ensure_indexes()
            assert self._by_name is not None
            exact = wanted.intersection(self._by_name)
        for symbol in self.symbols(include_undefined):
            if symbol.name in wanted:
                exact.add(symbol.name)
                results.append(symbol)
        return results, exact

    def resolve_address(self, address: int) -> SymbolInfo | None:
        """Return the first defined symbol whose address matches exactly."""

        self._ensure_indexes()
        assert self._by_address is not None
        return self._by_address.get(address)

    def by_name(self, include_undefined: bool = False) -> dict[str, SymbolInfo]:
        """Return the last symbol-table entry for each symbol name."""

        return {
            symbol.name: symbol for symbol in self.symbols(include_undefined)
        }

    def _ensure_indexes(self) -> None:
        """Build defined-symbol name and address indexes once."""

        if self._by_address is not None:
            return
        by_address: dict[int, SymbolInfo] = {}
        by_name: dict[str, list[SymbolInfo]] = {}
        for symbol in self.symbols(False):
            by_address.setdefault(symbol.address, symbol)
            by_name.setdefault(symbol.name, []).append(symbol)
        self._by_address = by_address
        self._by_name = by_name


def defined_symbols(
    elf_file: ELFLike,
    *,
    include_undefined: bool,
) -> list[SymbolInfo]:
    """Parse symbol metadata from every symbol table in an ELF object."""

    results: list[SymbolInfo] = []
    for table in symbol_tables(elf_file):
        table_name = getattr(table, "name", "<symbols>")
        for symbol in table.iter_symbols():
            name = getattr(symbol, "name", "")
            if not name:
                continue
            section = section_name(elf_file, entry_value(symbol, "st_shndx"))
            if section is None and not include_undefined:
                continue
            address = int_entry(symbol, "st_value")
            results.append(
                SymbolInfo(
                    name=name,
                    address=address,
                    size=int_entry(symbol, "st_size"),
                    type=enum_value(mapping_entry(symbol, "st_info").get("type")),
                    binding=enum_value(mapping_entry(symbol, "st_info").get("bind")),
                    visibility=enum_value(
                        mapping_entry(symbol, "st_other").get("visibility")
                    ),
                    section=section,
                    table=table_name,
                )
            )
    return results


def symbol_tables(elf_file: ELFLike) -> Iterable[SymbolTableSection]:
    """Yield symbol-table sections from an ELF object."""

    for section in elf_file.iter_sections():
        if isinstance(section, SymbolTableSection):
            yield section


def entry_value(symbol: object, key: str, default: object = None) -> object:
    """Read a symbol entry field from mapping or index-style APIs."""

    entry = getattr(symbol, "entry", None)
    if entry is not None:
        return entry.get(key, default)
    try:
        return symbol[key]  # type: ignore[index]
    except (KeyError, TypeError):
        return default


def int_entry(symbol: object, key: str) -> int:
    """Read and coerce an integer symbol entry field."""

    value = entry_value(symbol, key, 0) or 0
    if isinstance(value, int):
        return value
    return int(cast(SupportsInt, value))


def mapping_entry(symbol: object, key: str) -> dict[str, object]:
    """Read a mapping-valued symbol entry field."""

    value = entry_value(symbol, key, {})
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def section_name(elf_file: ELFLike, section_index: object) -> str | None:
    """Resolve a section index or special section constant to a name."""

    if section_index in (None, "SHN_UNDEF"):
        return None
    if isinstance(section_index, str):
        return section_index.removeprefix("SHN_").lower()
    try:
        section = elf_file.get_section(int(cast(SupportsInt, section_index)))
    except (IndexError, TypeError, ValueError):
        return str(section_index)
    return getattr(section, "name", str(section_index))


def enum_value(value: object) -> str:
    """Normalize an ELF enum value to a lowercase unprefixed string."""

    if value is None:
        return ""
    text = str(value)
    for prefix in ("STT_", "STB_", "STV_"):
        text = text.removeprefix(prefix)
    return text.lower()

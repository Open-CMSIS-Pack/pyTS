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

"""Cached DWARF index coordinating member and source-qualified lookup."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pyts.elf.dwarf_members import (
    die_size,
    die_symbol_type,
    die_type,
    dwarf_name,
    dwarf_type_name,
    dwarf_type_size,
    find_dwarf_variable,
    iter_object_members,
    resolve_die_address,
    resolve_member_path,
    split_member_expression,
    unwrap_dwarf_type,
)
from pyts.elf.dwarf_sources import (
    die_source_file,
    die_source_matches,
    normalize_source_file,
)
from pyts.elf.model import DwarfELFLike, MemberInfo, SymbolInfo
from pyts.elf.symbol_table import SymbolIndex


class DwarfIndex:
    """Cache DWARF metadata and expose focused lookup operations."""

    def __init__(self, elf_file: DwarfELFLike) -> None:
        """Create lazy caches for one ELF object's DWARF metadata."""

        self._elf_file = elf_file
        self._checked = False
        self._info: Any | None = None
        self._members_by_expression: dict[str, MemberInfo | None] = {}
        self._all_members: list[MemberInfo] | None = None
        self._source_files: set[str] | None = None

    def resolve_members(
        self,
        expressions: Sequence[str],
        *,
        source_file: str | None = None,
    ) -> list[MemberInfo]:
        """Resolve dotted expressions, caching both matches and misses."""

        results: list[MemberInfo] = []
        for expression in expressions:
            key = source_cache_key(expression, source_file)
            if key not in self._members_by_expression:
                self._members_by_expression[key] = self._resolve_member(
                    expression,
                    source_file=source_file,
                )
            member = self._members_by_expression[key]
            if member is not None:
                results.append(member)
        return results

    def resolve_members_by_address(
        self,
        members: Sequence[tuple[int, int]],
    ) -> list[MemberInfo]:
        """Return all members matching requested address and size pairs."""

        wanted = set(members)
        if not wanted:
            return []
        return [
            member
            for member in self._member_cache()
            if (member.address, member.size) in wanted
        ]

    def source_files(self) -> set[str]:
        """Return cached declaration-file paths found across all DIEs."""

        if self._source_files is None:
            info = self._dwarf_info()
            files: set[str] = set()
            if info is not None:
                for cu in info.iter_CUs():
                    for die in cu.iter_DIEs():
                        source_file = die_source_file(info, cu, die)
                        if source_file:
                            files.add(source_file)
            self._source_files = files
        return set(self._source_files)

    def resolve_symbols_by_source(
        self,
        names: Sequence[str],
        source_file: str,
        symbols: SymbolIndex,
        *,
        include_undefined: bool,
    ) -> list[SymbolInfo | MemberInfo]:
        """Resolve names only when their DWARF declaration file matches."""

        if not names:
            return []
        results: list[SymbolInfo | MemberInfo] = []
        member_expressions = [name for name in names if "." in name]
        if member_expressions:
            results.extend(
                self.resolve_members(member_expressions, source_file=source_file)
            )
        plain_names = [name for name in names if "." not in name]
        if plain_names:
            results.extend(
                self._resolve_plain_symbols(
                    plain_names,
                    source_file,
                    symbols,
                    include_undefined=include_undefined,
                )
            )
        return results

    def _resolve_member(
        self,
        expression: str,
        *,
        source_file: str | None,
    ) -> MemberInfo | None:
        """Resolve one dotted member expression from DWARF metadata."""

        info = self._dwarf_info()
        parsed = split_member_expression(expression)
        if info is None or parsed is None:
            return None
        base_name, member_names = parsed
        variable = find_dwarf_variable(info, base_name, source_file=source_file)
        if variable is None:
            return None
        cu, die = variable
        base_address = resolve_die_address(info, cu, die)
        if base_address is None:
            return None
        resolved = resolve_member_path(die, member_names)
        if resolved is None:
            return None
        offset, member_type = resolved
        address = base_address + offset
        return MemberInfo(
            name=expression,
            address=address,
            size=dwarf_type_size(cu, member_type),
            type=dwarf_type_name(member_type),
            base_symbol=base_name,
            member_path=".".join(member_names),
            offset=offset,
            source_file=die_source_file(info, cu, die),
        )

    def _resolve_plain_symbols(
        self,
        names: Sequence[str],
        source_file: str,
        symbols: SymbolIndex,
        *,
        include_undefined: bool,
    ) -> list[SymbolInfo]:
        """Resolve source-qualified variables and subprograms."""

        info = self._dwarf_info()
        if info is None:
            return []
        wanted = set(names)
        results: list[SymbolInfo] = []
        exact_symbols = symbols.by_name(include_undefined)
        for cu in info.iter_CUs():
            for die in cu.iter_DIEs():
                symbol = self._plain_symbol_from_die(
                    info, cu, die, wanted, source_file, exact_symbols
                )
                if symbol is not None:
                    results.append(symbol)
        return results

    @staticmethod
    def _plain_symbol_from_die(
        info: Any,
        cu: Any,
        die: Any,
        wanted: set[str],
        source_file: str,
        exact_symbols: dict[str, SymbolInfo],
    ) -> SymbolInfo | None:
        """Build one source-qualified symbol from a matching DIE."""

        if die.tag not in {"DW_TAG_variable", "DW_TAG_subprogram"}:
            return None
        name = dwarf_name(die)
        if name not in wanted or not die_source_matches(
            info, cu, die, source_file
        ):
            return None
        die_source = die_source_file(info, cu, die)
        symbol = exact_symbols.get(name)
        if symbol is not None:
            return SymbolInfo(
                name=symbol.name,
                address=symbol.address,
                size=symbol.size,
                type=symbol.type,
                binding=symbol.binding,
                visibility=symbol.visibility,
                section=symbol.section,
                table=symbol.table,
                source_file=die_source,
            )
        address = resolve_die_address(info, cu, die)
        if address is None:
            return None
        return SymbolInfo(
            name=name,
            address=address,
            size=die_size(cu, die),
            type=die_symbol_type(die),
            binding="",
            visibility="",
            section=None,
            table="dwarf",
            source_file=die_source,
        )

    def _member_cache(self) -> list[MemberInfo]:
        """Discover and cache every addressable DWARF object member."""

        if self._all_members is not None:
            return self._all_members
        info = self._dwarf_info()
        members = [] if info is None else self._discover_members(info)
        self._all_members = members
        return members

    @staticmethod
    def _discover_members(info: Any) -> list[MemberInfo]:
        """Collect addressable members from all variable DIEs."""

        members: list[MemberInfo] = []
        for cu in info.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_variable":
                    continue
                base_name = dwarf_name(die)
                base_address = resolve_die_address(info, cu, die)
                base_type = unwrap_dwarf_type(die_type(die))
                if not base_name or base_address is None or base_type is None:
                    continue
                members.extend(
                    iter_object_members(
                        info, cu, die, base_name, base_address, base_type
                    )
                )
        return members

    def _dwarf_info(self) -> Any | None:
        """Return DWARF information once, caching its absence as well."""

        if not self._checked:
            self._checked = True
            try:
                has_info = bool(self._elf_file.has_dwarf_info())
            except AttributeError:
                has_info = False
            if has_info:
                self._info = self._elf_file.get_dwarf_info()
        return self._info


def source_cache_key(expression: str, source_file: str | None) -> str:
    """Build a cache key from an expression and optional source qualifier."""

    if source_file is None:
        return expression
    return f"{normalize_source_file(source_file)}::{expression}"

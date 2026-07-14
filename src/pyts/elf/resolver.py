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

"""Public resource-owning façade for ELF and DWARF lookup."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from elftools.elf.elffile import ELFFile

from pyts.elf.dwarf import DwarfIndex
from pyts.elf.model import DwarfELFLike, ELFLike, MemberInfo, SymbolInfo
from pyts.elf.symbol_table import SymbolIndex


class ElfResolver:
    """Resolve symbols and DWARF members from one lazily opened ELF file."""

    def __init__(
        self,
        elf_path: str | Path,
    ) -> None:
        """Create a resolver for a filesystem path."""

        self.elf_path = Path(elf_path)
        self._stream: Any | None = None
        self._elf_file: ELFLike | None = None
        self._closed = False
        self._symbol_index: SymbolIndex | None = None
        self._dwarf_index: DwarfIndex | None = None

    def __enter__(self) -> ElfResolver:
        """Open the ELF source if necessary and return this resolver."""

        self._ensure_open()
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close resources owned by this resolver."""

        self.close()

    def close(self) -> None:
        """Close owned resources and permanently close this resolver."""

        if self._closed:
            return
        if self._stream is not None:
            self._stream.close()
        self._stream = None
        self._elf_file = None
        self._symbol_index = None
        self._dwarf_index = None
        self._closed = True

    def resolve_symbols(
        self,
        names: Sequence[str] | None = None,
        *,
        include_undefined: bool = False,
        source_file: str | None = None,
    ) -> list[SymbolInfo | MemberInfo]:
        """Resolve symbols and dotted DWARF expressions by name."""

        self._check_open()
        requested = list(names or ())
        if source_file is not None:
            return self._dwarf().resolve_symbols_by_source(
                requested,
                source_file,
                self._symbols(),
                include_undefined=include_undefined,
            )
        if not requested:
            return list(self._symbols().symbols(include_undefined))

        results, exact_matches = self._symbols().resolve_names(
            requested,
            include_undefined=include_undefined,
        )
        member_expressions = [
            name for name in requested if "." in name and name not in exact_matches
        ]
        if member_expressions:
            results_with_members: list[SymbolInfo | MemberInfo] = list(results)
            results_with_members.extend(
                self._dwarf().resolve_members(member_expressions)
            )
            return results_with_members
        return list(results)

    def resolve_address(self, address: int) -> SymbolInfo | None:
        """Return the first defined symbol at an exact address."""

        self._check_open()
        return self._symbols().resolve_address(address)

    def resolve_object_members_by_address(
        self,
        members: Sequence[tuple[int, int]],
    ) -> list[MemberInfo]:
        """Resolve DWARF members matching exact address and size pairs."""

        self._check_open()
        return self._dwarf().resolve_members_by_address(members)

    def source_files(self) -> set[str]:
        """Return normalized declaration files discovered in DWARF metadata."""

        self._check_open()
        return self._dwarf().source_files()

    def _symbols(self) -> SymbolIndex:
        """Return the lazily constructed symbol-table index."""

        if self._symbol_index is None:
            self._symbol_index = SymbolIndex(self._ensure_open())
        return self._symbol_index

    def _dwarf(self) -> DwarfIndex:
        """Return the lazily constructed DWARF index."""

        if self._dwarf_index is None:
            self._dwarf_index = DwarfIndex(
                cast(DwarfELFLike, self._ensure_open())
            )
        return self._dwarf_index

    def _ensure_open(self) -> ELFLike:
        """Open and return the underlying ELF object unless already closed."""

        self._check_open()
        if self._elf_file is None:
            self._stream = self.elf_path.open("rb")
            self._elf_file = ELFFile(self._stream)
        return self._elf_file

    def _check_open(self) -> None:
        """Raise when an operation is attempted after closure."""

        if self._closed:
            raise RuntimeError("ElfResolver is closed")

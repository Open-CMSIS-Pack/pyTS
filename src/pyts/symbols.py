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

"""Ordered multi-ELF symbol catalogue and resource ownership."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from pyts.elf import ElfResolver, MemberInfo, SymbolInfo


@dataclass(frozen=True)
class SymbolFile:
    """An ELF output plus aliases used by CMSIS trace qualifiers."""

    path: Path
    aliases: frozenset[str]
    project: str | None

    def matches(self, qualifier: str | None) -> bool:
        """Return whether this file matches a normalized qualifier."""

        if qualifier is None:
            return True
        return self.project == qualifier or qualifier in self.aliases


@dataclass(frozen=True)
class OpenSymbolFile:
    """A symbol file paired with its active resolver."""

    symbol_file: SymbolFile
    resolver: ElfResolver


class SymbolCatalog:
    """Own ordered ELF resolvers and provide cross-file lookup operations."""

    def __init__(
        self,
        symbol_files: Iterable[SymbolFile],
        *,
        resolver_factory: Callable[[Path], ElfResolver] = ElfResolver.from_path,
    ) -> None:
        """Create a lazy ordered catalogue for the supplied symbol files."""

        self.symbol_files = tuple(symbol_files)
        self._resolver_factory = resolver_factory
        self._stack = ExitStack()
        self._opened: dict[Path, OpenSymbolFile] = {}
        self._closed = False

    def __enter__(self) -> SymbolCatalog:
        """Return this open catalogue as a context-managed resource."""

        self._check_open()
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close all resolvers opened by this catalogue."""

        self.close()

    def close(self) -> None:
        """Close every resolver opened by this catalogue."""

        if self._closed:
            return
        self._stack.close()
        self._closed = True

    def candidates(self, qualifier: str | None = None) -> list[SymbolFile]:
        """Return files matching a normalized qualifier in declared order."""

        self._check_open()
        return [item for item in self.symbol_files if item.matches(qualifier)]

    def open(self, symbol_file: SymbolFile) -> OpenSymbolFile:
        """Open one file at most once and return its resolver pair."""

        self._check_open()
        key = symbol_file.path.resolve(strict=False)
        existing = self._opened.get(key)
        if existing is not None:
            return existing
        resolver = self._stack.enter_context(
            self._resolver_factory(symbol_file.path)
        )
        opened = OpenSymbolFile(symbol_file=symbol_file, resolver=resolver)
        self._opened[key] = opened
        return opened

    def open_candidates(
        self,
        qualifier: str | None = None,
    ) -> list[OpenSymbolFile]:
        """Open and return all matching files in declared order."""

        return [self.open(item) for item in self.candidates(qualifier)]

    def resolve_names(
        self,
        names: list[str],
    ) -> dict[str, SymbolInfo | MemberInfo]:
        """Resolve each name from the first ELF that provides it."""

        if not names:
            return {}
        resolved: dict[str, SymbolInfo | MemberInfo] = {}
        remaining = list(dict.fromkeys(names))
        for symbol_file in self.candidates():
            if not remaining:
                break
            opened = self.open(symbol_file)
            for symbol in opened.resolver.resolve_symbols(remaining):
                resolved.setdefault(symbol.name, symbol)
            remaining = [name for name in remaining if name not in resolved]
        return resolved

    def resolve_members_by_address(
        self,
        members: list[tuple[int, int]],
    ) -> tuple[dict[tuple[int, int], MemberInfo], set[tuple[int, int]]]:
        """Resolve unique DWARF members and report ambiguous address pairs."""

        if not members:
            return {}, set()
        resolved: dict[tuple[int, int], MemberInfo] = {}
        ambiguous: set[tuple[int, int]] = set()
        remaining = list(dict.fromkeys(members))
        for symbol_file in self.candidates():
            if not remaining:
                break
            opened = self.open(symbol_file)
            matches = opened.resolver.resolve_object_members_by_address(remaining)
            grouped: dict[tuple[int, int], list[MemberInfo]] = {
                member: [] for member in remaining
            }
            for match in matches:
                key = (match.address, match.size)
                if key in grouped:
                    grouped[key].append(match)
            for key, matches_for_key in grouped.items():
                if len(matches_for_key) == 1:
                    resolved[key] = matches_for_key[0]
                elif len(matches_for_key) > 1:
                    ambiguous.add(key)
            remaining = [
                key
                for key in remaining
                if key not in resolved and key not in ambiguous
            ]
        return resolved, ambiguous

    def resolve_addresses(
        self,
        addresses: list[int],
    ) -> dict[int, SymbolInfo | MemberInfo]:
        """Resolve exact addresses from the first ELF that provides each one."""

        if not addresses:
            return {}
        resolved: dict[int, SymbolInfo | MemberInfo] = {}
        remaining = list(dict.fromkeys(addresses))
        for symbol_file in self.candidates():
            if not remaining:
                break
            opened = self.open(symbol_file)
            for address in remaining:
                symbol = opened.resolver.resolve_address(address)
                if symbol is not None:
                    resolved.setdefault(address, symbol)
            remaining = [address for address in remaining if address not in resolved]
        return resolved

    def _check_open(self) -> None:
        """Raise when catalogue operations are attempted after closure."""

        if self._closed:
            raise RuntimeError("SymbolCatalog is closed")

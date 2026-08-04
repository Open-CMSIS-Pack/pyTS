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

"""Location candidate selection and ELF resolution."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from pyts.domain import EntryPath, EntryRef, YamlMapping
from pyts.elf import ElfResolver, MemberInfo, SymbolInfo
from pyts.symbols import OpenSymbolFile, SymbolCatalog, SymbolFile
from pyts.trace.enrichment import manual_size, warn_ambiguous_location
from pyts.trace.model import LocationSpec, ResolvedLocation, normalize_alias


def resolve_locations(
    catalog: SymbolCatalog,
    entries: list[EntryRef],
    pnames_by_path: dict[EntryPath, str] | None = None,
) -> tuple[dict[EntryPath, ResolvedLocation], dict[EntryPath, str]]:
    """Resolve location entries and return path-keyed matches and errors."""

    resolved: dict[EntryPath, ResolvedLocation] = {}
    errors: dict[EntryPath, str] = {}
    pnames = pnames_by_path or {}
    for ref in entries:
        result, error = _resolve_location_ref(
            catalog, ref, pnames.get(ref.path)
        )
        if result is not None:
            resolved[ref.path] = result
        if error is not None:
            errors[ref.path] = error
    return resolved, errors


def _resolve_location_ref(
    catalog: SymbolCatalog,
    ref: EntryRef,
    pname: str | None,
) -> tuple[ResolvedLocation | None, str | None]:
    """Resolve one location reference and return its result or error."""

    entry = ref.value
    location = LocationSpec.from_yaml(entry["location"])
    if location is None:
        return None, None
    if location.address is not None:
        return resolve_fixed_address(catalog, location.address, entry, pname), None
    candidates = catalog.candidates(
        normalize_alias(location.qualifier)
        if location.qualifier is not None
        else None,
        pname=pname,
    )
    if not candidates:
        return None, unresolved_qualifier_error(location, pname)
    opened, open_error = _open_location_candidates(catalog, candidates)
    if open_error is not None:
        return None, open_error
    source_error = source_file_error(location, opened)
    if source_error is not None:
        return None, source_error
    return _resolve_location_matches(location, opened, entry)


def _open_location_candidates(
    catalog: SymbolCatalog, candidates: Iterable[SymbolFile]
) -> tuple[list[OpenSymbolFile], str | None]:
    """Open location candidates, reporting a missing ELF path."""

    opened: list[OpenSymbolFile] = []
    for candidate in candidates:
        try:
            opened.append(catalog.open(candidate))
        except FileNotFoundError:
            path = candidate.path.resolve(strict=False)
            return [], f"ELF file does not exist: {path}"
    return opened, None


def _resolve_location_matches(
    location: LocationSpec,
    candidates: list[OpenSymbolFile],
    entry: YamlMapping,
) -> tuple[ResolvedLocation | None, str | None]:
    """Classify zero, one, or multiple location matches."""

    matches = resolve_location_from_candidates(location, candidates, entry)
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        warn_ambiguous_location(location.original)
        return None, f"location matches multiple symbols: {location.original}"
    return None, not_found_error(location)


def resolve_fixed_address(
    catalog: SymbolCatalog,
    address: int,
    entry: YamlMapping,
    pname: str | None,
) -> ResolvedLocation | None:
    """Optionally enrich an authoritative address from one unique ELF match."""

    matches: list[ResolvedLocation] = []
    for candidate in catalog.candidates(pname=pname):
        try:
            opened = catalog.open(candidate)
        except FileNotFoundError:
            continue
        matches.extend(resolve_location_address(opened, address, entry))
    return matches[0] if len(matches) == 1 else None


def resolve_location_from_candidates(
    location: LocationSpec,
    candidates: Iterable[OpenSymbolFile],
    entry: YamlMapping,
) -> list[ResolvedLocation]:
    """Resolve one location against each selected ELF candidate."""

    matches: list[ResolvedLocation] = []
    for candidate in candidates:
        if location.address is not None:
            matches.extend(resolve_location_address(candidate, location.address, entry))
            continue
        if location.symbol is None:
            continue
        for symbol in resolver_symbols(
            candidate.resolver,
            [location.symbol],
            source_file=location.source_file,
        ):
            matches.append(resolved_location(candidate.symbol_file.path, symbol))
    return matches


def unresolved_qualifier_error(
    location: LocationSpec,
    pname: str | None = None,
) -> str:
    """Describe why a location qualifier selected no ELF files."""

    qualifier = location.qualifier
    if pname is not None:
        if qualifier is None:
            return f"no ELF files are available for processor '{pname}'"
        return f"location qualifier '{qualifier}' does not resolve to an ELF file for processor '{pname}'."
    if qualifier is None:
        return "no ELF files are available for location lookup"
    normalized = normalize_alias(qualifier)
    if looks_like_file_qualifier(normalized):
        return f"ELF file qualifier '{qualifier}' does not resolve to an existing ELF file"
    return f"project '{qualifier}' does not resolve to an existing ELF file"


def looks_like_file_qualifier(qualifier: str) -> bool:
    """Return whether a qualifier syntactically resembles an ELF path."""

    return "/" in qualifier or Path(qualifier).suffix.lower() in {
        ".axf",
        ".elf",
        ".out",
    }


def source_file_error(
    location: LocationSpec,
    candidates: Iterable[OpenSymbolFile],
) -> str | None:
    """Return an error when no candidate contains the requested source file."""

    if location.source_file is None:
        return None
    for candidate in candidates:
        if source_file_exists(candidate.resolver, location.source_file):
            return None
    return f"source file not found: {location.source_file}"


def source_file_exists(resolver: ElfResolver, source_file: str) -> bool:
    """Return whether an ELF resolver reports a matching declaration file."""

    wanted = normalize_source_file(source_file)
    try:
        source_files = resolver.source_files()
    except AttributeError:
        return True
    for source in source_files:
        normalized = normalize_source_file(source)
        if (
            normalized == wanted
            or normalized.endswith(f"/{wanted}")
            or Path(normalized).name == wanted
        ):
            return True
    return False


def normalize_source_file(source_file: str) -> str:
    """Normalize source-file separators and surrounding quotes."""

    return source_file.replace("\\", "/").strip().strip('"')


def not_found_error(location: LocationSpec) -> str:
    """Describe a symbol or address that no selected ELF resolved."""

    if location.address is not None:
        return f"address not found in ELF symbols: 0x{location.address:x}"
    if location.source_file is not None:
        return (
            f"symbol not found in source file {location.source_file!r}: "
            f"{location.symbol}"
        )
    return f"symbol not found: {location.symbol}"


def resolve_location_address(
    candidate: OpenSymbolFile,
    address: int,
    entry: YamlMapping,
) -> list[ResolvedLocation]:
    """Resolve an exact address, preferring a size-matched DWARF member."""

    size = manual_size(entry)
    if size is not None:
        members = candidate.resolver.resolve_object_members_by_address(
            [(address, size)]
        )
        if members:
            return [
                resolved_location(candidate.symbol_file.path, member)
                for member in members
            ]
    symbol = candidate.resolver.resolve_address(address)
    if symbol is None:
        return []
    return [resolved_location(candidate.symbol_file.path, symbol)]


def resolver_symbols(
    resolver: ElfResolver,
    names: list[str],
    *,
    source_file: str | None,
) -> list[SymbolInfo | MemberInfo]:
    """Resolve names through the typed resolver interface."""

    return resolver.resolve_symbols(names, source_file=source_file)


def resolved_location(
    symbol_file: Path,
    symbol: SymbolInfo | MemberInfo,
) -> ResolvedLocation:
    """Convert ELF or DWARF metadata into trace location metadata."""

    return ResolvedLocation(
        symbol_file=str(symbol_file.resolve(strict=False)),
        symbol=symbol.name,
        address=symbol.address,
        address_hex=symbol.address_hex,
        size=symbol.size,
        type=symbol.type,
    )

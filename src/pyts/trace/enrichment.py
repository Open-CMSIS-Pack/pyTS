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

"""Trace entry enrichment, consistency checks, and warnings."""

from __future__ import annotations

import warnings
from collections.abc import Iterable

from pyts.domain import EntryPath, EntryRef, JsonValue, YamlMapping
from pyts.elf import MemberInfo, SymbolInfo
from pyts.trace.model import LocationSpec, ResolvedLocation
from pyts.yaml_io import HexInt


def entry_addresses(entries: Iterable[YamlMapping]) -> list[int]:
    """Collect valid manual addresses from trace entries."""

    return [
        address
        for entry in entries
        if (address := manual_address(entry)) is not None
    ]


def entry_sized_addresses(
    entries: Iterable[YamlMapping],
) -> list[tuple[int, int]]:
    """Collect entries having both a manual address and integer size."""

    results: list[tuple[int, int]] = []
    for entry in entries:
        address = manual_address(entry)
        size = manual_size(entry)
        if address is not None and size is not None:
            results.append((address, size))
    return results


def enrich_legacy_refs(
    entries: list[EntryRef],
    resolved: dict[str, SymbolInfo | MemberInfo],
    resolved_members_by_address: dict[tuple[int, int], MemberInfo],
    ambiguous_members: set[tuple[int, int]],
    resolved_by_address: dict[int, SymbolInfo | MemberInfo],
) -> None:
    """Add resolved metadata to legacy symbol and address entries in place."""

    for ref in entries:
        symbol, description = _resolve_legacy_ref(
            ref.value,
            resolved,
            resolved_members_by_address,
            ambiguous_members,
            resolved_by_address,
        )
        if symbol is None:
            continue
        _enrich_legacy_ref(ref.value, description, symbol)


def _resolve_legacy_ref(
    item: YamlMapping,
    resolved: dict[str, SymbolInfo | MemberInfo],
    resolved_members_by_address: dict[tuple[int, int], MemberInfo],
    ambiguous_members: set[tuple[int, int]],
    resolved_by_address: dict[int, SymbolInfo | MemberInfo],
) -> tuple[SymbolInfo | MemberInfo | None, str]:
    """Select resolved metadata for one legacy symbol or address entry."""

    symbol_name = item.get("symbol")
    if isinstance(symbol_name, str) and symbol_name:
        return resolved.get(symbol_name), f"symbol {symbol_name!r}"
    address = manual_address(item)
    if address is None:
        return None, ""
    size = manual_size(item)
    description = f"address 0x{address:x}"
    if size is not None and (address, size) in ambiguous_members:
        warn_ambiguous_member(description, size)
        return None, description
    return (
        resolved_address_symbol(
            address, size, resolved_members_by_address, resolved_by_address
        ),
        description,
    )


def _enrich_legacy_ref(
    item: YamlMapping, description: str, symbol: SymbolInfo | MemberInfo
) -> None:
    """Enrich all available metadata fields for one legacy reference."""

    enrich_property(item, description, "symbol", symbol.name,
                    symbol_is_consistent(item.get("symbol"), symbol))
    enrich_property(item, description, "address", symbol.address_hex,
                    address_is_consistent(item.get("address"), symbol))
    enrich_property(item, description, "symbol-size", symbol.size,
                    size_is_consistent(item.get("symbol-size"), symbol))
    if symbol.type:
        enrich_property(item, description, "symbol-type", symbol.type,
                        type_is_consistent(item.get("symbol-type"), symbol))


def enrich_location_refs(
    entries: list[EntryRef],
    resolved: dict[EntryPath, ResolvedLocation],
    errors: dict[EntryPath, str],
) -> None:
    """Add resolved metadata or errors to location entries in place."""

    for ref in entries:
        item = ref.value
        location = LocationSpec.from_yaml(item.get("location"))
        if location is not None and location.address is not None:
            normalize_fixed_address(item, location.address)
        error = errors.get(ref.path)
        if error is not None:
            enrich_property(
                item,
                f"location {item.get('location')!r}",
                "error",
                error,
                item.get("error") == error,
            )
            continue
        symbol = resolved.get(ref.path)
        if symbol is None:
            continue
        description = f"location {item.get('location')!r}"
        for name, value, consistent in (
            ("symbol-file", symbol.symbol_file, item.get("symbol-file") == symbol.symbol_file),
            ("symbol", symbol.symbol, item.get("symbol") == symbol.symbol),
            (
                "address",
                symbol.address_hex,
                location_address_is_consistent(item.get("address"), symbol),
            ),
            (
                "symbol-size",
                symbol.size,
                location_size_is_consistent(item.get("symbol-size"), symbol),
            ),
        ):
            enrich_property(item, description, name, value, consistent)
        if symbol.type:
            enrich_property(
                item,
                description,
                "symbol-type",
                symbol.type,
                item.get("symbol-type") == symbol.type,
            )


def normalize_fixed_address(item: YamlMapping, address: int) -> None:
    """Normalize a fixed location and materialize its authoritative address."""

    normalized = HexInt(address)
    item["location"] = normalized
    if "address" not in item or manual_address(item) == address:
        item["address"] = normalized
        return
    enrich_property(
        item,
        f"location 0x{address:x}",
        "address",
        normalized,
        False,
    )


def resolved_address_symbol(
    address: int,
    size: int | None,
    members: dict[tuple[int, int], MemberInfo],
    symbols: dict[int, SymbolInfo | MemberInfo],
) -> SymbolInfo | MemberInfo | None:
    """Prefer a size-matched member before falling back to an ELF symbol."""

    if size is not None and (address, size) in members:
        return members[(address, size)]
    return symbols.get(address)


def warn_ambiguous_member(description: str, size: int) -> None:
    """Warn that an address and size identify multiple DWARF members."""

    warnings.warn(
        (
            f"ctrace {description} with size {size!r} matches multiple "
            "DWARF object members; keeping existing value"
        ),
        UserWarning,
        stacklevel=2,
    )


def warn_ambiguous_location(location: str) -> None:
    """Warn that a location resolves to multiple symbols."""

    warnings.warn(
        (
            f"ctrace location {location!r} matches multiple symbols; "
            "keeping existing value"
        ),
        UserWarning,
        stacklevel=2,
    )


def enrich_property(
    item: YamlMapping,
    description: str,
    property_name: str,
    resolved_value: int | str,
    is_consistent: bool,
) -> None:
    """Add a missing property or warn while preserving an inconsistent value."""

    if property_name not in item:
        item[property_name] = resolved_value
        return
    if is_consistent:
        return
    warnings.warn(
        (
            f"ctrace {description} has inconsistent {property_name!r}: "
            f"existing value {item[property_name]!r} does not match resolved value "
            f"{resolved_value!r}; keeping existing value"
        ),
        UserWarning,
        stacklevel=2,
    )


def symbol_is_consistent(
    existing: JsonValue,
    symbol: SymbolInfo | MemberInfo,
) -> bool:
    """Return whether an existing symbol name matches resolved metadata."""

    return isinstance(existing, str) and existing == symbol.name


def address_is_consistent(
    existing: JsonValue,
    symbol: SymbolInfo | MemberInfo,
) -> bool:
    """Return whether a string or integer address matches resolved metadata."""

    if existing == symbol.address_hex:
        return True
    return (
        isinstance(existing, int)
        and not isinstance(existing, bool)
        and existing == symbol.address
    )


def size_is_consistent(
    existing: JsonValue,
    symbol: SymbolInfo | MemberInfo,
) -> bool:
    """Return whether an existing integer size matches resolved metadata."""

    return (
        isinstance(existing, int)
        and not isinstance(existing, bool)
        and existing == symbol.size
    )


def type_is_consistent(
    existing: JsonValue,
    symbol: SymbolInfo | MemberInfo,
) -> bool:
    """Return whether an existing type name matches resolved metadata."""

    return isinstance(existing, str) and existing == symbol.type


def location_address_is_consistent(
    existing: JsonValue,
    symbol: ResolvedLocation,
) -> bool:
    """Return whether an existing address matches a resolved location."""

    if existing == symbol.address_hex:
        return True
    return (
        isinstance(existing, int)
        and not isinstance(existing, bool)
        and existing == symbol.address
    )


def location_size_is_consistent(
    existing: JsonValue,
    symbol: ResolvedLocation,
) -> bool:
    """Return whether an existing size matches a resolved location."""

    return (
        isinstance(existing, int)
        and not isinstance(existing, bool)
        and existing == symbol.size
    )


def manual_address(entry: YamlMapping) -> int | None:
    """Parse a trace entry's manual integer or base-prefixed address."""

    value = entry.get("address")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def manual_size(entry: YamlMapping) -> int | None:
    """Return a trace entry's integer size while rejecting booleans."""

    value = entry.get("size")
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None

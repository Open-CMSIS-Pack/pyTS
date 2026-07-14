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

"""Copy-on-transform orchestration for mixed trace entry styles."""

from __future__ import annotations

from collections.abc import Iterable
from copy import deepcopy
from typing import cast

from pyts.domain import (
    Diagnostic,
    DiagnosticSeverity,
    EntryPath,
    EntryRef,
    YamlMapping,
)
from pyts.elf import missing_symbols
from pyts.symbols import SymbolCatalog
from pyts.trace.enrichment import (
    enrich_legacy_refs,
    enrich_location_refs,
    enrich_property,
    entry_addresses,
    entry_sized_addresses,
    manual_address,
    manual_size,
    resolved_address_symbol,
)
from pyts.trace.locations import resolve_locations
from pyts.trace.model import LocationSpec, TraceTransformResult


def mapping_refs(node: object, path: EntryPath = ()) -> Iterable[EntryRef]:
    """Yield every mapping with its stable path in document order."""

    if isinstance(node, dict):
        mapping = cast(YamlMapping, node)
        yield EntryRef(path, mapping)
        for key, value in mapping.items():
            yield from mapping_refs(value, (*path, key))
    elif isinstance(node, list):
        for index, item in enumerate(cast(list[object], node)):
            yield from mapping_refs(item, (*path, index))


def has_location(entry: YamlMapping) -> bool:
    """Return whether a mapping contains a valid location scalar."""

    return LocationSpec.from_yaml(entry.get("location")) is not None


def transform_trace_document(
    source: YamlMapping,
    catalog: SymbolCatalog,
) -> TraceTransformResult:
    """Resolve and enrich a copied trace document without filesystem writes."""

    document = deepcopy(source)
    refs = list(mapping_refs(document))
    location_refs = [ref for ref in refs if has_location(ref.value)]
    legacy_symbol_refs = [
        ref
        for ref in refs
        if not has_location(ref.value)
        and isinstance(ref.value.get("symbol"), str)
        and bool(cast(str, ref.value.get("symbol")))
    ]
    legacy_address_refs = [
        ref
        for ref in refs
        if not has_location(ref.value)
        and not (
            isinstance(ref.value.get("symbol"), str)
            and bool(cast(str, ref.value.get("symbol")))
        )
        and manual_address(ref.value) is not None
    ]

    resolved_locations, location_errors = resolve_locations(catalog, location_refs)
    enrich_location_refs(location_refs, resolved_locations, location_errors)

    symbol_names = [cast(str, ref.value["symbol"]) for ref in legacy_symbol_refs]
    address_entries = [ref.value for ref in legacy_address_refs]
    resolved = catalog.resolve_names(symbol_names)
    resolved_members, ambiguous_members = catalog.resolve_members_by_address(
        entry_sized_addresses(address_entries)
    )
    resolved_by_address = catalog.resolve_addresses(entry_addresses(address_entries))
    legacy_missing = missing_symbols(resolved.values(), symbol_names)
    enrich_legacy_refs(
        [*legacy_symbol_refs, *legacy_address_refs],
        resolved,
        resolved_members,
        ambiguous_members,
        resolved_by_address,
    )

    missing_by_path: dict[EntryPath, str] = {
        ref.path: str(ref.value["location"])
        for ref in location_refs
        if ref.path in location_errors
    }
    unresolved_names = set(legacy_missing)
    for ref in legacy_symbol_refs:
        symbol = cast(str, ref.value["symbol"])
        if symbol not in unresolved_names:
            continue
        missing_by_path[ref.path] = symbol
        if location_refs:
            error = f"symbol not found: {symbol}"
            enrich_property(
                ref.value,
                f"symbol {symbol!r}",
                "error",
                error,
                ref.value.get("error") == error,
            )

    resolved_names: dict[EntryPath, str] = {
        path: value.symbol for path, value in resolved_locations.items()
    }
    for ref in legacy_symbol_refs:
        symbol = cast(str, ref.value["symbol"])
        if symbol in resolved:
            resolved_names[ref.path] = symbol
    for ref in legacy_address_refs:
        address = manual_address(ref.value)
        if address is None:
            continue
        size = manual_size(ref.value)
        if size is not None and (address, size) in ambiguous_members:
            continue
        match = resolved_address_symbol(
            address,
            size,
            resolved_members,
            resolved_by_address,
        )
        if match is not None:
            resolved_names[ref.path] = match.name

    missing = [missing_by_path[ref.path] for ref in refs if ref.path in missing_by_path]
    symbols = [resolved_names[ref.path] for ref in refs if ref.path in resolved_names]
    diagnostics = [
        Diagnostic(
            code=(
                "location_unresolved"
                if ref.path in location_errors
                else "symbol_unresolved"
            ),
            message=(
                location_errors[ref.path]
                if ref.path in location_errors
                else f"symbol not found: {missing_by_path[ref.path]}"
            ),
            severity=DiagnosticSeverity.ERROR,
            path=ref.path,
        )
        for ref in refs
        if ref.path in missing_by_path
    ]
    return TraceTransformResult(
        document=document,
        symbols=symbols,
        missing=missing,
        diagnostics=diagnostics,
        has_locations=bool(location_refs),
        has_legacy_entries=bool(legacy_symbol_refs or legacy_address_refs),
    )

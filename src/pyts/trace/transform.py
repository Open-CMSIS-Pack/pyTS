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
    EntryPath,
    EntryRef,
    YamlMapping,
)
from pyts.elf import MemberInfo, SymbolInfo, missing_symbols
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


def setup_processor_names(document: YamlMapping) -> dict[int, str]:
    """Return normalized processor names keyed by trace setup index."""

    root = document.get("ctrace")
    if not isinstance(root, dict):
        return {}
    setups = root.get("setup")
    if not isinstance(setups, list):
        return {}
    result: dict[int, str] = {}
    for index, setup in enumerate(setups):
        if not isinstance(setup, dict):
            continue
        pname = setup.get("pname")
        if isinstance(pname, str) and pname.strip():
            result[index] = pname.strip()
    return result


def enclosing_setup_pname(
    path: EntryPath,
    setup_pnames: dict[int, str],
) -> str | None:
    """Return the processor selected by the setup containing a path."""

    if (
        len(path) >= 3
        and path[0] == "ctrace"
        and path[1] == "setup"
        and isinstance(path[2], int)
    ):
        return setup_pnames.get(path[2])
    return None


def transform_trace_document(
    source: YamlMapping,
    catalog: SymbolCatalog,
) -> TraceTransformResult:
    """Resolve and enrich a copied trace document without filesystem writes."""

    document = deepcopy(source)
    refs = list(mapping_refs(document))
    setup_pnames = setup_processor_names(document)
    pnames_by_path = {
        ref.path: pname
        for ref in refs
        if (pname := enclosing_setup_pname(ref.path, setup_pnames)) is not None
    }
    location_refs, legacy_symbol_refs, legacy_address_refs = _classify_refs(refs)

    resolved_locations, location_errors = resolve_locations(
        catalog,
        location_refs,
        pnames_by_path,
    )
    enrich_location_refs(location_refs, resolved_locations, location_errors)

    missing_by_path = _location_missing_names(location_refs, location_errors)
    resolved_names: dict[EntryPath, str] = {
        path: value.symbol for path, value in resolved_locations.items()
    }
    legacy_missing, legacy_resolved = _process_legacy_refs(
        catalog,
        legacy_symbol_refs,
        legacy_address_refs,
        pnames_by_path,
        bool(location_refs),
    )
    missing_by_path.update(legacy_missing)
    resolved_names.update(legacy_resolved)

    missing = [missing_by_path[ref.path] for ref in refs if ref.path in missing_by_path]
    symbols = [resolved_names[ref.path] for ref in refs if ref.path in resolved_names]
    return TraceTransformResult(
        document=document,
        symbols=symbols,
        missing=missing,
        has_locations=bool(location_refs),
        has_legacy_entries=bool(legacy_symbol_refs or legacy_address_refs),
    )


def _classify_refs(
    refs: list[EntryRef],
) -> tuple[list[EntryRef], list[EntryRef], list[EntryRef]]:
    """Partition mappings into location, legacy-symbol, and legacy-address refs."""

    locations = [ref for ref in refs if has_location(ref.value)]
    symbols = [
        ref for ref in refs
        if not has_location(ref.value)
        and isinstance(ref.value.get("symbol"), str)
        and bool(cast(str, ref.value.get("symbol")))
    ]
    addresses = [
        ref
        for ref in refs
        if not has_location(ref.value)
        and not (
            isinstance(ref.value.get("symbol"), str)
            and bool(cast(str, ref.value.get("symbol")))
        )
        and manual_address(ref.value) is not None
    ]
    return locations, symbols, addresses


def _location_missing_names(
    refs: list[EntryRef], errors: dict[EntryPath, str]
) -> dict[EntryPath, str]:
    """Collect location values that failed resolution."""

    return {
        ref.path: str(ref.value["location"])
        for ref in refs if ref.path in errors
    }


def _process_legacy_refs(
    catalog: SymbolCatalog,
    symbol_refs: list[EntryRef],
    address_refs: list[EntryRef],
    pnames_by_path: dict[EntryPath, str],
    has_locations: bool,
) -> tuple[dict[EntryPath, str], dict[EntryPath, str]]:
    """Resolve and enrich all legacy references grouped by processor."""

    missing: dict[EntryPath, str] = {}
    resolved_names: dict[EntryPath, str] = {}
    groups: dict[str | None, list[EntryRef]] = {}
    for ref in [*symbol_refs, *address_refs]:
        groups.setdefault(pnames_by_path.get(ref.path), []).append(ref)
    symbol_paths = {ref.path for ref in symbol_refs}
    for pname, refs in groups.items():
        scoped_symbols = [ref for ref in refs if ref.path in symbol_paths]
        scoped_addresses = [ref for ref in refs if ref.path not in symbol_paths]
        _process_legacy_scope(
            catalog,
            pname,
            refs,
            scoped_symbols,
            scoped_addresses,
            has_locations,
            missing,
            resolved_names,
        )
    return missing, resolved_names


def _process_legacy_scope(
    catalog: SymbolCatalog,
    pname: str | None,
    refs: list[EntryRef],
    symbol_refs: list[EntryRef],
    address_refs: list[EntryRef],
    has_locations: bool,
    missing: dict[EntryPath, str],
    resolved_names: dict[EntryPath, str],
) -> None:
    """Resolve, enrich, and classify one processor-scoped legacy group."""

    symbol_names = [cast(str, ref.value["symbol"]) for ref in symbol_refs]
    address_entries = [ref.value for ref in address_refs]
    if pname is None:
        resolved = catalog.resolve_names(symbol_names)
        resolved_members, ambiguous_members = catalog.resolve_members_by_address(
            entry_sized_addresses(address_entries)
        )
        resolved_by_address = catalog.resolve_addresses(entry_addresses(address_entries))
    else:
        resolved = catalog.resolve_names(symbol_names, pname=pname)
        resolved_members, ambiguous_members = catalog.resolve_members_by_address(
            entry_sized_addresses(address_entries), pname=pname
        )
        resolved_by_address = catalog.resolve_addresses(
            entry_addresses(address_entries), pname=pname
        )
    enrich_legacy_refs(
        refs, resolved, resolved_members, ambiguous_members, resolved_by_address
    )
    unresolved = set(missing_symbols(resolved.values(), symbol_names))
    _record_legacy_symbol_results(
        symbol_refs, unresolved, has_locations, missing, resolved_names
    )
    _record_legacy_address_results(
        address_refs, ambiguous_members, resolved_members, resolved_by_address,
        resolved_names
    )


def _record_legacy_symbol_results(
    refs: list[EntryRef], unresolved: set[str], has_locations: bool,
    missing: dict[EntryPath, str], resolved_names: dict[EntryPath, str]
) -> None:
    """Record resolved or missing legacy symbol names."""

    for ref in refs:
        symbol = cast(str, ref.value["symbol"])
        if symbol in unresolved:
            missing[ref.path] = symbol
            if has_locations:
                error = f"symbol not found: {symbol}"
                enrich_property(ref.value, f"symbol {symbol!r}", "error",
                                error, ref.value.get("error") == error)
        else:
            resolved_names[ref.path] = symbol


def _record_legacy_address_results(
    refs: list[EntryRef], ambiguous: set[tuple[int, int]],
    members: dict[tuple[int, int], MemberInfo],
    symbols: dict[int, SymbolInfo | MemberInfo],
    resolved_names: dict[EntryPath, str],
) -> None:
    """Record names resolved from legacy address entries."""

    for ref in refs:
        address = manual_address(ref.value)
        if address is None:
            continue
        size = manual_size(ref.value)
        if size is not None and (address, size) in ambiguous:
            continue
        match = resolved_address_symbol(address, size, members, symbols)
        if match is not None:
            resolved_names[ref.path] = match.name

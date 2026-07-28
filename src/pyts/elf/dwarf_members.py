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

"""DWARF expression parsing, type traversal, and member discovery."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, cast

from elftools.dwarf.dwarf_expr import DWARFExprParser

from pyts.elf.dwarf_sources import die_source_file, die_source_matches
from pyts.elf.model import MemberInfo


TYPE_WRAPPER_TAGS = {
    "DW_TAG_const_type",
    "DW_TAG_restrict_type",
    "DW_TAG_typedef",
    "DW_TAG_volatile_type",
}


def split_member_expression(expression: str) -> tuple[str, list[str]] | None:
    """Split a valid dotted member expression into base and member names."""

    parts = expression.split(".")
    if len(parts) < 2 or any(part == "" for part in parts):
        return None
    return parts[0], parts[1:]


def find_dwarf_variable(
    dwarf_info: Any,
    name: str,
    *,
    source_file: str | None = None,
) -> tuple[Any, Any] | None:
    """Find the first variable DIE matching a name and source qualifier."""

    for cu in dwarf_info.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_variable" or dwarf_name(die) != name:
                continue
            if source_file is not None and not die_source_matches(
                dwarf_info, cu, die, source_file
            ):
                continue
            return cu, die
    return None


def resolve_die_address(dwarf_info: Any, cu: Any, die: Any) -> int | None:
    """Resolve a DIE address from low-PC or a supported location expression."""

    low_pc = die.attributes.get("DW_AT_low_pc")
    if low_pc is not None:
        return normalize_die_address(die, int(low_pc.value))
    location = die.attributes.get("DW_AT_location")
    if location is None:
        return None
    try:
        operations = DWARFExprParser(cu.structs).parse_expr(location.value)
    except Exception:
        return None
    if len(operations) != 1:
        return None
    operation = operations[0]
    if operation.op_name == "DW_OP_addr":
        return normalize_die_address(die, int(operation.args[0]))
    if operation.op_name == "DW_OP_addrx":
        try:
            address = int(dwarf_info.get_addr(cu, operation.args[0]))
        except Exception:
            return None
        return normalize_die_address(die, address)
    return None


def normalize_die_address(die: Any, address: int) -> int:
    """Return a half-word-aligned address for a Thumb code DIE.

    ARM Thumb DWARF addresses can include the instruction-set state in bit 0,
    while the code memory address consumed by pyTS must be half-word aligned.
    Data-object addresses are returned unchanged.
    """

    return address & ~1 if die.tag == "DW_TAG_subprogram" else address


def resolve_member_path(
    variable_die: Any,
    member_names: Sequence[str],
) -> tuple[int, Any] | None:
    """Walk nested structure members and return total offset and final type."""

    current_type = unwrap_dwarf_type(die_type(variable_die))
    offset = 0
    for member_name in member_names:
        if current_type is None or current_type.tag not in {
            "DW_TAG_structure_type",
            "DW_TAG_union_type",
        }:
            return None
        member_die = find_member(current_type, member_name)
        if member_die is None:
            return None
        next_offset = member_offset(member_die)
        if next_offset is None:
            return None
        offset += next_offset
        current_type = unwrap_dwarf_type(die_type(member_die))
    return None if current_type is None else (offset, current_type)


def iter_object_members(
    dwarf_info: Any,
    cu: Any,
    base_die: Any,
    base_name: str,
    base_address: int,
    base_type: Any,
) -> Iterable[MemberInfo]:
    """Yield every named member nested under one DWARF variable."""

    yield from iter_type_members(
        die_source_file(dwarf_info, cu, base_die),
        cu,
        base_name,
        base_address,
        base_type,
        [],
        0,
    )


def iter_type_members(
    source_file: str | None,
    cu: Any,
    base_symbol: str,
    base_address: int,
    type_die: Any,
    parent_path: list[str],
    parent_offset: int,
) -> Iterable[MemberInfo]:
    """Recursively yield named members for a structure or union type."""

    if type_die.tag not in {"DW_TAG_structure_type", "DW_TAG_union_type"}:
        return
    for member_die in type_die.iter_children():
        if member_die.tag != "DW_TAG_member":
            continue
        relative_offset = member_offset(member_die)
        resolved_type = unwrap_dwarf_type(die_type(member_die))
        if relative_offset is None or resolved_type is None:
            continue
        name = dwarf_name(member_die)
        member_path = parent_path + ([name] if name else [])
        offset = parent_offset + relative_offset
        address = base_address + offset
        if member_path:
            yield MemberInfo(
                name=f"{base_symbol}.{'.'.join(member_path)}",
                address=address,
                size=dwarf_type_size(cu, resolved_type),
                type=dwarf_type_name(resolved_type),
                base_symbol=base_symbol,
                member_path=".".join(member_path),
                offset=offset,
                source_file=source_file,
            )
        yield from iter_type_members(
            source_file,
            cu,
            base_symbol,
            base_address,
            resolved_type,
            member_path,
            offset,
        )


def find_member(type_die: Any, name: str) -> Any | None:
    """Return a named direct member DIE from a structure or union."""

    for child in type_die.iter_children():
        if child.tag == "DW_TAG_member" and dwarf_name(child) == name:
            return child
    return None


def die_type(die: Any) -> Any | None:
    """Resolve the type DIE referenced by a DIE, if available."""

    if "DW_AT_type" not in die.attributes:
        return None
    try:
        return die.get_DIE_from_attribute("DW_AT_type")
    except Exception:
        return None


def unwrap_dwarf_type(die: Any | None) -> Any | None:
    """Remove typedef and qualifier wrapper DIEs from a type."""

    while die is not None and die.tag in TYPE_WRAPPER_TAGS:
        die = die_type(die)
    return die


def member_offset(member_die: Any) -> int | None:
    """Return a constant member byte offset when representable."""

    location = member_die.attributes.get("DW_AT_data_member_location")
    if location is None:
        return 0
    return int(location.value) if isinstance(location.value, int) else None


def dwarf_type_size(cu: Any, die: Any) -> int:
    """Return a DWARF type's byte size, including pointer fallback size."""

    byte_size = die.attributes.get("DW_AT_byte_size")
    if byte_size is not None:
        return int(byte_size.value)
    if die.tag == "DW_TAG_pointer_type":
        header = getattr(cu, "header", {})
        address_size = header.get("address_size") if hasattr(header, "get") else None
        return int(address_size or 0)
    return 0


def dwarf_type_name(die: Any) -> str:
    """Return a human-readable name for a DWARF type DIE."""

    name = dwarf_name(die)
    if name:
        return name
    known = {
        "DW_TAG_pointer_type": "pointer",
        "DW_TAG_structure_type": "struct",
        "DW_TAG_union_type": "union",
    }
    return known.get(die.tag, cast(str, die.tag).removeprefix("DW_TAG_").lower())


def dwarf_name(die: Any) -> str:
    """Decode a DIE's optional DW_AT_name attribute."""

    attribute = die.attributes.get("DW_AT_name")
    if attribute is None:
        return ""
    value = attribute.value
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value)


def die_size(cu: Any, die: Any) -> int:
    """Return a subprogram extent or the size of a DIE's resolved type."""

    low_pc = die.attributes.get("DW_AT_low_pc")
    high_pc = die.attributes.get("DW_AT_high_pc")
    if low_pc is not None and high_pc is not None:
        try:
            high_value = int(high_pc.value)
            low_value = int(low_pc.value)
        except (TypeError, ValueError):
            return 0
        return high_value - low_value if high_value >= low_value else high_value
    resolved_type = unwrap_dwarf_type(die_type(die))
    return 0 if resolved_type is None else dwarf_type_size(cu, resolved_type)


def die_symbol_type(die: Any) -> str:
    """Return the normalized symbol type represented by a DWARF DIE."""

    if die.tag == "DW_TAG_subprogram":
        return "func"
    resolved_type = unwrap_dwarf_type(die_type(die))
    if resolved_type is None:
        return str(die.tag).removeprefix("DW_TAG_")
    return dwarf_type_name(resolved_type)

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
from dataclasses import dataclass
from typing import Any

from elftools.dwarf.dwarf_expr import DWARFExprParser

from pyts.elf.dwarf_sources import die_source_file, die_source_matches
from pyts.elf.model import MemberInfo


TYPE_WRAPPER_TAGS = {
    "DW_TAG_atomic_type",
    "DW_TAG_const_type",
    "DW_TAG_restrict_type",
    "DW_TAG_typedef",
    "DW_TAG_volatile_type",
}

AGGREGATE_TYPE_TAGS = {
    "DW_TAG_class_type",
    "DW_TAG_structure_type",
    "DW_TAG_union_type",
}

CANONICAL_TAG_TYPES = {
    "DW_TAG_array_type": "array",
    "DW_TAG_class_type": "class",
    "DW_TAG_enumeration_type": "enum",
    "DW_TAG_pointer_type": "pointer",
    "DW_TAG_ptr_to_member_type": "pointer",
    "DW_TAG_reference_type": "reference",
    "DW_TAG_rvalue_reference_type": "reference",
    "DW_TAG_set_type": "set",
    "DW_TAG_string_type": "string",
    "DW_TAG_structure_type": "struct",
    "DW_TAG_subroutine_type": "function",
    "DW_TAG_union_type": "union",
}

CANONICAL_ENCODING_TYPES = {
    "DW_ATE_address": "address",
    "DW_ATE_ASCII": "char",
    "DW_ATE_boolean": "bool",
    "DW_ATE_complex_float": "complex",
    "DW_ATE_decimal_float": "float",
    "DW_ATE_float": "float",
    "DW_ATE_imaginary_float": "complex",
    "DW_ATE_numeric_string": "string",
    "DW_ATE_signed": "signed",
    "DW_ATE_signed_char": "signed",
    "DW_ATE_signed_fixed": "signed",
    "DW_ATE_UCS": "char",
    "DW_ATE_unsigned": "unsigned",
    "DW_ATE_unsigned_char": "unsigned",
    "DW_ATE_unsigned_fixed": "unsigned",
    "DW_ATE_UTF": "char",
}

DWARF_ENCODING_NAMES = {
    0x01: "DW_ATE_address",
    0x02: "DW_ATE_boolean",
    0x03: "DW_ATE_complex_float",
    0x04: "DW_ATE_float",
    0x05: "DW_ATE_signed",
    0x06: "DW_ATE_signed_char",
    0x07: "DW_ATE_unsigned",
    0x08: "DW_ATE_unsigned_char",
    0x09: "DW_ATE_imaginary_float",
    0x0B: "DW_ATE_numeric_string",
    0x0D: "DW_ATE_signed_fixed",
    0x0E: "DW_ATE_unsigned_fixed",
    0x0F: "DW_ATE_decimal_float",
    0x10: "DW_ATE_UTF",
    0x11: "DW_ATE_UCS",
    0x12: "DW_ATE_ASCII",
}


@dataclass(frozen=True)
class DwarfTypeInfo:
    """Language-neutral type category and optional source-level spelling."""

    name: str
    source_name: str | None


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
    """Walk nested members and return total offset and declared final type."""

    current_type = die_type(variable_die)
    offset = 0
    for member_name in member_names:
        aggregate_type = unwrap_dwarf_type(current_type)
        if (
            aggregate_type is None
            or aggregate_type.tag not in AGGREGATE_TYPE_TAGS
        ):
            return None
        member_die = find_member(aggregate_type, member_name)
        if member_die is None:
            return None
        next_offset = member_offset(member_die)
        if next_offset is None:
            return None
        offset += next_offset
        current_type = die_type(member_die)
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

    if type_die.tag not in AGGREGATE_TYPE_TAGS:
        return
    for member_die in type_die.iter_children():
        if member_die.tag != "DW_TAG_member":
            continue
        relative_offset = member_offset(member_die)
        declared_type = die_type(member_die)
        resolved_type = unwrap_dwarf_type(declared_type)
        if relative_offset is None or resolved_type is None:
            continue
        type_info = canonical_dwarf_type(declared_type)
        name = dwarf_name(member_die)
        member_path = parent_path + ([name] if name else [])
        offset = parent_offset + relative_offset
        address = base_address + offset
        if member_path:
            yield MemberInfo(
                name=f"{base_symbol}.{'.'.join(member_path)}",
                address=address,
                size=dwarf_type_size(cu, resolved_type),
                type=type_info.name,
                base_symbol=base_symbol,
                member_path=".".join(member_path),
                offset=offset,
                source_file=source_file,
                source_type=type_info.source_name,
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

    resolved_type = unwrap_dwarf_type(die)
    if resolved_type is None:
        return 0
    byte_size = resolved_type.attributes.get("DW_AT_byte_size")
    if byte_size is not None:
        return int(byte_size.value)
    if resolved_type.tag in {
        "DW_TAG_pointer_type",
        "DW_TAG_ptr_to_member_type",
        "DW_TAG_reference_type",
        "DW_TAG_rvalue_reference_type",
    }:
        header = getattr(cu, "header", {})
        address_size = header.get("address_size") if hasattr(header, "get") else None
        return int(address_size or 0)
    return 0


def canonical_dwarf_type(die: Any | None) -> DwarfTypeInfo:
    """Derive a language-neutral category from DWARF type semantics."""

    if die is None:
        return DwarfTypeInfo("", None)
    source_name = dwarf_source_type_name(die)
    resolved_type = unwrap_dwarf_type(die)
    if resolved_type is None:
        return DwarfTypeInfo("", source_name)
    if source_name is None:
        source_name = dwarf_name(resolved_type) or None
    canonical_name = CANONICAL_TAG_TYPES.get(resolved_type.tag)
    if canonical_name is None and resolved_type.tag == "DW_TAG_base_type":
        canonical_name = canonical_encoding_type(resolved_type)
    return DwarfTypeInfo(canonical_name or "", source_name)


def dwarf_source_type_name(die: Any) -> str | None:
    """Return the first declared name across type and qualifier wrappers."""

    current = die
    while current is not None:
        name = dwarf_name(current)
        if name:
            return name
        if current.tag not in TYPE_WRAPPER_TAGS:
            return None
        current = die_type(current)
    return None


def canonical_encoding_type(die: Any) -> str:
    """Return the canonical category for a base type's DW_AT_encoding."""

    attribute = die.attributes.get("DW_AT_encoding")
    if attribute is None:
        return ""
    encoding = attribute.value
    if isinstance(encoding, int):
        encoding_name = DWARF_ENCODING_NAMES.get(encoding, "")
    else:
        encoding_name = str(encoding)
    return CANONICAL_ENCODING_TYPES.get(encoding_name, "")


def dwarf_type_name(die: Any) -> str:
    """Return the language-neutral category for a DWARF type DIE."""

    return canonical_dwarf_type(die).name


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
        return "function"
    return canonical_dwarf_type(die_type(die)).name

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

"""DWARF declaration-file and line-program resolution."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any, SupportsInt, cast


def die_source_matches(
    dwarf_info: Any,
    cu: Any,
    die: Any,
    source_file: str,
) -> bool:
    """Return whether a DIE's declaration file matches a source qualifier."""

    resolved = die_source_file(dwarf_info, cu, die)
    if resolved is None:
        return False
    wanted = normalize_source_file(source_file)
    actual = normalize_source_file(resolved)
    return actual == wanted or actual.endswith(f"/{wanted}") or Path(actual).name == wanted


def die_source_file(dwarf_info: Any, cu: Any, die: Any) -> str | None:
    """Resolve a DIE declaration file through its compilation unit line table."""

    decl_file = die.attributes.get("DW_AT_decl_file")
    if decl_file is None:
        return None
    try:
        file_index = int(decl_file.value)
    except (TypeError, ValueError):
        return None
    if file_index <= 0:
        return None

    try:
        line_program = dwarf_info.line_program_for_CU(cu)
    except Exception:
        line_program = None
    if line_program is None:
        return None

    header = getattr(line_program, "header", {})
    file_entries = header_list(header, "file_entry")
    if file_index > len(file_entries):
        return None
    file_entry = file_entries[file_index - 1]
    file_name = entry_text(file_entry, "name")
    if not file_name:
        return None

    file_path = Path(file_name)
    if file_path.is_absolute():
        return normalize_source_file(str(file_path))

    dir_index = entry_int(file_entry, "dir_index")
    include_dirs = header_list(header, "include_directory")
    base_dir = ""
    if 0 < dir_index <= len(include_dirs):
        base_dir = decode_text(include_dirs[dir_index - 1])
    if not base_dir:
        base_dir = compilation_directory(cu) or ""
    if base_dir:
        return normalize_source_file(str(Path(base_dir) / file_name))
    return normalize_source_file(file_name)


def compilation_directory(cu: Any) -> str | None:
    """Return the compilation directory recorded on a unit's top DIE."""

    try:
        top_die = cu.get_top_DIE()
    except Exception:
        return None
    comp_dir = top_die.attributes.get("DW_AT_comp_dir")
    return None if comp_dir is None else decode_text(comp_dir.value)


def header_list(header: object, key: str) -> list[Any]:
    """Read a list-like line-program header field across pyelftools versions."""

    header_any = cast(Any, header)
    value: object
    if hasattr(header, "get"):
        value = cast(object, header_any.get(key, []))
    else:
        value = cast(object, getattr(header, key, []))
    if isinstance(value, list):
        return list(cast(Iterable[Any], value))
    return list(cast(Iterable[Any], value))


def entry_text(entry: object, key: str) -> str:
    """Read and decode a text field from a line-program entry."""

    entry_any = cast(Any, entry)
    value = entry_any.get(key, b"") if hasattr(entry, "get") else getattr(entry, key, b"")
    return decode_text(value)


def entry_int(entry: object, key: str) -> int:
    """Read and safely coerce an integer line-program entry field."""

    entry_any = cast(Any, entry)
    value: object
    if hasattr(entry, "get"):
        value = entry_any.get(key, 0)
    else:
        value = getattr(entry, key, 0)
    try:
        if isinstance(value, int):
            return value
        if isinstance(value, str | bytes | bytearray):
            return int(value)
        return int(cast(SupportsInt, value))
    except (TypeError, ValueError):
        return 0


def decode_text(value: object) -> str:
    """Decode bytes or stringify a text-like DWARF value."""

    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value) if value is not None else ""


def normalize_source_file(source_file: str) -> str:
    """Normalize source-file separators and surrounding quotes."""

    return source_file.replace("\\", "/").strip().strip('"')

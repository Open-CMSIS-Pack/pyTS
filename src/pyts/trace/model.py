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

"""Value objects shared by trace project, transformation, and workflow modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from pyts.domain import JsonValue, YamlMapping
from pyts.symbols import SymbolFile


@dataclass(frozen=True)
class LocationSpec:
    """Parsed CMSIS trace location value."""

    original: str
    symbol: str | None
    source_file: str | None
    qualifier: str | None
    address: int | None

    @classmethod
    def from_yaml(cls, value: JsonValue) -> LocationSpec | None:
        """Parse an address or qualified symbol location from a YAML scalar."""

        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return cls(str(value), None, None, None, value)
        if not isinstance(value, str):
            return None

        original = value
        text = normalize_alias(value)
        if not text:
            return None
        address = parse_int(text)
        if address is not None:
            return cls(original, None, None, None, address)

        qualifier: str | None = None
        expression = text
        if "|" in text:
            qualifier, expression = text.split("|", 1)
            qualifier = qualifier.strip() or None
            expression = expression.strip()

        source_file: str | None = None
        symbol = expression
        if "::" in expression:
            source_file, symbol = expression.split("::", 1)
            source_file = unquote(source_file.strip()) or None
            symbol = symbol.strip()
        if not symbol:
            return None
        return cls(original, symbol, source_file, qualifier, None)


@dataclass(frozen=True)
class ResolvedLocation:
    """Resolved symbol metadata for one trace location entry."""

    symbol_file: str
    symbol: str
    address: int
    address_hex: str
    size: int
    type: str


@dataclass(frozen=True)
class TraceSetupResult:
    """Summary returned after writing a trace-run document."""

    cbuild_run: str
    ctrace: str
    output: str
    target: str
    symbols: list[str]
    missing: list[str]

    def to_dict(self) -> dict[str, str | list[str]]:
        """Return this summary as a plain JSON/YAML-compatible mapping."""

        return asdict(self)


@dataclass(frozen=True)
class TraceProject:
    """Resolved project paths and cbuild metadata for one setup run."""

    cbuild_run_path: Path
    cbuild_run: YamlMapping
    project_root: Path
    target: str
    ctrace_path: Path
    output_path: Path
    symbol_files: tuple[SymbolFile, ...]


@dataclass(frozen=True)
class TraceTransformResult:
    """Copied document plus symbol resolution results."""

    document: YamlMapping
    symbols: list[str]
    missing: list[str]
    has_locations: bool
    has_legacy_entries: bool


def normalize_alias(value: str) -> str:
    """Normalize path separators, soft hyphens, and surrounding whitespace."""

    return value.replace("\u00ad", "").replace("\\", "/").strip()


def parse_int(value: str) -> int | None:
    """Parse a base-prefixed integer string, returning ``None`` on failure."""

    try:
        return int(value, 0)
    except ValueError:
        return None


def unquote(value: str) -> str:
    """Remove one matching pair of double quotes from a string."""

    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value

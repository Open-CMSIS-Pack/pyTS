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

"""Typed requests and session state for architectural CoreSight generation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, IntEnum

from pyts.domain import JsonValue, YamlMapping
from pyts.yaml_io import HexInt


class DwtVersion(IntEnum):
    """Supported architectural DWT generations."""

    V1 = 1
    V2 = 2


_CORE_ALIAS_GROUPS: dict[str, tuple[str, ...]] = {
    "MC1": ("MC1", "STAR-MC1"),
    "MC3": ("MC3", "STAR-MC3"),
    "SC000": ("SC000", "SecurCore SC000"),
    "SC300": ("SC300", "SecurCore SC300"),
    "CM0": ("CM0", "Cortex-M0"),
    "CM0+": ("CM0+", "CM0PLUS", "Cortex-M0+", "Cortex-M0plus"),
    "CM1": ("CM1", "Cortex-M1"),
    "CM23": ("CM23", "Cortex-M23"),
    "CM3": ("CM3", "Cortex-M3"),
    "CM33": ("CM33", "Cortex-M33"),
    "CM35P": ("CM35P", "Cortex-M35P"),
    "CM52": ("CM52", "Cortex-M52"),
    "CM55": ("CM55", "Cortex-M55"),
    "CM85": ("CM85", "Cortex-M85"),
    "CM4": ("CM4", "Cortex-M4"),
    "CM7": ("CM7", "Cortex-M7"),
    "ARMV8MBL": ("ARMV8MBL",),
    "ARMV8MML": ("ARMV8MML",),
    "ARMV81MML": ("ARMV81MML",),
}

_CORE_ALIASES: dict[str, str] = {
    alias.casefold(): normalized
    for normalized, aliases in _CORE_ALIAS_GROUPS.items()
    for alias in aliases
}

_PROCESSOR_CLASSES = {
    "MC1": "STAR-MC1",
    "MC3": "STAR-MC3",
    "SC000": "SecurCore SC000",
    "SC300": "SecurCore SC300",
    "CM0": "Cortex-M0",
    "CM0+": "Cortex-M0+",
    "CM1": "Cortex-M1",
    "CM23": "Cortex-M23",
    "CM3": "Cortex-M3",
    "CM33": "Cortex-M33",
    "CM35P": "Cortex-M35P",
    "CM52": "Cortex-M52",
    "CM55": "Cortex-M55",
    "CM85": "Cortex-M85",
    "CM4": "Cortex-M4",
    "CM7": "Cortex-M7",
    "ARMV8MBL": "ARMV8MBL",
    "ARMV8MML": "ARMV8MML",
    "ARMV81MML": "ARMV81MML",
}

_DWT_VERSIONS = {
    "CM3": DwtVersion.V1,
    "CM4": DwtVersion.V1,
    "CM7": DwtVersion.V1,
    "SC300": DwtVersion.V1,
    "MC1": DwtVersion.V2,
    "MC3": DwtVersion.V2,
    "CM23": DwtVersion.V2,
    "CM33": DwtVersion.V2,
    "CM35P": DwtVersion.V2,
    "CM52": DwtVersion.V2,
    "CM55": DwtVersion.V2,
    "CM85": DwtVersion.V2,
}


class DataAccess(str, Enum):
    """Memory access direction selected for data tracing."""

    READ = "R"
    WRITE = "W"
    READ_WRITE = "RW"


class DataOutput(str, Enum):
    """Packet content requested for one data trace entry."""

    VALUE = "value"
    OFFSET = "offset"
    PC = "PC"
    MATCH = "match"
    PC_VALUE = "PC+value"
    OFFSET_VALUE = "offset+value"
    PC_OFFSET = "PC+offset"


@dataclass(frozen=True)
class DataMatch:
    """Validated DWT data value match configuration."""

    value: int
    size: int

    @classmethod
    def from_yaml(cls, value: JsonValue) -> DataMatch:
        """Parse and validate a ``data.match`` YAML node."""

        if not isinstance(value, dict):
            raise ValueError("data.match must be a mapping")
        if "value" not in value:
            raise ValueError("data.match.value is required")
        match_value = _integer(value.get("value"))
        if match_value is None:
            raise ValueError("data.match.value must be an integer")
        if "size" in value:
            match_size = _integer(value.get("size"))
            if match_size is None:
                raise ValueError("data.match.size must be an integer")
        else:
            match_size = 4
        if match_size not in {1, 2, 4}:
            raise ValueError("data.match.size must be 1, 2, or 4")
        if not 0 <= match_value < 1 << (match_size * 8):
            raise ValueError("data.match.value does not fit data.match.size")
        return cls(value=match_value, size=match_size)


@dataclass(frozen=True)
class DataTraceRequest:
    """Validated architecture-independent data trace request."""

    address: int
    size: int
    access: DataAccess
    output: DataOutput
    match: DataMatch | None = None

    @classmethod
    def from_yaml(cls, value: JsonValue) -> DataTraceRequest:
        """Parse and validate one CMSIS ``data`` entry."""

        if not isinstance(value, dict):
            raise ValueError("data entry must be a mapping")
        address = _integer(value.get("address"))
        if address is None:
            error = value.get("error")
            raise ValueError(
                error
                if isinstance(error, str)
                else "data location has no resolved address"
            )
        if not 0 <= address <= 0xFFFFFFFF:
            raise ValueError("data address must be a 32-bit unsigned integer")

        if "size" in value:
            size = _integer(value.get("size"))
            if size is None:
                raise ValueError("data.size must be an integer")
        else:
            size = 4
        if size <= 0:
            raise ValueError("data.size must be a positive integer")
        if address + size - 1 > 0xFFFFFFFF:
            raise ValueError("data range exceeds the 32-bit address space")

        access_value = value.get("access", "W")
        if not isinstance(access_value, str):
            raise ValueError("data.access must be R, W, or RW")
        try:
            access = DataAccess(access_value.upper())
        except ValueError:
            raise ValueError("data.access must be R, W, or RW") from None

        output_value = value.get("output", "value")
        if not isinstance(output_value, str):
            raise ValueError(f"unsupported data.output value: {output_value!r}")
        try:
            output = DataOutput(output_value)
        except ValueError:
            raise ValueError(
                f"unsupported data.output value: {output_value!r}"
            ) from None

        match = DataMatch.from_yaml(value["match"]) if "match" in value else None
        return cls(address, size, access, output, match)


@dataclass(frozen=True)
class RegisterWrite:
    """One masked or unmasked architectural register write."""

    name: str
    value: int
    mask: int | None = None

    def to_yaml(self) -> YamlMapping:
        """Serialize the write with hexadecimal integer formatting."""

        result: YamlMapping = {"name": self.name, "value": HexInt(self.value)}
        if self.mask is not None:
            result["mask"] = HexInt(self.mask)
        return result


@dataclass
class ComparatorAllocator:
    """Allocate DWT comparators for one generation session."""

    next_index: int = 0

    def allocate(
        self,
        count: int,
    ) -> list[int]:
        """Reserve consecutive comparator indices for one encoded request."""

        if count <= 0:
            raise ValueError("comparator allocation count must be positive")
        indices = list(range(self.next_index, self.next_index + count))
        self.next_index += count
        return indices


@dataclass
class CoreSight(ABC):
    """Explicit per-processor CoreSight register generation session."""

    core: str
    comparators: ComparatorAllocator = field(default_factory=ComparatorAllocator)

    def encode_data(self, request: DataTraceRequest) -> list[YamlMapping]:
        """Encode one validated request using this session's allocator."""

        return [write.to_yaml() for write in self._encode_data(request)]

    @abstractmethod
    def _encode_data(self, request: DataTraceRequest) -> list[RegisterWrite]:
        """Return architecture-specific writes for one request."""


def normalize_core(core: str) -> str | None:
    """Resolve a known processor spelling to its CMSIS device enum literal."""

    return _CORE_ALIASES.get(core.casefold())


def processor_class(core: str) -> str:
    """Return the fixed user-facing class name for a known processor."""

    normalized = normalize_core(core)
    if normalized is None:
        return core
    return _PROCESSOR_CLASSES.get(normalized, core)


def dwt_version_for_core(core: str) -> DwtVersion | None:
    """Return the DWT generation for a known processor spelling."""

    normalized = normalize_core(core)
    if normalized is None:
        return None
    return _DWT_VERSIONS.get(normalized)


def _integer(value: JsonValue) -> int | None:
    """Parse an integer YAML scalar while rejecting booleans."""

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

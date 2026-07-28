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

"""DWT version 2 CoreSight implementation."""

from __future__ import annotations

from dataclasses import dataclass

from pyts.coresight.model import (
    CoreSight,
    DataAccess,
    DataMatch,
    DataOutput,
    DataTraceRequest,
    RegisterWrite,
    normalize_core,
    processor_class,
)


@dataclass(frozen=True)
class DwtV2Encoder:
    """Stateless DWTv2 request encoder."""

    core: str

    def allocation_count(self, request: DataTraceRequest) -> tuple[int, bool]:
        """Return comparator count and address-with-value restriction."""

        self._validate_core()
        if request.match is not None:
            self._validate_match(request, request.match)
            _function, uses_value = _output_function(
                request.output,
                request.access,
            )
            return 2, uses_value
        use_range, uses_value = self._address_mode(request)
        if use_range and request.size == 1:
            raise ValueError(
                f"{processor_class(self.core)} DWT-Unit data.output "
                f"{request.output.value!r} cannot emit an offset for a one-byte range"
            )
        return (2 if use_range else 1), uses_value

    def encode(self, request: DataTraceRequest, indices: list[int]) -> list[RegisterWrite]:
        """Encode a validated request using allocated comparator indices."""

        if request.match is not None:
            return self._match_writes(request, request.match, indices)
        return self._address_writes(request, indices)

    def _validate_core(self) -> None:
        """Reject cores that cannot emit DWT data trace packets."""

        if normalize_core(self.core) == "CM23":
            raise ValueError(
                "Cortex-M23 DWT-Unit does not support data trace packets"
            )

    def _validate_match(self, request: DataTraceRequest, match: DataMatch) -> None:
        """Validate DWTv2 linked data-value matching constraints."""

        dwt_unit = f"{processor_class(self.core)} DWT-Unit"
        if request.size != match.size:
            raise ValueError(
                f"{dwt_unit} data.size must equal data.match.size"
            )
        if request.address % match.size:
            raise ValueError(
                f"{dwt_unit} match address must be aligned to data.match.size"
            )

    @staticmethod
    def _address_mode(request: DataTraceRequest) -> tuple[bool, bool]:
        """Return whether a range and data-value matching are required."""

        use_range = (
            request.output in _OFFSET_OUTPUTS
            or request.size not in _DATA_SIZE
            or request.address % request.size != 0
        )
        uses_value = request.output in _VALUE_OUTPUTS
        return use_range, uses_value

    def _match_writes(
        self,
        request: DataTraceRequest,
        match: DataMatch,
        indices: list[int],
    ) -> list[RegisterWrite]:
        """Encode a linked address and value comparator pair."""

        address_index, value_index = indices
        size_bits = _DATA_SIZE[match.size]
        first_function, _ = _output_function(
            request.output,
            request.access,
        )
        return [
            RegisterWrite(f"DWT_COMP{address_index}", request.address),
            RegisterWrite(
                f"DWT_FUNCTION{address_index}",
                size_bits | first_function,
            ),
            RegisterWrite(f"DWT_COMP{value_index}", _replicate_match_value(match)),
            RegisterWrite(f"DWT_FUNCTION{value_index}", size_bits | 0x20 | 0xB),
            _forwarding_write(),
        ]

    def _address_writes(
        self,
        request: DataTraceRequest,
        indices: list[int],
    ) -> list[RegisterWrite]:
        """Encode a single-address or range-based data trace request."""

        use_range, _ = self._address_mode(request)
        function, _ = _output_function(
            request.output,
            request.access,
        )

        if use_range:
            lower, limit = indices
            limit_action = (
                0x30
                if request.output in _OFFSET_OUTPUTS
                else 0
            )
            return [
                RegisterWrite(f"DWT_COMP{lower}", request.address),
                RegisterWrite(f"DWT_FUNCTION{lower}", function),
                RegisterWrite(
                    f"DWT_COMP{limit}", request.address + request.size - 1
                ),
                RegisterWrite(f"DWT_FUNCTION{limit}", limit_action | 0x7),
                _forwarding_write(),
            ]

        index = indices[0]
        return [
            RegisterWrite(f"DWT_COMP{index}", request.address),
            RegisterWrite(
                f"DWT_FUNCTION{index}",
                _DATA_SIZE[request.size] | function,
            ),
            _forwarding_write(),
        ]


class DwtV2CoreSight(CoreSight):
    """Per-processor DWTv2 generation session."""

    def _encode_data(self, request: DataTraceRequest) -> list[RegisterWrite]:
        """Validate, allocate comparators, and encode one DWTv2 request."""

        encoder = DwtV2Encoder(self.core)
        count, restricted = encoder.allocation_count(request)
        if restricted and self.comparators.next_index >= 4:
            raise ValueError(
                f"{processor_class(self.core)} DWT-Unit Data Address With Value "
                "requires an address comparator with index 0 through 3"
            )
        indices = self.comparators.allocate(count)
        return encoder.encode(request, indices)


_DATA_SIZE = {1: 0, 2: 1 << 10, 4: 2 << 10}

_OUTPUT_ACTION = {
    DataOutput.VALUE: 0x20,
    DataOutput.OFFSET: 0x00,
    DataOutput.PC: 0x30,
    DataOutput.MATCH: 0x20,
    DataOutput.PC_VALUE: 0x30,
    DataOutput.OFFSET_VALUE: 0x20,
    DataOutput.PC_OFFSET: 0x30,
}

_VALUE_OUTPUTS = frozenset(
    {DataOutput.VALUE, DataOutput.PC_VALUE, DataOutput.OFFSET_VALUE}
)

_OFFSET_OUTPUTS = frozenset(
    {DataOutput.OFFSET, DataOutput.OFFSET_VALUE, DataOutput.PC_OFFSET}
)


def _output_function(output: DataOutput, access: DataAccess) -> tuple[int, bool]:
    """Return function bits and the address-with-value restriction flag."""

    uses_value = output in _VALUE_OUTPUTS
    match_type = (
        _address_value_match(access) if uses_value else _address_match(access)
    )
    return _OUTPUT_ACTION[output] | match_type, uses_value


def _address_match(access: DataAccess) -> int:
    """Return the DWTv2 address-match function bits for an access mode."""

    return {DataAccess.READ: 0x6, DataAccess.WRITE: 0x5, DataAccess.READ_WRITE: 0x4}[
        access
    ]


def _address_value_match(access: DataAccess) -> int:
    """Return address-with-value match bits for an access mode."""

    return {DataAccess.READ: 0xE, DataAccess.WRITE: 0xD, DataAccess.READ_WRITE: 0xC}[
        access
    ]


def _replicate_match_value(match: DataMatch) -> int:
    """Replicate byte and halfword match values across a comparator word."""

    if match.size == 1:
        return match.value * 0x01010101
    if match.size == 2:
        return match.value | match.value << 16
    return match.value


def _forwarding_write() -> RegisterWrite:
    """Return the ITM write enabling DWT packet forwarding."""

    return RegisterWrite("ITM_TCR", 9, 9)

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

"""DWT version 1 CoreSight implementation."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from pyts.coresight.model import (
    CoreSight,
    DataAccess,
    DataOutput,
    DataTraceRequest,
    RegisterWrite,
    processor_class,
)


@dataclass(frozen=True)
class DwtV1Encoder:
    """Stateless DWTv1 request encoder."""

    core: str

    def encode(
        self,
        request: DataTraceRequest,
        indices: list[int],
    ) -> list[RegisterWrite]:
        """Validate and encode one DWTv1 request using assigned comparators."""

        function = self._validate(request)
        if request.match is not None:
            address_index, value_index = indices
            match_function = (
                (1 << 8)
                | (address_index << 12)
                | _DATA_SIZE[request.match.size]
                | function
            )
            return [
                RegisterWrite(f"DWT_COMP{address_index}", request.address),
                RegisterWrite(
                    f"DWT_MASK{address_index}",
                    request.size.bit_length() - 1,
                ),
                RegisterWrite(f"DWT_FUNCTION{address_index}", 0),
                RegisterWrite(f"DWT_COMP{value_index}", request.match.value),
                RegisterWrite(f"DWT_FUNCTION{value_index}", match_function),
                _forwarding_write(),
            ]

        index = indices[0]
        return [
            RegisterWrite(f"DWT_COMP{index}", request.address),
            RegisterWrite(
                f"DWT_MASK{index}", request.size.bit_length() - 1
            ),
            RegisterWrite(f"DWT_FUNCTION{index}", function),
            _forwarding_write(),
        ]

    def _validate(self, request: DataTraceRequest) -> int:
        """Validate DWTv1 output support and return its function code."""

        dwt_unit = f"{processor_class(self.core)} DWT-Unit"
        if request.output not in _FUNCTIONS:
            raise ValueError(
                f"{dwt_unit} does not support data.output {request.output.value!r}"
            )
        function = _FUNCTIONS[request.output].get(request.access)
        if function is None:
            raise ValueError(
                f"{dwt_unit} data.output {request.output.value!r} does not support "
                f"access {request.access.value}"
            )
        return function


@dataclass
class DwtV1CoreSight(CoreSight):
    """Per-processor DWTv1 session with one portable linked match pair."""

    _match_pair_reserved: bool = field(default=False, init=False)
    _match_pair_available: bool = field(default=False, init=False)

    def normalize_data_request(
        self, request: DataTraceRequest
    ) -> DataTraceRequest:
        """Expand a request to its smallest enclosing DWTv1 mask range."""

        last_address = request.address + request.size - 1
        size = 1 << (request.address ^ last_address).bit_length()
        if size > 1 << 31:
            raise ValueError(
                f"Data range exceeds {processor_class(self.core)} "
                "DWT-Unit mask capability"
            )
        address = request.address & ~(size - 1)
        # replace preserves the concrete dataclass type at runtime, but
        # Radarlint S5886 models its return as a generic DataclassInstance.
        return replace(request, address=address, size=size)  # NOSONAR

    def reserve_data_match_pair(self) -> None:
        """Reserve portable comparators 0/1 before ordinary allocation begins."""

        if self._match_pair_reserved:
            return
        if self.comparators.next_index != 0:
            raise ValueError(
                f"{processor_class(self.core)} DWT-Unit portable data.match "
                "requires comparators 0 and 1 "
                "before other data trace requests"
            )
        self.comparators.allocate(2)
        self._match_pair_reserved = True
        self._match_pair_available = True

    def _encode_data(self, request: DataTraceRequest) -> list[RegisterWrite]:
        """Encode without consuming allocation state when validation fails."""

        encoder = DwtV1Encoder(self.core)
        if request.match is not None:
            writes = encoder.encode(request, [0, 1])
            if not self._match_pair_reserved:
                self.reserve_data_match_pair()
            if not self._match_pair_available:
                raise ValueError(
                    f"{processor_class(self.core)} DWT-Unit supports only one "
                    "portable data.match using "
                    "comparators 0 and 1"
                )
            self._match_pair_available = False
            return writes

        next_index = self.comparators.next_index
        writes = encoder.encode(request, [next_index])
        self.comparators.allocate(1)
        return writes


_FUNCTIONS: dict[DataOutput, dict[DataAccess, int]] = {
    DataOutput.VALUE: {
        DataAccess.READ: 0xC,
        DataAccess.WRITE: 0xD,
        DataAccess.READ_WRITE: 0x2,
    },
    DataOutput.OFFSET: {
        DataAccess.READ: 0x2C,
        DataAccess.WRITE: 0x2D,
        DataAccess.READ_WRITE: 0x21,
    },
    DataOutput.PC: {DataAccess.READ_WRITE: 0x1},
    DataOutput.PC_VALUE: {
        DataAccess.READ: 0xE,
        DataAccess.WRITE: 0xF,
        DataAccess.READ_WRITE: 0x3,
    },
    DataOutput.OFFSET_VALUE: {
        DataAccess.READ: 0x2E,
        DataAccess.WRITE: 0x2F,
        DataAccess.READ_WRITE: 0x22,
    },
}

_DATA_SIZE = {1: 0, 2: 1 << 10, 4: 2 << 10}


def _forwarding_write() -> RegisterWrite:
    """Return the ITM write enabling DWT packet forwarding."""

    return RegisterWrite("ITM_TCR", 9, 9)

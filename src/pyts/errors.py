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

"""Domain exceptions raised by the trace setup workflow."""

from __future__ import annotations

from collections.abc import Sequence


class TraceSetupError(ValueError):
    """Base class for expected trace setup failures."""


class MissingSymbolsError(TraceSetupError):
    """Raised when required trace locations cannot be resolved."""

    def __init__(self, missing: Sequence[str]) -> None:
        """Create an error containing missing names in document order."""

        self.missing = tuple(missing)
        super().__init__("missing symbols: " + ", ".join(self.missing))

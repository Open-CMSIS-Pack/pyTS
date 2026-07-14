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

"""Architectural CoreSight register generation."""

from pyts.coresight.generator import (
    Processor,
    create_coresight,
    generate_ctrace_run,
    processors_from_cbuild,
)
from pyts.coresight.model import (
    CoreSight,
    DataAccess,
    DataOutput,
    DataTraceRequest,
    DwtVersion,
    RegisterWrite,
)
from pyts.coresight.v1 import DwtV1CoreSight
from pyts.coresight.v2 import DwtV2CoreSight

__all__ = [
    "CoreSight",
    "DataAccess",
    "DataOutput",
    "DataTraceRequest",
    "DwtV1CoreSight",
    "DwtV2CoreSight",
    "DwtVersion",
    "Processor",
    "RegisterWrite",
    "create_coresight",
    "generate_ctrace_run",
    "processors_from_cbuild",
]

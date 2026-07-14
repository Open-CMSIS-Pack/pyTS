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

"""CMSIS trace setup workflow and transformation API."""

from pyts.trace.model import (
    LocationSpec,
    ResolvedLocation,
    TraceProject,
    TraceSetupResult,
    TraceTransformResult,
)
from pyts.trace.transform import transform_trace_document
from pyts.trace.workflow import setup_trace

__all__ = [
    "LocationSpec",
    "ResolvedLocation",
    "TraceProject",
    "TraceSetupResult",
    "TraceTransformResult",
    "setup_trace",
    "transform_trace_document",
]

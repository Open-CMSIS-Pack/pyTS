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

from __future__ import annotations

import pyts
from pyts.elf import (
    DwarfELFLike,
    ELFLike,
    ElfResolver,
    MemberInfo,
    SymbolInfo,
    missing_symbols,
)
from pyts.elf.model import MemberInfo as ModelMemberInfo
from pyts.elf.model import SymbolInfo as ModelSymbolInfo
from pyts.elf.resolver import ElfResolver as ResolverImplementation
from pyts.trace import (
    LocationSpec,
    ResolvedLocation,
    TraceProject,
    TraceSetupResult,
    TraceTransformResult,
    setup_trace,
    transform_trace_document,
)
from pyts.trace.model import TraceSetupResult as ModelTraceSetupResult
from pyts.trace.transform import transform_trace_document as transform_implementation
from pyts.trace.workflow import setup_trace as setup_implementation


def test_elf_facade_preserves_public_imports() -> None:
    assert ElfResolver is ResolverImplementation
    assert SymbolInfo is ModelSymbolInfo
    assert MemberInfo is ModelMemberInfo
    assert pyts.ElfResolver is ElfResolver
    assert pyts.SymbolInfo is SymbolInfo
    assert pyts.MemberInfo is MemberInfo
    assert callable(missing_symbols)
    assert ELFLike is not None
    assert DwarfELFLike is not None


def test_trace_facade_preserves_public_imports() -> None:
    assert setup_trace is setup_implementation
    assert transform_trace_document is transform_implementation
    assert TraceSetupResult is ModelTraceSetupResult
    assert pyts.setup_trace is setup_trace
    assert pyts.transform_trace_document is transform_trace_document
    assert pyts.TraceSetupResult is TraceSetupResult
    assert LocationSpec is not None
    assert ResolvedLocation is not None
    assert TraceProject is not None
    assert TraceTransformResult is not None

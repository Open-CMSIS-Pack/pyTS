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

"""Filesystem orchestration for CMSIS trace setup generation."""

from __future__ import annotations

from pathlib import Path

from pyts.coresight import generate_ctrace_run, processors_from_cbuild
from pyts.domain import YamlMapping
from pyts.errors import MissingSymbolsError
from pyts.symbols import SymbolCatalog
from pyts.trace.model import TraceSetupResult
from pyts.trace.project import load_trace_project, required_mapping
from pyts.trace.transform import transform_trace_document
from pyts.yaml_io import read_yaml, write_yaml


def setup_trace(
    cbuild_run_path: str | Path,
    *,
    allow_missing: bool = False,
) -> TraceSetupResult:
    """Generate a CMSIS trace run file from a cbuild-run file.

    Legacy-only missing symbols fail before writing. Location-style and mixed
    documents write annotated diagnostics before raising ``MissingSymbolsError``.
    """

    project = load_trace_project(Path(cbuild_run_path))
    source = required_mapping(read_yaml(project.ctrace_path), "ctrace file")
    with SymbolCatalog(project.symbol_files) as catalog:
        transformed = transform_trace_document(source, catalog)

    if (
        transformed.missing
        and not allow_missing
        and transformed.has_legacy_entries
        and not transformed.has_locations
    ):
        raise MissingSymbolsError(transformed.missing)

    project.output_path.parent.mkdir(parents=True, exist_ok=True)
    processors = processors_from_cbuild(project.cbuild_run)
    output = (
        generate_ctrace_run(transformed.document, processors)
        if processors and has_spec_setup(transformed.document)
        else transformed.document
    )
    write_yaml(project.output_path, output, sort_keys=False)
    if transformed.missing and not allow_missing:
        raise MissingSymbolsError(transformed.missing)

    return TraceSetupResult(
        cbuild_run=str(project.cbuild_run_path),
        ctrace=str(project.ctrace_path),
        output=str(project.output_path),
        target=project.target,
        symbols=transformed.symbols,
        missing=transformed.missing,
    )


def has_spec_setup(ctrace: YamlMapping) -> bool:
    """Return whether a document contains specification-style setup entries."""

    root = ctrace.get("ctrace")
    return isinstance(root, dict) and isinstance(root.get("setup"), list)

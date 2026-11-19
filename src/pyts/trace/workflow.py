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

from pyts._version import package_version
from pyts.coresight import generate_ctrace_run, processors_from_cbuild
from pyts.domain import YamlMapping
from pyts.errors import MissingSymbolsError
from pyts.symbols import SymbolCatalog
from pyts.trace.model import TraceSetupResult
from pyts.trace.project import load_trace_project, required_mapping
from pyts.trace.transform import mapping_refs, transform_trace_document
from pyts.yaml_io import read_yaml, write_yaml


def setup_trace(
    cbuild_run_path: str | Path,
    *,
    allow_missing: bool = False,
) -> TraceSetupResult:
    """Generate a CMSIS trace run file from a cbuild-run file.

    Missing inputs write a diagnostic run file. Unresolved symbols write their
    diagnostics before raising ``MissingSymbolsError`` unless allowed.
    """

    build_path = Path(cbuild_run_path)
    try:
        project = load_trace_project(build_path)
    except FileNotFoundError as exc:
        # Without build metadata, place the diagnostic beside the requested input.
        name = (
            build_path.name.removesuffix(".yml")
            .removesuffix(".yaml")
            .removesuffix(".cbuild-run")
        )
        return _write_input_error(
            build_path,
            build_path.parent / ".cmsis" / f"{name}.ctrace.yml",
            build_path.parent / ".trace" / f"{name}.ctrace-run.yml",
            "",
            exc,
        )
    try:
        source = required_mapping(read_yaml(project.ctrace_path), "ctrace file")
    except FileNotFoundError as exc:
        return _write_input_error(
            build_path,
            project.ctrace_path,
            project.output_path,
            project.target,
            exc,
        )
    with SymbolCatalog(project.symbol_files) as catalog:
        transformed = transform_trace_document(
            source,
            catalog,
            symbol_file_directory=project.output_path.parent,
        )

    project.output_path.parent.mkdir(parents=True, exist_ok=True)
    processors = processors_from_cbuild(project.cbuild_run)
    output = (
        generate_ctrace_run(transformed.document, processors, source)
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
        diagnostics=_output_diagnostics(output),
    )


def _write_input_error(
    build_path: Path,
    trace_path: Path,
    output_path: Path,
    target: str,
    error: FileNotFoundError,
) -> TraceSetupResult:
    """Replace stale output with a root diagnostic when an input is missing."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_yaml(output_path, {
        "ctrace-run": {
            "generated-by": f"pyTS v{package_version()}",
            "ctrace-setup": [],
            "ctrace-disable": None,
            "ctrace-refs": [{
                "ref": "ctrace",
                "error": f"file not found: {error.filename}",
            }],
        },
    })
    return TraceSetupResult(
        cbuild_run=str(build_path),
        ctrace=str(trace_path),
        output=str(output_path),
        target=target,
        symbols=[],
        missing=[],
        diagnostics=frozenset({"error"}),
    )


def _output_diagnostics(document: YamlMapping) -> frozenset[str]:
    """Find error and warning fields in the document that was written."""

    return frozenset(
        level
        for ref in mapping_refs(document)
        for level in ("error", "warning")
        if isinstance(ref.value.get(level), str)
    )


def has_spec_setup(ctrace: YamlMapping) -> bool:
    """Return whether a document contains specification-style setup entries."""

    root = ctrace.get("ctrace")
    return isinstance(root, dict) and isinstance(root.get("setup"), list)

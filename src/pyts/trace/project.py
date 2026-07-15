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

"""Trace project loading, path derivation, and ELF output discovery."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from pyts.domain import YamlMapping
from pyts.symbols import SymbolFile
from pyts.trace.model import TraceProject, normalize_alias
from pyts.yaml_io import read_yaml


def load_trace_project(cbuild_run_path: Path) -> TraceProject:
    """Load cbuild metadata and derive all trace project paths."""

    cbuild_run = required_mapping(read_yaml(cbuild_run_path), "cbuild-run file")
    data = required_mapping(cbuild_run.get("cbuild-run"), "cbuild-run")
    root = project_root(cbuild_run_path, data)
    solution_name = (
        solution(cbuild_run_path, data).name
            .removesuffix(".yaml")
            .removesuffix(".yml")
            .removesuffix(".csolution")
    )
    target = target_name(data)
    return TraceProject(
        cbuild_run_path=cbuild_run_path,
        cbuild_run=data,
        project_root=root,
        target=target,
        ctrace_path=root / ".cmsis" / f"{solution_name}+{target}.ctrace.yml",
        output_path=root / ".trace" / f"{solution_name}+{target}.ctrace-run.yml",
        symbol_files=tuple(symbol_files(cbuild_run_path, data, root)),
    )

def solution(cbuild_run_path: Path, cbuild_run: YamlMapping) -> Path:
    """Return the solution name from the cbuild-run file."""

    solution = cbuild_run.get("solution")
    if not isinstance(solution, str) or not solution:
        raise ValueError("cbuild-run.solution is required")
    return (cbuild_run_path.parent / solution).resolve(strict=False)

def project_root(cbuild_run_path: Path, cbuild_run: YamlMapping) -> Path:
    """Derive the project root from the cbuild solution path."""

    return solution(cbuild_run_path, cbuild_run).parent


def target_name(cbuild_run: YamlMapping) -> str:
    """Return the target type with an optional target-set suffix."""

    target_type = cbuild_run.get("target-type")
    if not isinstance(target_type, str) or not target_type:
        raise ValueError("cbuild-run.target-type is required")
    target_set = cbuild_run.get("target-set")
    return (
        f"{target_type}@{target_set}"
        if isinstance(target_set, str) and target_set and target_set != "<default>"
        else target_type
    )


def symbol_files(
    cbuild_run_path: Path,
    cbuild_run: YamlMapping,
    root: Path,
) -> list[SymbolFile]:
    """Discover ordered ELF outputs and their qualifier aliases."""

    outputs = cbuild_run.get("output")
    if not isinstance(outputs, list):
        raise ValueError("cbuild-run.output must list at least one ELF file")
    projects = project_aliases_from_index(root)
    results: list[SymbolFile] = []
    for output in outputs:
        if not isinstance(output, dict) or output.get("type") != "elf":
            continue
        file_name = output.get("file")
        if not isinstance(file_name, str) or not file_name:
            continue
        path = Path(file_name)
        if not path.is_absolute():
            path = cbuild_run_path.parent / path
        resolved_path = path.resolve(strict=False)
        results.append(
            SymbolFile(
                path=path,
                aliases=file_aliases(file_name, resolved_path),
                project=output_project(file_name, output, projects),
            )
        )
    if not results:
        raise ValueError("cbuild-run.output must list at least one ELF file")
    return results


def project_aliases_from_index(root: Path) -> dict[str, str]:
    """Load cbuild-path-to-project aliases from the optional build index."""

    index_path = root / f"{root.name}.cbuild-idx.yml"
    if not index_path.exists():
        return {}
    try:
        index = required_mapping(read_yaml(index_path), "cbuild index")
        build_idx = required_mapping(index.get("build-idx"), "build-idx")
    except ValueError:
        return {}
    cbuilds = build_idx.get("cbuilds")
    if not isinstance(cbuilds, list):
        return {}
    projects: dict[str, str] = {}
    for cbuild in cbuilds:
        if not isinstance(cbuild, dict):
            continue
        project = cbuild.get("project")
        cbuild_path = cbuild.get("cbuild")
        if not isinstance(project, str) or not isinstance(cbuild_path, str):
            continue
        path = Path(cbuild_path)
        projects[normalize_alias(str(path))] = project
        projects[normalize_alias(str(path.parent))] = project
    return projects


def output_project(
    file_name: str,
    output: YamlMapping,
    projects: dict[str, str],
) -> str | None:
    """Infer the project qualifier associated with one build output."""

    normalized_file = normalize_alias(file_name)
    for prefix, project in projects.items():
        if normalized_file.startswith(prefix.rstrip("/") + "/"):
            return project
    path = Path(file_name)
    if path.parts and path.parts[0] not in {".", ".."}:
        return path.parts[0]
    info = output.get("info")
    if isinstance(info, str) and " by " in info:
        return info.rsplit(" by ", 1)[1].split(".", 1)[0]
    return None


def file_aliases(file_name: str, resolved_path: Path) -> frozenset[str]:
    """Return normalized full-path, file-name, and stem aliases for an ELF."""

    relative = Path(file_name)
    aliases = {
        normalize_alias(file_name),
        normalize_alias(str(resolved_path)),
        normalize_alias(relative.name),
        normalize_alias(relative.stem),
    }
    return frozenset(alias for alias in aliases if alias)


def required_mapping(value: object, name: str) -> YamlMapping:
    """Validate and narrow a required YAML mapping node."""

    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a mapping")
    return cast(YamlMapping, value)

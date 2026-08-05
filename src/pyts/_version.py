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

"""Package version helpers."""

from __future__ import annotations

import re
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


_DESCRIBE_PATTERN = re.compile(
    r"^v?(?P<release>\d+(?:\.\d+)*)(?:-(?P<distance>\d+)-g(?P<commit>[0-9a-f]+))?"
    r"(?P<dirty>-dirty)?$"
)
_COMMIT_PATTERN = re.compile(r"^(?P<commit>[0-9a-f]+)(?P<dirty>-dirty)?$")
_VERSION_TAG_PATTERN = "v*"


def _repository_root() -> Path:
    """Find the checkout containing this source, or the current checkout."""

    source_root = Path(__file__).resolve().parents[2]
    if (source_root / ".git").exists():
        return source_root

    current = Path.cwd().resolve()
    for parent in (current, *current.parents):
        if (parent / ".git").exists():
            return parent
    return source_root


def source_version() -> str:
    """Return a PEP 440 version derived from the current Git checkout."""

    try:
        description = subprocess.run(
            [
                "git",
                "describe",
                "--tags",
                "--long",
                "--match",
                _VERSION_TAG_PATTERN,
                "--always",
                "--dirty",
                "--abbrev=7",
            ],
            capture_output=True,
            check=True,
            cwd=_repository_root(),
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "0.0.0"

    match = _DESCRIBE_PATTERN.fullmatch(description)
    if match is None:
        commit_match = _COMMIT_PATTERN.fullmatch(description)
        if commit_match is None:
            return "0.0.0"
        return f"0.0.0+g{commit_match['commit']}{'.dirty' if commit_match['dirty'] else ''}"

    release = match["release"]
    distance = match["distance"]
    dirty = match["dirty"]
    if distance == "0" and not dirty:
        return release

    release_parts = release.split(".")
    release_parts[-1] = str(int(release_parts[-1]) + 1)
    next_release = ".".join(release_parts)
    local = f"+g{match['commit']}{'.dirty' if dirty else ''}"
    return f"{next_release}.dev{distance or '0'}{local}"


def package_version() -> str:
    """Return the installed pyTS version, with a source-tree fallback."""

    try:
        return version("pyts")
    except PackageNotFoundError:
        return source_version()

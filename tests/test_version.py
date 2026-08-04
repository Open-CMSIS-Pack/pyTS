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

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import cast

import pytest

from pyts import _version


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("v1.2.3-0-gabcdef0", "1.2.3"),
        ("v1.2.3-0-gabcdef0-dirty", "1.2.4.dev0+gabcdef0.dirty"),
        ("v1.2.3-4-gabcdef0", "1.2.4.dev4+gabcdef0"),
        ("v1.2.3-4-gabcdef0-dirty", "1.2.4.dev4+gabcdef0.dirty"),
        ("abcdef0", "0.0.0+gabcdef0"),
    ],
)
def test_source_version_uses_git_describe(
    monkeypatch: pytest.MonkeyPatch,
    description: str,
    expected: str,
) -> None:
    command: list[object] = []
    working_directory: list[object] = []

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        command.extend(cast(list[object], args[0]))
        working_directory.append(kwargs["cwd"])
        return subprocess.CompletedProcess(["git"], 0, stdout=description, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert _version.source_version() == expected
    assert command == [
        "git",
        "describe",
        "--tags",
        "--long",
        "--match",
        "v*",
        "--always",
        "--dirty",
        "--abbrev=7",
    ]
    assert working_directory == [Path(__file__).resolve().parents[1]]


def test_source_version_falls_back_without_git(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert _version.source_version() == "0.0.0"

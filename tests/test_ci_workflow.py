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

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None,
    reason="Bash is required for CI workflow integration tests",
)


@pytest.mark.parametrize(
    ("event", "tag", "expected_version"),
    [
        ("release", "v1.2.3", "1.2.3"),
        ("release", "v1.2.3rc1", "1.2.3rc1"),
        ("push", "", None),
        ("pull_request", "", None),
        ("workflow_dispatch", "", None),
    ],
)
def test_build_install_sets_release_version(
    tmp_path: Path, event: str, tag: str, expected_version: str | None
) -> None:
    workflow_path = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    workflow = cast(dict[str, Any], yaml.safe_load(workflow_path.read_text()))
    steps = cast(list[dict[str, Any]], workflow["jobs"]["build"]["steps"])
    install = next(step for step in steps if step.get("name") == "Install dependencies")
    assert install["shell"] == "bash"
    assert install["env"]["RELEASE_TAG"] == "${{ github.event.release.tag_name }}"

    github_env = tmp_path / "github-env"
    env = dict(os.environ)
    env.pop("SETUPTOOLS_SCM_PRETEND_VERSION", None)
    env.update(GITHUB_EVENT_NAME=event, RELEASE_TAG=tag, GITHUB_ENV=str(github_env))
    # Observe the version passed to both pip commands without installing anything.
    script = 'python() { printf "%s\\n" "${SETUPTOOLS_SCM_PRETEND_VERSION-unset}"; }\n'
    result = subprocess.run(
        ["bash", "-e", "-c", script + cast(str, install["run"])],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.splitlines() == [expected_version or "unset"] * 2
    if expected_version is None:
        assert not github_env.exists()
    else:
        assert github_env.read_text() == f"SETUPTOOLS_SCM_PRETEND_VERSION={expected_version}\n"


@pytest.mark.parametrize(
    ("tag", "filenames", "valid"),
    [
        (
            "v1.2.3",
            [
                "pyTS-1.2.3-linux-amd64.tar.gz",
                "pyTS-1.2.3-linux-arm64.tar.gz",
                "pyTS-1.2.3-windows-amd64.zip",
                "pyTS-1.2.3-windows-arm64.zip",
                "pyTS-1.2.3-darwin-arm64.tar.gz",
            ],
            True,
        ),
        ("v1.2.3rc1", ["pyTS-1.2.3rc1-linux-amd64.tar.gz"], True),
        ("v1.2.3", ["pyTS-1.2.4-linux-amd64.tar.gz"], False),
        ("v1.2.3", ["pyTS-v1.2.3-linux-amd64.tar.gz"], False),
        ("v1.2.3", ["pyTS-1.2.30-linux-amd64.tar.gz"], False),
        ("v1.2.3", ["pyTS-1.2.3.dev1+gabcdef0-linux-amd64.tar.gz"], False),
        ("v1.2.3", ["pyTS-1.2.3-rc1-linux-amd64.tar.gz"], False),
        ("v1.2.3", ["pyTS-1x2x3-linux-amd64.tar.gz"], False),
        (
            "v1.2.3",
            ["pyTS-1.2.3-linux-amd64.tar.gz", "pyTS-1.2.4-windows-arm64.zip"],
            False,
        ),
        ("v1.2.3", ["unexpected.zip"], False),
        ("v1.2.3", [], False),
    ],
)
def test_release_validates_archive_versions_before_upload(
    tmp_path: Path, tag: str, filenames: list[str], valid: bool
) -> None:
    workflow_path = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    workflow = cast(dict[str, Any], yaml.safe_load(workflow_path.read_text()))
    steps = cast(list[dict[str, Any]], workflow["jobs"]["release"]["steps"])
    names = [step["name"] for step in steps]
    validation_name = "Validate release archive versions"
    assert names.index("Download build artifacts") < names.index(validation_name)
    assert names.index(validation_name) < names.index("Upload executables to GitHub release")
    validation = steps[names.index(validation_name)]
    assert validation["shell"] == "bash"
    assert validation["env"]["RELEASE_TAG"] == "${{ github.event.release.tag_name }}"

    assets = tmp_path / "release-assets"
    assets.mkdir()
    for filename in filenames:
        (assets / filename).touch()

    result = subprocess.run(
        ["bash", "-e", "-c", cast(str, validation["run"])],
        cwd=tmp_path,
        env={**os.environ, "RELEASE_TAG": tag},
        capture_output=True,
        text=True,
    )

    if valid:
        assert result.returncode == 0, result.stdout + result.stderr
    else:
        assert result.returncode != 0
        assert "::error::" in result.stdout
        if filenames:
            assert f"expected version '{tag.removeprefix('v')}'" in result.stdout
        else:
            assert "No release archives found" in result.stdout

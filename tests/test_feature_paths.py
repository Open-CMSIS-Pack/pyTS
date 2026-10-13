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

"""Feature dispatch through complete YAML paths and independent group children."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from pyts.coresight import generator
from pyts.coresight.model import CoreSight
from pyts.domain import JsonValue, YamlMapping
from pyts.yaml_io import read_yaml


def _first_encoder(value: JsonValue, _coresight: CoreSight) -> list[YamlMapping]:
    return [{"name": "FIRST", "value": value}]


def _second_encoder(value: JsonValue, _coresight: CoreSight) -> list[YamlMapping]:
    return [{"name": "SECOND", "value": 0 if value is None else value}]


@pytest.fixture
def grouped_features(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, generator.FeatureSpec]:
    specs = {
        "group.first": generator.FeatureSpec("first"),
        "group.nested.second": generator.FeatureSpec("second"),
    }
    monkeypatch.setattr(generator, "_FEATURE_SPECS", specs)
    monkeypatch.setattr(
        generator,
        "_FEATURE_ENCODERS",
        {
            "group.first": _first_encoder,
            "group.nested.second": _second_encoder,
        },
    )
    return specs


def _generate(tmp_path: Path, setup: str) -> dict[str, Any]:
    path = tmp_path / "trace.yml"
    path.write_text(f"ctrace:\n  setup:\n    - {setup}\n", encoding="utf-8")
    document = read_yaml(path)
    before = deepcopy(document)
    output = generator.generate_ctrace_run(
        document, [generator.Processor.from_core("CM4", "core")],
    )
    assert document == before
    run = cast(dict[str, Any], output["ctrace-run"])
    assert run["ctrace-setup"] == before["ctrace"]["setup"]
    return run


@pytest.mark.usefixtures("grouped_features")
def test_group_children_use_separate_values_encoders_and_paths(tmp_path: Path) -> None:
    run = _generate(
        tmp_path,
        """\
pname: core
      group:
        first: 7
        nested:
          second: 11
          extension: ignored
        extension: ignored
""",
    )
    assert run["ctrace-refs"] == [
        {
            "ref": "core/group/first", "type": "first",
            "regs": [{"name": "FIRST", "value": 7}],
        },
        {
            "ref": "core/group/nested/second", "type": "second",
            "regs": [{"name": "SECOND", "value": 11}],
        },
    ]


@pytest.mark.usefixtures("grouped_features")
@pytest.mark.parametrize(
    "setup",
    [
        "{}", "group:", "group: {}", "group:\n        nested:",
        "group:\n        nested: {}",
        "group:\n        first:\n        nested:\n          second:",
        "group:\n        extension: ignored", '"group.first": 7',
    ],
)
def test_missing_and_null_group_features_are_skipped(tmp_path: Path, setup: str) -> None:
    assert _generate(tmp_path, setup)["ctrace-refs"] == []


@pytest.mark.parametrize(
    "setup",
    [
        "{}", "group:", "group: {}", "group:\n        nested:",
        "group:\n        nested:\n          second:",
    ],
)
def test_default_feature_is_generated_when_its_path_is_absent(
    tmp_path: Path,
    grouped_features: dict[str, generator.FeatureSpec],
    setup: str,
) -> None:
    grouped_features["group.nested.second"] = generator.FeatureSpec(
        "second", generate_when_absent=True,
    )
    assert _generate(tmp_path, setup)["ctrace-refs"] == [
        {
            "ref": "group/nested/second", "type": "second",
            "regs": [{"name": "SECOND", "value": 0}],
        },
    ]


@pytest.mark.usefixtures("grouped_features")
@pytest.mark.parametrize("container", ["false", "128", "packet", "[]"])
def test_invalid_group_reports_errors_on_its_feature_paths(
    tmp_path: Path, container: str,
) -> None:
    assert _generate(tmp_path, f"group: {container}")["ctrace-refs"] == [
        {"ref": "group/first", "type": "first", "error": "group must be a mapping"},
        {
            "ref": "group/nested/second", "type": "second",
            "error": "group must be a mapping",
        },
    ]


@pytest.mark.usefixtures("grouped_features")
def test_invalid_nested_group_does_not_prevent_sibling_feature(tmp_path: Path) -> None:
    run = _generate(tmp_path, "group:\n        first: 7\n        nested: false")
    assert run["ctrace-refs"] == [
        {
            "ref": "group/first", "type": "first",
            "regs": [{"name": "FIRST", "value": 7}],
        },
        {
            "ref": "group/nested/second", "type": "second",
            "error": "group.nested must be a mapping",
        },
    ]


def test_grouped_repeated_feature_keeps_list_indices(
    tmp_path: Path, grouped_features: dict[str, generator.FeatureSpec],
) -> None:
    grouped_features["group.first"] = generator.FeatureSpec(
        "first", repeated=True, sequence=True,
    )
    run = _generate(tmp_path, "pname: core\n      group:\n        first: [7, null, 11]")
    assert run["ctrace-refs"] == [
        {
            "ref": "core/group/first#0", "type": "first",
            "regs": [{"name": "FIRST", "value": 7}],
        },
        {
            "ref": "core/group/first#2", "type": "first",
            "regs": [{"name": "FIRST", "value": 11}],
        },
    ]

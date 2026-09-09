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

from typing import Any, cast

import yaml

from pyts.coresight import Processor, generate_ctrace_run


def test_issue_46_accepts_pc_sampling_period_192() -> None:
    """Regression for https://github.com/Open-CMSIS-Pack/pyTS/issues/46."""

    document = yaml.safe_load(
        """\
ctrace:
  setup:
    - pname: CM7
      pcsampling:
        period: 192
"""
    )
    output = generate_ctrace_run(
        document,
        [Processor.from_core("CM4", "CM4"), Processor.from_core("CM7", "CM7")],
    )
    run_node = output.get("ctrace-run")
    assert isinstance(run_node, dict)
    run = cast(dict[str, Any], run_node)

    reported_output = cast(
        list[dict[str, Any]],
        yaml.safe_load(
            """\
  - ctrace-ref: CM7/pcsampling
    type: pcsample
    pname: CM7
    error: 'unsupported pcsampling.period: 192'
"""
        ),
    )
    refs = cast(list[dict[str, Any]], run["ctrace-refs"])

    assert reported_output[0] not in refs
    pcsampling_ref = next(
        ref for ref in refs if ref["ctrace-ref"] == "CM7/pcsampling"
    )
    assert pcsampling_ref == {
        "ctrace-ref": "CM7/pcsampling",
        "type": "pcsample",
        "pname": "CM7",
        "regs": [
            {"name": "DWT_CTRL", "value": 0x1005, "mask": 0x121F},
            {"name": "ITM_TCR", "value": 9, "mask": 9},
        ],
        "stream": 1,
    }

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


def test_issue_45_skips_empty_events_node() -> None:
    """Regression for https://github.com/Open-CMSIS-Pack/pyTS/issues/45."""

    document = yaml.safe_load(
        """\
ctrace:
  created-by: CMSIS Debugger
  setup:
    - pname: CM4
      core: Cortex-M4
      disable:
      timestamps:
        itm-prescaler: 1
      data:
      events:
      itm:
        enable: 0x0
      pcsampling:
        period: 0
      synchronization:
        DWT: 256M
    - pname: CM7
      core: Cortex-M7
      timestamps:
        itm-prescaler: 1
      data:
      events:
      itm:
        enable: 0x0
      pcsampling:
        period: 0
      synchronization:
        DWT: 256M
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
- ctrace-ref: CM7/events
  type: event
  pname: CM7
  error: events entry must contain an event name
"""
        ),
    )
    refs = cast(list[dict[str, Any]], run["ctrace-refs"])

    reported_ref_names = {ref["ctrace-ref"] for ref in reported_output}
    assert all(ref["ctrace-ref"] not in reported_ref_names for ref in refs)

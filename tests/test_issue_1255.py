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


def test_issue_1255_rejects_empty_instructions_node() -> None:
    """Regression for CMSIS Debugger issue 1255.

    https://github.com/Open-CMSIS-Pack/vscode-cmsis-debugger/issues/1255
    """

    document = yaml.safe_load(
        """\
ctrace:
  setup:
    - instructions:
"""
    )
    output = generate_ctrace_run(
        document,
        [Processor.from_core("CM4", None)],
    )
    run_node = output.get("ctrace-run")
    assert isinstance(run_node, dict)
    run = cast(dict[str, Any], run_node)

    assert run["ctrace-refs"] == [
        {
            "ref": "instructions",
            "type": "dwt",
            "error": "instructions trace register generation is not supported",
        }
    ]

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

"""Command line interface for pyTS."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from elftools.common.exceptions import ELFError

from pyts._version import package_version
from pyts.errors import TraceSetupError
from pyts.trace import setup_trace
from pyts.yaml_io import write_yaml_stream


def main(argv: list[str] | None = None) -> int:
    """Run the ``pyts`` command line interface.

    Args:
        argv: Command arguments excluding the program name. ``None`` uses
            ``sys.argv`` through ``argparse``.

    Returns:
        Process-style status code. Successful trace setup returns ``0``.
        Missing symbols, file errors, ELF parsing errors, and validation errors
        are reported on stderr and return ``2``.
    """

    parser = build_parser()
    raw_args = sys.argv[1:] if argv is None else argv

    args = parser.parse_args(raw_args)
    try:
        return _handle_trace_setup(args)
    except FileNotFoundError as exc:
        print(f"pyts: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except ELFError as exc:
        print(f"pyts: invalid ELF file: {exc}", file=sys.stderr)
        return 2
    except TraceSetupError as exc:
        print(f"pyts: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"pyts: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level argument parser for ``pyts``.

    The parser accepts a CMSIS ``*.cbuild-run.yml`` file and trace setup
    options. Callers embedding the CLI can use this function to inspect or
    extend command definitions before parsing.
    """

    parser = argparse.ArgumentParser(
        prog="pyts",
        description="Generate a CMSIS trace run configuration.",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version="%(prog)s " + package_version(),
    )
    parser.add_argument(
        "cbuild_run",
        type=Path,
        help="cbuild-run YAML file to process",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Write the ctrace-run file even if some symbols are unresolved.",
    )
    parser.add_argument(
        "--format",
        choices=("yaml", "json"),
        default="yaml",
        help="Output format",
    )

    return parser


def _handle_trace_setup(args: argparse.Namespace) -> int:
    """Generate a ctrace-run file and print result metadata."""

    result = setup_trace(args.cbuild_run, allow_missing=args.allow_missing)
    _dump(result.to_dict(), sys.stdout, args.format)
    return 0


def _dump(data: Any, stream: TextIO, output_format: str) -> None:
    """Write *data* to *stream* as JSON or normalized YAML."""

    if output_format == "json":
        json.dump(data, stream, indent=2)
        stream.write("\n")
        return
    write_yaml_stream(stream, data, sort_keys=False)

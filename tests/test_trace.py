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

import json
import warnings
from pathlib import Path
from typing import Any, Callable, ClassVar, Sequence, cast

import pytest

from pyts.cli import main
from pyts.coresight import Processor, create_coresight, generate_ctrace_run
from pyts.coresight.model import (
    CoreSight,
    DataAccess,
    DataMatch,
    DataOutput,
    DataTraceRequest,
    DwtVersion,
    normalize_core,
    processor_class,
)
from pyts.coresight.v1 import DwtV1CoreSight
from pyts.coresight.v2 import DwtV2CoreSight
from pyts.elf import MemberInfo, SymbolInfo
from pyts.trace import setup_trace
from pyts.trace import transform_trace_document
from pyts.symbols import SymbolCatalog
from pyts.yaml_io import HexInt, read_yaml, write_yaml


def _write_trace_project(
    tmp_path: Path,
    *,
    target_set: str = "SWO",
    symbols: list[str] | None = None,
    outputs: list[dict[str, str]] | None = None,
    ctrace: dict[str, Any] | None = None,
    processors: list[dict[str, Any]] | None = None,
) -> tuple[Path, Path, str]:
    project = tmp_path / "project"
    out = project / "out"
    cmsis = project / ".cmsis"
    out.mkdir(parents=True)
    cmsis.mkdir()

    target = "NUCLEO-L552ZE-Q"
    target_name = (
        f"{target}@{target_set}"
        if target_set and target_set != "<default>"
        else target
    )
    trace_name = f"Blinky+{target_name}"
    cbuild_run = out / f"Blinky+{target}.cbuild-run.yml"

    output_entries = outputs or [
        {
            "file": "Blinky/NUCLEO-L552ZE-Q/DebugSWO/Blinky.axf",
            "type": "elf",
        }
    ]
    data = [{"symbol": symbol, "access": "w"} for symbol in (symbols or ["main"])]

    cbuild_data: dict[str, Any] = {
        "cbuild-run": {
            "solution": "../Blinky.csolution.yml",
            "target-type": target,
            "output": output_entries,
        }
    }
    if target_set:
        cbuild_data["cbuild-run"]["target-set"] = target_set
    if processors is not None:
        cbuild_data["cbuild-run"]["system-resources"] = {
            "processors": processors
        }

    write_yaml(cbuild_run, cbuild_data)
    write_yaml(cmsis / f"{trace_name}.ctrace.yml", ctrace or {"ctrace": {"data": data}})
    return project, cbuild_run, trace_name


def _main_symbol() -> SymbolInfo:
    return SymbolInfo(
        name="main",
        address=0x08000100,
        size=64,
        type="func",
        binding="global",
        visibility="default",
        section=".text",
        table=".symtab",
    )


def _curr_member() -> MemberInfo:
    return MemberInfo(
        name="osRtxInfo.thread.run.curr",
        address=0x20000028,
        size=4,
        type="pointer",
        base_symbol="osRtxInfo",
        member_path="thread.run.curr",
        offset=0x14,
    )


def _next_member() -> MemberInfo:
    return MemberInfo(
        name="osRtxInfo.thread.run.next",
        address=0x2000002C,
        size=4,
        type="pointer",
        base_symbol="osRtxInfo",
        member_path="thread.run.next",
        offset=0x18,
        source_file="/src/rtx_kernel.c",
    )


def _tick_member() -> MemberInfo:
    return MemberInfo(
        name="osRtxInfo.kernel.tick",
        address=0x20000024,
        size=4,
        type="int",
        base_symbol="osRtxInfo",
        member_path="kernel.tick",
        offset=0x10,
        source_file="/src/rtx_kernel.c",
    )


def _patch_trace_resolver(
    monkeypatch: pytest.MonkeyPatch,
    *,
    resolve_symbols: Callable[..., object] | None = None,
    resolve_object_members_by_address: Callable[..., object] | None = None,
    source_files: Callable[..., object] | None = None,
) -> type[Any]:
    class FakeElfResolver:
        opened_paths: ClassVar[list[Path]] = []

        def __init__(self, path: Path) -> None:
            self.path = Path(path)

        def __enter__(self) -> FakeElfResolver:
            self.opened_paths.append(self.path)
            return self

        def __exit__(self, *exc_info: object) -> None:
            pass

        def resolve_symbols(
            self,
            names: Sequence[str] | None = None,
            *,
            include_undefined: bool = False,
            source_file: str | None = None,
        ) -> list[SymbolInfo | MemberInfo]:
            if resolve_symbols is None:
                return []
            requested = list(names) if names is not None else None
            try:
                symbols = resolve_symbols(
                    self.path,
                    requested,
                    include_undefined,
                    source_file,
                )
            except TypeError:
                try:
                    symbols = resolve_symbols(self.path, requested, include_undefined)
                except TypeError:
                    symbols = resolve_symbols(self.path, requested)
            return cast(
                list[SymbolInfo | MemberInfo],
                symbols,
            )

        def resolve_address(self, address: int) -> SymbolInfo | None:
            for symbol in self.resolve_symbols(None):
                if isinstance(symbol, SymbolInfo) and symbol.address == address:
                    return symbol
            return None

        def resolve_object_members_by_address(
            self,
            members: Sequence[tuple[int, int]],
        ) -> list[MemberInfo]:
            if resolve_object_members_by_address is None:
                return []
            return cast(
                list[MemberInfo],
                resolve_object_members_by_address(self.path, list(members)),
            )

        def source_files(self) -> set[str]:
            if source_files is None:
                raise AttributeError("source_files")
            return cast(set[str], source_files(self.path))

    monkeypatch.setattr("pyts.symbols.ElfResolver", FakeElfResolver)
    return FakeElfResolver


def test_setup_trace_derives_paths_and_enriches_ctrace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, cbuild_run, trace_name = _write_trace_project(
        tmp_path,
        symbols=["main", "osRtxInfo.thread.run.curr"],
    )

    def fake_resolve_symbols(
        path: Path,
        names: list[str],
    ) -> list[SymbolInfo | MemberInfo]:
        assert path == cbuild_run.parent / "Blinky/NUCLEO-L552ZE-Q/DebugSWO/Blinky.axf"
        assert names == ["main", "osRtxInfo.thread.run.curr"]
        return [
            SymbolInfo(
                name="main",
                address=0x08000100,
                size=64,
                type="func",
                binding="global",
                visibility="default",
                section=".text",
                table=".symtab",
            ),
            MemberInfo(
                name="osRtxInfo.thread.run.curr",
                address=0x20000028,
                size=4,
                type="pointer",
                base_symbol="osRtxInfo",
                member_path="thread.run.curr",
                offset=0x14,
            ),
        ]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    result = setup_trace(cbuild_run)

    output = project / ".trace" / f"{trace_name}.ctrace-run.yml"
    assert result.output == str(output)
    assert result.target == "NUCLEO-L552ZE-Q@SWO"
    assert result.symbols == ["main", "osRtxInfo.thread.run.curr"]
    assert result.missing == []
    assert read_yaml(output) == {
        "ctrace": {
            "data": [
                {
                    "symbol": "main",
                    "access": "w",
                    "address": "0x8000100",
                    "size": 64,
                    "type": "func",
                },
                {
                    "symbol": "osRtxInfo.thread.run.curr",
                    "access": "w",
                    "address": "0x20000028",
                    "size": 4,
                    "type": "pointer",
                },
            ]
        }
    }


def test_setup_trace_enriches_spec_location_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "setup": [
                {
                    "data": [
                        {"location": "osRtxInfo.thread.run.curr", "access": "w"},
                        {"location": '"rtx_kernel.c"::osRtxInfo.thread.run.next'},
                        {
                            "location": (
                                'Blinky\u00ad|"rtx_kernel.c"::'
                                "osRtxInfo.kernel.tick"
                            )
                        },
                        {
                            "location": (
                                'Blinky\u00ad.axf|"rtx_kernel.c"::'
                                "osRtxInfo.kernel.tick"
                            )
                        },
                    ]
                }
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    expected_elf = cbuild_run.parent / "Blinky/NUCLEO-L552ZE-Q/DebugSWO/Blinky.axf"
    expected_symbol_file = str(expected_elf.resolve(strict=False))
    calls: list[tuple[list[str], str | None]] = []

    def fake_resolve_symbols(
        path: Path,
        names: list[str],
        include_undefined: bool = False,
        source_file: str | None = None,
    ) -> list[MemberInfo]:
        assert path == expected_elf
        calls.append((list(names), source_file))
        if names == ["osRtxInfo.thread.run.curr"] and source_file is None:
            return [_curr_member()]
        if names == ["osRtxInfo.thread.run.next"] and source_file == "rtx_kernel.c":
            return [_next_member()]
        if names == ["osRtxInfo.kernel.tick"] and source_file == "rtx_kernel.c":
            return [_tick_member()]
        return []

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    result = setup_trace(cbuild_run)

    output = read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml")
    entries = output["ctrace"]["setup"][0]["data"]
    assert result.symbols == [
        "osRtxInfo.thread.run.curr",
        "osRtxInfo.thread.run.next",
        "osRtxInfo.kernel.tick",
        "osRtxInfo.kernel.tick",
    ]
    assert result.missing == []
    assert calls == [
        (["osRtxInfo.thread.run.curr"], None),
        (["osRtxInfo.thread.run.next"], "rtx_kernel.c"),
        (["osRtxInfo.kernel.tick"], "rtx_kernel.c"),
        (["osRtxInfo.kernel.tick"], "rtx_kernel.c"),
    ]
    assert entries == [
        {
            "location": "osRtxInfo.thread.run.curr",
            "access": "w",
            "symbol-file": expected_symbol_file,
            "symbol": "osRtxInfo.thread.run.curr",
            "address": "0x20000028",
            "size": 4,
            "type": "pointer",
        },
        {
            "location": '"rtx_kernel.c"::osRtxInfo.thread.run.next',
            "symbol-file": expected_symbol_file,
            "symbol": "osRtxInfo.thread.run.next",
            "address": "0x2000002c",
            "size": 4,
            "type": "pointer",
        },
        {
            "location": 'Blinky\u00ad|"rtx_kernel.c"::osRtxInfo.kernel.tick',
            "symbol-file": expected_symbol_file,
            "symbol": "osRtxInfo.kernel.tick",
            "address": "0x20000024",
            "size": 4,
            "type": "int",
        },
        {
            "location": 'Blinky\u00ad.axf|"rtx_kernel.c"::osRtxInfo.kernel.tick',
            "symbol-file": expected_symbol_file,
            "symbol": "osRtxInfo.kernel.tick",
            "address": "0x20000024",
            "size": 4,
            "type": "int",
        },
    ]


def test_setup_trace_limits_elf_lookup_to_setup_processor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "setup": [
                {
                    "pname": "CM7",
                    "data": [
                        {"location": "App|shared"},
                        {"symbol": "legacy_shared"},
                    ],
                },
                {
                    "pname": "CM4",
                    "data": [
                        {"location": "App|shared"},
                        {"symbol": "legacy_shared"},
                        {"location": "App|cm7_only"},
                    ],
                },
            ]
        }
    }
    outputs = [
        {
            "file": "App/cm7.axf",
            "type": "elf",
            "project": "App",
            "pname": "CM7",
        },
        {
            "file": "App/cm4.axf",
            "type": "elf",
            "project": "App",
            "pname": "CM4",
        },
    ]
    project, cbuild_run, trace_name = _write_trace_project(
        tmp_path,
        ctrace=ctrace,
        outputs=outputs,
    )
    calls: list[tuple[str, list[str]]] = []

    def fake_resolve_symbols(
        path: Path,
        names: list[str],
    ) -> list[SymbolInfo]:
        core = path.stem
        calls.append((core, list(names)))
        addresses = {
            "cm7": {
                "shared": 0x1000,
                "legacy_shared": 0x1010,
                "cm7_only": 0x1020,
            },
            "cm4": {
                "shared": 0x2000,
                "legacy_shared": 0x2010,
            },
        }[core]
        return [
            SymbolInfo(
                name=name,
                address=addresses[name],
                size=4,
                type="object",
                binding="global",
                visibility="default",
                section=".data",
                table=".symtab",
            )
            for name in names
            if name in addresses
        ]

    fake_resolver = _patch_trace_resolver(
        monkeypatch,
        resolve_symbols=fake_resolve_symbols,
    )

    result = setup_trace(cbuild_run, allow_missing=True)

    output = read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml")
    cm7_data = output["ctrace"]["setup"][0]["data"]
    cm4_data = output["ctrace"]["setup"][1]["data"]
    assert cm7_data[0]["address"] == "0x1000"
    assert cm7_data[1]["address"] == "0x1010"
    assert cm4_data[0]["address"] == "0x2000"
    assert cm4_data[1]["address"] == "0x2010"
    assert cm4_data[2]["error"] == "symbol not found: cm7_only"
    assert cm7_data[0]["symbol-file"].endswith("/App/cm7.axf")
    assert cm4_data[0]["symbol-file"].endswith("/App/cm4.axf")
    assert result.symbols == [
        "shared",
        "legacy_shared",
        "shared",
        "legacy_shared",
    ]
    assert result.missing == ["App|cm7_only"]
    assert fake_resolver.opened_paths == [
        cbuild_run.parent / "App/cm7.axf",
        cbuild_run.parent / "App/cm4.axf",
    ]
    assert ("cm7", ["cm7_only"]) not in calls


def test_setup_trace_generates_coresight_register_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "created-by": "CMSIS-Debugger v1.4.0",
            "setup": [
                {
                    "timestamps": {"itm-prescaler": 4},
                    "data": [{"location": "main", "access": "RW"}],
                    "exceptions": None,
                    "events": [{"event": "CPICNT"}],
                    "itm": {"enable": 0xF, "privileged": 1},
                    "synchronization": [{"DWT": "16M"}],
                }
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(
        tmp_path,
        ctrace=ctrace,
        processors=[{"core": "CM4", "max-clock": 120_000_000}],
    )
    _patch_trace_resolver(
        monkeypatch,
        resolve_symbols=lambda *_args: [_main_symbol()],
    )

    setup_trace(cbuild_run)

    output_path = project / ".trace" / f"{trace_name}.ctrace-run.yml"
    output = read_yaml(output_path)
    run = output["ctrace-run"]
    assert run["created-by"] == "CMSIS-Debugger v1.4.0"
    assert run["setup"][0]["data"][0] == {
        "location": "main",
        "access": "RW",
        "symbol-file": str(
            (
                cbuild_run.parent
                / "Blinky/NUCLEO-L552ZE-Q/DebugSWO/Blinky.axf"
            ).resolve(strict=False)
        ),
        "symbol": "main",
        "address": 0x08000100,
        "size": 64,
        "type": "func",
    }
    refs = output["ctrace-run"]["ctrace-refs"]
    assert output["ctrace-run"]["generated-by"] == "pyTS v0.1.0"
    assert refs[0] == {
        "ctrace-ref": "timestamps",
        "type": "dwt",
        "regs": [{"name": "ITM_TCR", "value": 0x103, "mask": 0x303}],
    }
    assert refs[1]["ctrace-ref"] == "data#0"
    assert refs[1]["type"] == "dwt"
    assert "source" not in refs[1]
    assert refs[1]["symbol-address"] == 0x08000100
    assert refs[1]["regs"] == [
        {"name": "DWT_COMP0", "value": 0x08000100},
        {"name": "DWT_MASK0", "value": 6},
        {"name": "DWT_FUNCTION0", "value": 2},
        {"name": "ITM_TCR", "value": 9, "mask": 9},
    ]
    assert refs[2] == {
        "ctrace-ref": "exceptions",
        "type": "exception",
        "regs": [
            {"name": "DWT_CTRL", "value": 1 << 16, "mask": 1 << 16},
            {"name": "ITM_TCR", "value": 9, "mask": 9},
        ],
    }
    assert refs[3]["regs"][0] == {
        "name": "DWT_CTRL",
        "value": 1 << 17,
        "mask": 1 << 17,
    }
    assert refs[4]["regs"] == [
        {"name": "ITM_TER0", "value": 0xF},
        {"name": "ITM_TPR", "value": 1, "mask": 0xF},
        {"name": "ITM_TCR", "value": 1, "mask": 1},
    ]
    assert refs[5]["regs"] == [
        {"name": "DWT_CTRL", "value": 0, "mask": 0xC00},
        {"name": "ITM_TCR", "value": 5, "mask": 5},
    ]
    output_text = output_path.read_text(encoding="utf-8")
    assert "address: 0x08000100" in output_text
    assert "symbol-address: 0x08000100" in output_text
    assert "value: 0x00000103" in output_text
    assert "mask: 0x00000303" in output_text
    assert "exceptions:\n" in output_text
    assert "exceptions: null" not in output_text


def test_setup_trace_scopes_refs_and_reports_unsupported_core(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "setup": [
                {"pname": "application", "itm": {"enable": 1}},
                {"pname": "network", "exceptions": None},
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(
        tmp_path,
        ctrace=ctrace,
        processors=[
            {"core": "CM33", "max-clock": 160_000_000, "pname": "application"},
            {"core": "CM0PLUS", "max-clock": 32_000_000, "pname": "network"},
        ],
    )
    _patch_trace_resolver(monkeypatch, resolve_symbols=lambda *_args: [])

    setup_trace(cbuild_run)

    output = read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml")
    assert output["ctrace-run"]["ctrace-refs"] == [
        {
            "ctrace-ref": "application/itm",
            "type": "itm",
            "pname": "application",
            "regs": [
                {"name": "ITM_TER0", "value": 1},
                {"name": "ITM_TPR", "value": 0, "mask": 0xF},
                {"name": "ITM_TCR", "value": 1, "mask": 1},
            ],
        },
        {
            "ctrace-ref": "network/exceptions",
            "type": "exception",
            "pname": "network",
            "error": "core CM0PLUS has no architectural ITM/DWT trace support",
        },
    ]


@pytest.mark.parametrize(
    ("literal", "display", "version"),
    [
        ("MC1", "STAR-MC1", DwtVersion.V2),
        ("MC3", "STAR-MC3", DwtVersion.V2),
        ("SC000", "SecurCore SC000", None),
        ("SC300", "SecurCore SC300", DwtVersion.V1),
        ("CM0", "Cortex-M0", None),
        ("CM0+", "Cortex-M0+", None),
        ("CM1", "Cortex-M1", None),
        ("CM23", "Cortex-M23", DwtVersion.V2),
        ("CM3", "Cortex-M3", DwtVersion.V1),
        ("CM33", "Cortex-M33", DwtVersion.V2),
        ("CM35P", "Cortex-M35P", DwtVersion.V2),
        ("CM52", "Cortex-M52", DwtVersion.V2),
        ("CM55", "Cortex-M55", DwtVersion.V2),
        ("CM85", "Cortex-M85", DwtVersion.V2),
        ("CM4", "Cortex-M4", DwtVersion.V1),
        ("CM7", "Cortex-M7", DwtVersion.V1),
        ("ARMV8MBL", "ARMV8MBL", None),
        ("ARMV8MML", "ARMV8MML", None),
        ("ARMV81MML", "ARMV81MML", None),
    ],
)
def test_core_metadata_uses_normalized_device_literals(
    literal: str,
    display: str,
    version: DwtVersion | None,
) -> None:
    assert normalize_core(literal.lower()) == literal
    assert normalize_core(display.swapcase()) == literal
    assert processor_class(literal) == display
    assert Processor.from_core(literal, None).dwt_version == version


@pytest.mark.parametrize(
    ("core", "literal"),
    [
        ("STAR-MC3", "MC3"),
        ("star-mc3", "MC3"),
        ("MC3", "MC3"),
        ("Cortex-M0+", "CM0+"),
        ("Cortex-M0plus", "CM0+"),
        ("cOrTeX-M0pLuS", "CM0+"),
        ("CM0+", "CM0+"),
        ("CM0PLUS", "CM0+"),
    ],
)
def test_core_aliases_resolve_case_insensitively(
    core: str,
    literal: str,
) -> None:
    assert normalize_core(core) == literal


def test_generate_ctrace_run_uses_dwtv2_comparator_model() -> None:
    ctrace: dict[str, Any] = {
        "ctrace": {
            "setup": [
                {
                    "data": [
                        {
                            "location": "counter",
                            "address": "0x20000000",
                            "size": 4,
                            "access": "W",
                        }
                    ]
                }
            ]
        }
    }

    output = cast(
        dict[str, Any],
        generate_ctrace_run(
            ctrace,
            [Processor(core="CM33", pname=None, dwt_version=2)],
        ),
    )

    assert output["ctrace-run"]["ctrace-refs"][0]["regs"] == [
        {"name": "DWT_COMP0", "value": 0x20000000},
        {"name": "DWT_FUNCTION0", "value": 0x82D},
        {"name": "ITM_TCR", "value": 9, "mask": 9},
    ]


@pytest.mark.parametrize("cyctap", [64, 1024])
@pytest.mark.parametrize("postpreset", range(1, 17))
def test_generate_ctrace_run_encodes_pc_sampling_period_literals(
    cyctap: int,
    postpreset: int,
) -> None:
    output = cast(
        dict[str, Any],
        generate_ctrace_run(
            {
                "ctrace": {
                    "setup": [
                        {"pcsampling": {"period": f"{cyctap}*{postpreset}"}}
                    ]
                }
            },
            [Processor.from_core("CM4", None)],
        ),
    )

    cyctap_bit = 0 if cyctap == 64 else 1
    expected_ctrl = (
        (1 << 12)
        | (cyctap_bit << 9)
        | ((postpreset - 1) << 1)
        | 1
    )
    assert output["ctrace-run"]["ctrace-refs"][0]["regs"] == [
        {"name": "DWT_CTRL", "value": expected_ctrl, "mask": 0x121F},
        {"name": "ITM_TCR", "value": 9, "mask": 9},
    ]


@pytest.mark.parametrize(
    "period",
    [
        0,
        64,
        True,
        None,
        "64*0",
        "64*17",
        "1024*0",
        "1024*17",
        "128*1",
        "64 * 1",
    ],
)
def test_generate_ctrace_run_rejects_invalid_pc_sampling_period_literals(
    period: Any,
) -> None:
    output = cast(
        dict[str, Any],
        generate_ctrace_run(
            {"ctrace": {"setup": [{"pcsampling": {"period": period}}]}},
            [Processor.from_core("CM4", None)],
        ),
    )

    ref = output["ctrace-run"]["ctrace-refs"][0]
    assert "error" in ref
    assert "regs" not in ref


@pytest.mark.parametrize("pcsampling", [None, {}])
def test_generate_ctrace_run_disables_pc_sampling_without_a_period(
    pcsampling: Any,
) -> None:
    output = cast(
        dict[str, Any],
        generate_ctrace_run(
            {"ctrace": {"setup": [{"pcsampling": pcsampling}]}},
            [Processor.from_core("CM4", None)],
        ),
    )

    assert output["ctrace-run"]["ctrace-refs"][0]["regs"] == [
        {"name": "DWT_CTRL", "value": 0, "mask": 1 << 12}
    ]


@pytest.mark.parametrize(
    ("dwt", "encoding"),
    [("16M", 0), ("64M", 1), ("256M", 2)],
)
def test_generate_ctrace_run_encodes_dwt_synchronization_literals(
    dwt: str,
    encoding: int,
) -> None:
    output = cast(
        dict[str, Any],
        generate_ctrace_run(
            {"ctrace": {"setup": [{"synchronization": [{"DWT": dwt}]}]}},
            [Processor.from_core("CM4", None)],
        ),
    )

    assert output["ctrace-run"]["ctrace-refs"][0]["regs"] == [
        {"name": "DWT_CTRL", "value": encoding << 10, "mask": 0xC00},
        {"name": "ITM_TCR", "value": 5, "mask": 5},
    ]


def test_generate_ctrace_run_disables_dwt_synchronization_with_zero() -> None:
    output = cast(
        dict[str, Any],
        generate_ctrace_run(
            {"ctrace": {"setup": [{"synchronization": [{"DWT": 0}]}]}},
            [Processor.from_core("CM4", None)],
        ),
    )

    assert output["ctrace-run"]["ctrace-refs"][0]["regs"] == [
        {"name": "ITM_TCR", "value": 0, "mask": 1 << 2}
    ]


@pytest.mark.parametrize(
    "entry",
    [
        {},
        {"period": "DWT\\16M"},
        {"DWT": 1},
        {"DWT": 0.0},
        {"DWT": False},
        {"DWT": None},
        {"DWT": "0"},
        {"DWT": "16m"},
        {"DWT": "32M"},
    ],
)
def test_generate_ctrace_run_rejects_invalid_dwt_synchronization_literals(
    entry: dict[str, Any],
) -> None:
    output = cast(
        dict[str, Any],
        generate_ctrace_run(
            {"ctrace": {"setup": [{"synchronization": [entry]}]}},
            [Processor.from_core("CM4", None)],
        ),
    )

    ref = output["ctrace-run"]["ctrace-refs"][0]
    assert "error" in ref
    assert "regs" not in ref


def _generate_data_refs(
    entries: list[dict[str, Any]],
    processor: Processor,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    output = cast(
        dict[str, Any],
        generate_ctrace_run(
            cast(Any, {"ctrace": {"setup": [{"data": entries}]}}),
            [processor],
        ),
    )
    return output, cast(
        list[dict[str, Any]],
        output["ctrace-run"]["ctrace-refs"],
    )


@pytest.mark.parametrize(
    ("core", "display"),
    [("star-mc1", "STAR-MC1"), ("STAR-MC3", "STAR-MC3")],
)
def test_star_cores_support_dwtv2_data_trace(
    core: str,
    display: str,
) -> None:
    processor = Processor.from_core(core, None)
    assert processor.dwt_version == DwtVersion.V2

    _output, refs = _generate_data_refs(
        [
            {"location": "value", "address": 0x20000000},
            {
                "location": "address",
                "address": 0x20000004,
                "size": 1,
                "output": "address",
            },
        ],
        processor,
    )

    assert refs[0]["regs"][0] == {"name": "DWT_COMP0", "value": 0x20000000}
    assert refs[1]["error"] == (
        f"{display} DWT-Unit data.output 'address' cannot emit an address "
        "for a one-byte range"
    )


@pytest.mark.parametrize(
    ("output_mode", "access", "expected_function"),
    [
        ("value", "R", 0xC),
        ("value", "W", 0xD),
        ("value", "RW", 0x2),
        ("address", "R", 0x2C),
        ("address", "W", 0x2D),
        ("address", "RW", 0x21),
        ("PC", "RW", 0x1),
        ("PC+value", "R", 0xE),
        ("PC+value", "W", 0xF),
        ("PC+value", "RW", 0x3),
        ("address+value", "R", 0x2E),
        ("address+value", "W", 0x2F),
        ("address+value", "RW", 0x22),
    ],
)
def test_generate_ctrace_run_supports_dwtv1_output_modes(
    output_mode: str,
    access: str,
    expected_function: int,
) -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "counter",
                "address": 0x20000000,
                "size": 4,
                "access": access,
                "output": output_mode,
            }
        ],
        Processor(core="CM4", pname=None, dwt_version=1),
    )

    assert refs[0]["regs"][2] == {
        "name": "DWT_FUNCTION0",
        "value": expected_function,
    }
    assert "source" not in refs[0]


@pytest.mark.parametrize(
    ("output_mode", "access", "base_function"),
    [
        ("value", "R", 0xC),
        ("value", "W", 0xD),
        ("value", "RW", 0x2),
        ("address", "R", 0x2C),
        ("address", "W", 0x2D),
        ("address", "RW", 0x21),
        ("PC", "RW", 0x1),
        ("PC+value", "R", 0xE),
        ("PC+value", "W", 0xF),
        ("PC+value", "RW", 0x3),
        ("address+value", "R", 0x2E),
        ("address+value", "W", 0x2F),
        ("address+value", "RW", 0x22),
    ],
)
def test_generate_ctrace_run_supports_dwtv1_linked_match_outputs(
    output_mode: str,
    access: str,
    base_function: int,
) -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "counter",
                "address": 0x20000000,
                "size": 4,
                "access": access,
                "output": output_mode,
                "match": {"value": 0x12345678, "size": 4},
            }
        ],
        Processor(core="CM4", pname=None, dwt_version=1),
    )

    assert refs[0]["regs"] == [
        {"name": "DWT_COMP0", "value": 0x20000000},
        {"name": "DWT_MASK0", "value": 2},
        {"name": "DWT_FUNCTION0", "value": 0},
        {"name": "DWT_COMP1", "value": 0x12345678},
        {"name": "DWT_FUNCTION1", "value": 0x900 | base_function},
        {"name": "ITM_TCR", "value": 9, "mask": 9},
    ]


@pytest.mark.parametrize(
    ("match_size", "match_value", "match_function"),
    [
        (1, 0x7F, 0x10D),
        (2, 0x1234, 0x50D),
        (4, 0x12345678, 0x90D),
    ],
)
def test_dwtv1_linked_match_keeps_range_and_match_sizes_independent(
    match_size: int,
    match_value: int,
    match_function: int,
) -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "range",
                "address": 0x20000000,
                "size": 8,
                "match": {"value": match_value, "size": match_size},
            }
        ],
        Processor(core="CM4", pname=None, dwt_version=1),
    )

    assert refs[0]["regs"][1] == {"name": "DWT_MASK0", "value": 3}
    assert refs[0]["regs"][3] == {"name": "DWT_COMP1", "value": match_value}
    assert refs[0]["regs"][4] == {
        "name": "DWT_FUNCTION1",
        "value": match_function,
    }


@pytest.mark.parametrize(
    ("output_mode", "access", "expected_function"),
    [
        ("value", "R", 0x82E),
        ("value", "W", 0x82D),
        ("value", "RW", 0x82C),
        ("PC", "R", 0x836),
        ("PC", "W", 0x835),
        ("PC", "RW", 0x834),
        ("match", "R", 0x826),
        ("match", "W", 0x825),
        ("match", "RW", 0x824),
        ("PC+value", "R", 0x83E),
        ("PC+value", "W", 0x83D),
        ("PC+value", "RW", 0x83C),
    ],
)
def test_generate_ctrace_run_supports_dwtv2_single_comparator_outputs(
    output_mode: str,
    access: str,
    expected_function: int,
) -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "counter",
                "address": 0x20000000,
                "size": 4,
                "access": access,
                "output": output_mode,
            }
        ],
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert "source" not in refs[0]
    assert refs[0]["regs"] == [
        {"name": "DWT_COMP0", "value": 0x20000000},
        {"name": "DWT_FUNCTION0", "value": expected_function},
        {"name": "ITM_TCR", "value": 9, "mask": 9},
    ]


@pytest.mark.parametrize(
    ("output_mode", "lower_function", "limit_function"),
    [
        ("value", 0x2C, 0x07),
        ("address", 0x04, 0x37),
        ("PC", 0x34, 0x07),
        ("match", 0x24, 0x07),
        ("PC+value", 0x3C, 0x07),
        ("address+value", 0x2C, 0x37),
        ("PC+address", 0x34, 0x37),
    ],
)
def test_generate_ctrace_run_supports_dwtv2_range_outputs(
    output_mode: str,
    lower_function: int,
    limit_function: int,
) -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "buffer",
                "address": 0x20000000,
                "size": 8,
                "access": "RW",
                "output": output_mode,
            }
        ],
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert refs[0]["regs"] == [
        {"name": "DWT_COMP0", "value": 0x20000000},
        {"name": "DWT_FUNCTION0", "value": lower_function},
        {"name": "DWT_COMP1", "value": 0x20000007},
        {"name": "DWT_FUNCTION1", "value": limit_function},
        {"name": "ITM_TCR", "value": 9, "mask": 9},
    ]


@pytest.mark.parametrize(
    ("access", "match_size", "match_value", "address_function", "value_function", "stored_value"),
    [
        ("R", 1, 0x7F, 0x026, 0x02B, 0x7F7F7F7F),
        ("W", 2, 0x1234, 0x425, 0x42B, 0x12341234),
        ("RW", 4, 0x12345678, 0x824, 0x82B, 0x12345678),
    ],
)
def test_generate_ctrace_run_supports_dwtv2_linked_value_match(
    access: str,
    match_size: int,
    match_value: int,
    address_function: int,
    value_function: int,
    stored_value: int,
) -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "counter",
                "address": 0x20000000,
                "size": match_size,
                "access": access,
                "output": "match",
                "match": {"value": match_value, "size": match_size},
            }
        ],
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert refs[0]["regs"] == [
        {"name": "DWT_COMP0", "value": 0x20000000},
        {"name": "DWT_FUNCTION0", "value": address_function},
        {"name": "DWT_COMP1", "value": stored_value},
        {"name": "DWT_FUNCTION1", "value": value_function},
        {"name": "ITM_TCR", "value": 9, "mask": 9},
    ]
    assert "source" not in refs[0]


@pytest.mark.parametrize(
    ("output_mode", "address_function"),
    [
        ("value", 0x82D),
        ("address", 0x805),
        ("PC", 0x835),
        ("match", 0x825),
        ("PC+value", 0x83D),
        ("address+value", 0x82D),
        ("PC+address", 0x835),
    ],
)
def test_generate_ctrace_run_applies_output_to_linked_address_comparator(
    output_mode: str,
    address_function: int,
) -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "counter",
                "address": 0x20000000,
                "size": 4,
                "access": "W",
                "output": output_mode,
                "match": {"value": 1, "size": 4},
            }
        ],
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert refs[0]["regs"][1] == {
        "name": "DWT_FUNCTION0",
        "value": address_function,
    }
    assert refs[0]["regs"][3] == {
        "name": "DWT_FUNCTION1",
        "value": 0x82B,
    }


def test_generate_ctrace_run_defaults_data_match_size_to_word() -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "counter",
                "address": 0x20000000,
                "size": 4,
                "match": {"value": 0x12345678},
            }
        ],
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert refs[0]["regs"][1] == {"name": "DWT_FUNCTION0", "value": 0x82D}
    assert refs[0]["regs"][3] == {"name": "DWT_FUNCTION1", "value": 0x82B}


def test_generate_ctrace_run_uses_range_for_arbitrary_or_unaligned_size() -> None:
    _output, refs = _generate_data_refs(
        [
            {"location": "three", "address": 0x20000000, "size": 3},
            {"location": "unaligned", "address": 0x20000005, "size": 4},
        ],
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert [ref["regs"][2]["value"] for ref in refs] == [0x20000002, 0x20000008]
    assert refs[0]["regs"][0]["name"] == "DWT_COMP0"
    assert refs[1]["regs"][0]["name"] == "DWT_COMP2"


def test_generate_ctrace_run_allocates_mixed_data_comparators() -> None:
    _output, refs = _generate_data_refs(
        [
            {"location": "first", "address": 0x20000010, "size": 4},
            {
                "location": "range",
                "address": 0x20000020,
                "size": 8,
                "output": "address",
            },
            {"location": "last", "address": 0x20000030, "size": 4, "output": "PC"},
        ],
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert [ref["regs"][0]["name"] for ref in refs] == [
        "DWT_COMP0",
        "DWT_COMP1",
        "DWT_COMP3",
    ]
    assert refs[1]["regs"][2]["name"] == "DWT_COMP2"
    assert all("source" not in ref for ref in refs)


def test_generate_ctrace_run_allocates_comparators_per_processor() -> None:
    ctrace = cast(
        Any,
        {
            "ctrace": {
                "setup": [
                    {
                        "pname": "application",
                        "data": [
                            {
                                "location": "app_counter",
                                "address": 0x20000000,
                                "output": "match",
                                "match": {"value": 1},
                            }
                        ],
                    },
                    {
                        "pname": "network",
                        "data": [
                            {
                                "location": "net_counter",
                                "address": 0x30000000,
                                "output": "match",
                                "match": {"value": 2},
                            }
                        ],
                    },
                ]
            }
        },
    )

    output = cast(
        dict[str, Any],
        generate_ctrace_run(
            ctrace,
            [
                Processor(core="CM33", pname="application", dwt_version=2),
                Processor(core="CM33", pname="network", dwt_version=2),
            ],
        ),
    )
    refs = output["ctrace-run"]["ctrace-refs"]

    assert [ref["regs"][0]["name"] for ref in refs] == ["DWT_COMP0", "DWT_COMP0"]
    assert [ref["regs"][2]["name"] for ref in refs] == ["DWT_COMP1", "DWT_COMP1"]
    assert all("source" not in ref for ref in refs)
    assert [ref["pname"] for ref in refs] == ["application", "network"]


def test_dwtv1_reserves_match_pair_per_processor() -> None:
    ctrace = cast(
        Any,
        {
            "ctrace": {
                "setup": [
                    {
                        "pname": "application",
                        "data": [
                            {
                                "location": "app_counter",
                                "address": 0x20000000,
                                "match": {"value": 1},
                            }
                        ],
                    },
                    {
                        "pname": "network",
                        "data": [
                            {
                                "location": "net_counter",
                                "address": 0x30000000,
                                "match": {"value": 2},
                            }
                        ],
                    },
                ]
            }
        },
    )

    output = cast(
        dict[str, Any],
        generate_ctrace_run(
            ctrace,
            [
                Processor(core="CM4", pname="application", dwt_version=1),
                Processor(core="CM4", pname="network", dwt_version=1),
            ],
        ),
    )
    refs = output["ctrace-run"]["ctrace-refs"]

    assert [ref["regs"][0]["name"] for ref in refs] == [
        "DWT_COMP0",
        "DWT_COMP0",
    ]
    assert [ref["regs"][3]["name"] for ref in refs] == [
        "DWT_COMP1",
        "DWT_COMP1",
    ]


def test_dwtv1_uses_one_portable_match_pair_without_consuming_later_indices() -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "first",
                "address": 0x20000000,
                "match": {"value": 1},
            },
            {
                "location": "second",
                "address": 0x20000004,
                "match": {"value": 2},
            },
            {"location": "plain", "address": 0x20000008},
        ],
        Processor(core="CM4", pname=None, dwt_version=1),
    )

    assert refs[0]["regs"][0]["name"] == "DWT_COMP0"
    assert refs[0]["regs"][3]["name"] == "DWT_COMP1"
    assert refs[1]["error"] == (
        "Cortex-M4 DWT-Unit supports only one portable data.match using "
        "comparators 0 and 1"
    )
    assert "regs" not in refs[1]
    assert refs[2]["regs"][0]["name"] == "DWT_COMP2"


def test_dwtv1_reserves_match_pair_independently_of_request_order() -> None:
    _output, refs = _generate_data_refs(
        [
            {"location": "plain", "address": 0x20000008},
            {
                "location": "matched",
                "address": 0x20000000,
                "match": {"value": 1},
            },
        ],
        Processor(core="CM4", pname=None, dwt_version=1),
    )

    assert refs[0]["regs"][0]["name"] == "DWT_COMP2"
    assert refs[1]["regs"][0]["name"] == "DWT_COMP0"
    assert refs[1]["regs"][3]["name"] == "DWT_COMP1"


def test_invalid_dwtv1_matches_do_not_consume_reserved_pair() -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "invalid",
                "address": 0x20000000,
                "size": 3,
                "match": {"value": 1},
            },
            {
                "location": "unaligned",
                "address": 0x20000002,
                "size": 4,
                "match": {"value": 2},
            },
            {
                "location": "valid",
                "address": 0x20000004,
                "match": {"value": 3},
            },
            {"location": "plain", "address": 0x20000008},
        ],
        Processor(core="CM4", pname=None, dwt_version=1),
    )

    assert "must be a power of two" in refs[0]["error"]
    assert "must be aligned" in refs[1]["error"]
    assert refs[2]["regs"][0]["name"] == "DWT_COMP0"
    assert refs[2]["regs"][3]["name"] == "DWT_COMP1"
    assert refs[3]["regs"][0]["name"] == "DWT_COMP2"


def test_malformed_dwtv1_match_does_not_reserve_pair() -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "invalid",
                "address": 0x20000000,
                "match": {"value": True},
            },
            {"location": "plain", "address": 0x20000004},
        ],
        Processor(core="CM4", pname=None, dwt_version=1),
    )

    assert refs[0]["error"] == "data.match.value must be an integer"
    assert refs[1]["regs"][0]["name"] == "DWT_COMP0"


def test_direct_dwtv1_match_requires_pair_before_plain_allocation() -> None:
    coresight = create_coresight(
        Processor(core="CM4", pname=None, dwt_version=1)
    )
    assert isinstance(coresight, DwtV1CoreSight)

    first = coresight.encode_data(
        DataTraceRequest(
            address=0x20000000,
            size=4,
            access=DataAccess.WRITE,
            output=DataOutput.VALUE,
        )
    )
    with pytest.raises(ValueError, match="requires comparators 0 and 1"):
        coresight.encode_data(
            DataTraceRequest(
                address=0x20000004,
                size=4,
                access=DataAccess.WRITE,
                output=DataOutput.VALUE,
                match=DataMatch(value=1, size=4),
            )
        )
    second = coresight.encode_data(
        DataTraceRequest(
            address=0x20000008,
            size=4,
            access=DataAccess.WRITE,
            output=DataOutput.VALUE,
        )
    )

    assert first[0]["name"] == "DWT_COMP0"
    assert second[0]["name"] == "DWT_COMP1"


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        ({"output": "PC", "access": "R"}, "does not support access R"),
        ({"output": "PC", "access": "W"}, "does not support access W"),
        ({"output": "match"}, "does not support data.output 'match'"),
        ({"output": "PC+address"}, "does not support data.output 'PC+address'"),
    ],
)
def test_generate_ctrace_run_rejects_unsupported_dwtv1_outputs(
    entry: dict[str, Any],
    error: str,
) -> None:
    _output, refs = _generate_data_refs(
        [{"location": "counter", "address": 0x20000000, **entry}],
        Processor(core="CM4", pname=None, dwt_version=1),
    )

    assert error in refs[0]["error"]
    assert "regs" not in refs[0]


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        ({"size": 3}, "must be a power of two"),
        ({"address": 0x20000002, "size": 4}, "must be aligned"),
        ({"output": "pc"}, "unsupported data.output value"),
    ],
)
def test_generate_ctrace_run_validates_dwtv1_data_configuration(
    entry: dict[str, Any],
    error: str,
) -> None:
    data = {"location": "counter", "address": 0x20000000, **entry}
    _output, refs = _generate_data_refs(
        [data],
        Processor(core="CM4", pname=None, dwt_version=1),
    )

    assert error in refs[0]["error"]
    assert "regs" not in refs[0]


def test_dwtv1_error_names_the_processor_class() -> None:
    _output, refs = _generate_data_refs(
        [{"location": "counter", "address": 0x20000000, "size": 3}],
        Processor(core="CM7", pname=None, dwt_version=1),
    )

    assert refs[0]["error"] == (
        "Cortex-M7 DWT-Unit data.size must be a power of two"
    )


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        ({"output": "address", "size": 1}, "cannot emit an address"),
        (
            {"output": "match", "size": 4, "match": {"value": 1, "size": 2}},
            "data.size must equal data.match.size",
        ),
        (
            {
                "output": "match",
                "address": 0x20000001,
                "size": 2,
                "match": {"value": 1, "size": 2},
            },
            "match address must be aligned",
        ),
        ({"address": 0xFFFFFFFE, "size": 4}, "range exceeds"),
    ],
)
def test_generate_ctrace_run_rejects_unrepresentable_dwtv2_data(
    entry: dict[str, Any],
    error: str,
) -> None:
    data = {"location": "counter", "address": 0x20000000, **entry}
    _output, refs = _generate_data_refs(
        [data],
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert error in refs[0]["error"]
    assert "regs" not in refs[0]


def test_dwtv2_error_names_the_processor_class() -> None:
    _output, refs = _generate_data_refs(
        [
            {
                "location": "counter",
                "address": 0x20000000,
                "size": 1,
                "output": "address",
            }
        ],
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert refs[0]["error"] == (
        "Cortex-M33 DWT-Unit data.output 'address' cannot emit an address "
        "for a one-byte range"
    )


def test_generate_ctrace_run_rejects_cortex_m23_data_trace() -> None:
    _output, refs = _generate_data_refs(
        [{"location": "counter", "address": 0x20000000}],
        Processor(core="Cortex-M23", pname=None, dwt_version=2),
    )

    assert refs[0]["error"] == (
        "Cortex-M23 DWT-Unit does not support data trace packets"
    )
    assert "regs" not in refs[0]


def test_generate_ctrace_run_enforces_dwtv2_value_comparator_position() -> None:
    entries = [
        {
            "location": f"match_{index}",
            "address": 0x20000000 + index * 4,
            "output": "match",
        }
        for index in range(4)
    ]
    entries.extend(
        [
            {"location": "value", "address": 0x20000010},
            {"location": "pc", "address": 0x20000014, "output": "PC"},
        ]
    )

    _output, refs = _generate_data_refs(
        entries,
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert "index 0 through 3" in refs[4]["error"]
    assert "regs" not in refs[4]
    assert refs[5]["regs"][0]["name"] == "DWT_COMP4"


def test_linked_value_output_enforces_comparator_position_without_allocation() -> None:
    entries: list[dict[str, Any]] = [
        {
            "location": f"match_{index}",
            "address": 0x20000000 + index * 4,
            "output": "match",
        }
        for index in range(4)
    ]
    entries.extend(
        [
            {
                "location": "linked",
                "address": 0x20000010,
                "match": {"value": 1},
            },
            {"location": "pc", "address": 0x20000014, "output": "PC"},
        ]
    )

    _output, refs = _generate_data_refs(
        entries,
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert "index 0 through 3" in refs[4]["error"]
    assert "regs" not in refs[4]
    assert refs[5]["regs"][0]["name"] == "DWT_COMP4"


def test_invalid_coresight_request_does_not_consume_comparators() -> None:
    coresight = create_coresight(
        Processor(core="CM33", pname=None, dwt_version=2)
    )
    assert coresight is not None

    with pytest.raises(ValueError, match="cannot emit an address"):
        coresight.encode_data(
            DataTraceRequest(
                address=0x20000000,
                size=1,
                access=DataAccess.WRITE,
                output=DataOutput.ADDRESS,
            )
        )

    assert coresight.comparators.next_index == 0
    registers = coresight.encode_data(
        DataTraceRequest(
            address=0x20000000,
            size=4,
            access=DataAccess.WRITE,
            output=DataOutput.VALUE,
        )
    )
    assert registers[0]["name"] == "DWT_COMP0"


@pytest.mark.parametrize(
    ("match", "error"),
    [
        (None, "data.match must be a mapping"),
        ({}, "data.match.value is required"),
        ({"value": True}, "data.match.value must be an integer"),
        ({"value": 1.0}, "data.match.value must be an integer"),
        ({"value": -1}, "data.match.value does not fit data.match.size"),
        ({"value": 0x100, "size": 1}, "data.match.value does not fit data.match.size"),
        ({"value": 1, "size": 3}, "data.match.size must be 1, 2, or 4"),
        ({"value": 1, "size": True}, "data.match.size must be an integer"),
        ({"value": 1, "size": 1.0}, "data.match.size must be an integer"),
    ],
)
def test_generate_ctrace_run_reports_invalid_data_match(
    match: Any,
    error: str,
) -> None:
    output, refs = _generate_data_refs(
        [
            {
                "location": "counter",
                "address": 0x20000000,
                "match": match,
            }
        ],
        Processor(core="CM33", pname=None, dwt_version=2),
    )

    assert refs[0]["error"] == error
    assert "source" not in refs[0]
    assert "regs" not in refs[0]
    assert output["ctrace-run"]["setup"][0]["data"][0]["match"] == match


def test_generate_ctrace_run_serializes_match_registers_as_hex(tmp_path: Path) -> None:
    output, _refs = _generate_data_refs(
        [
            {
                "location": "counter",
                "address": 0x20000000,
                "size": 2,
                "output": "match",
                "match": {"value": HexInt(0x1234), "size": 2},
            }
        ],
        Processor(core="CM33", pname=None, dwt_version=2),
    )
    path = tmp_path / "match.ctrace-run.yml"

    write_yaml(path, output)

    text = path.read_text(encoding="utf-8")
    assert "    value: 0x00001234" in text
    assert "value: 0x12341234" in text
    assert "value: 0x0000042b" in text


def test_setup_trace_reports_missing_location(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {"ctrace": {"setup": [{"data": [{"location": "missing"}]}]}}
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)

    def fake_resolve_symbols(
        path: Path,
        names: list[str],
        include_undefined: bool = False,
        source_file: str | None = None,
    ) -> list[SymbolInfo]:
        return []

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    with pytest.raises(ValueError, match="missing symbols: missing"):
        setup_trace(cbuild_run)

    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "setup": [
                {
                    "data": [
                        {
                            "location": "missing",
                            "error": "symbol not found: missing",
                        }
                    ]
                }
            ]
        }
    }


def test_setup_trace_reports_source_file_location_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "setup": [
                {
                    "data": [
                        {"location": '"missing.c"::main'},
                        {"location": '"rtx_kernel.c"::missing'},
                    ]
                }
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)

    def fake_resolve_symbols(
        path: Path,
        names: list[str],
        include_undefined: bool = False,
        source_file: str | None = None,
    ) -> list[SymbolInfo]:
        return []

    def fake_source_files(path: Path) -> set[str]:
        return {"/src/rtx_kernel.c"}

    _patch_trace_resolver(
        monkeypatch,
        resolve_symbols=fake_resolve_symbols,
        source_files=fake_source_files,
    )

    with pytest.raises(
        ValueError,
        match='missing symbols: "missing.c"::main, "rtx_kernel.c"::missing',
    ):
        setup_trace(cbuild_run)

    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "setup": [
                {
                    "data": [
                        {
                            "location": '"missing.c"::main',
                            "error": "source file not found: missing.c",
                        },
                        {
                            "location": '"rtx_kernel.c"::missing',
                            "error": (
                                "symbol not found in source file "
                                "'rtx_kernel.c': missing"
                            ),
                        },
                    ]
                }
            ]
        }
    }


def test_setup_trace_reports_unresolved_project_and_file_qualifiers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "setup": [
                {
                    "data": [
                        {"location": "OtherProject|main"},
                        {"location": "Other.axf|main"},
                    ]
                }
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    _patch_trace_resolver(monkeypatch, resolve_symbols=lambda *_: [_main_symbol()])

    with pytest.raises(
        ValueError,
        match="missing symbols: OtherProject\\|main, Other.axf\\|main",
    ):
        setup_trace(cbuild_run)

    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "setup": [
                {
                    "data": [
                        {
                            "location": "OtherProject|main",
                            "error": (
                                "project 'OtherProject' does not resolve to an "
                                "existing ELF file"
                            ),
                        },
                        {
                            "location": "Other.axf|main",
                            "error": (
                                "ELF file qualifier 'Other.axf' does not resolve to "
                                "an existing ELF file"
                            ),
                        },
                    ]
                }
            ]
        }
    }


def test_setup_trace_reports_missing_elf_file_on_location(
    tmp_path: Path,
) -> None:
    ctrace = {"ctrace": {"setup": [{"data": [{"location": "Blinky|main"}]}]}}
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    missing_elf = (
        cbuild_run.parent / "Blinky/NUCLEO-L552ZE-Q/DebugSWO/Blinky.axf"
    ).resolve(strict=False)

    with pytest.raises(ValueError, match="missing symbols: Blinky\\|main"):
        setup_trace(cbuild_run)

    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "setup": [
                {
                    "data": [
                        {
                            "location": "Blinky|main",
                            "error": f"ELF file does not exist: {missing_elf}",
                        }
                    ]
                }
            ]
        }
    }


def test_setup_trace_leaves_ambiguous_location_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {"ctrace": {"setup": [{"data": [{"location": "main"}]}]}}
    project, cbuild_run, trace_name = _write_trace_project(
        tmp_path,
        outputs=[
            {"file": "first.axf", "type": "elf"},
            {"file": "second.axf", "type": "elf"},
        ],
        ctrace=ctrace,
    )

    def fake_resolve_symbols(
        path: Path,
        names: list[str],
        include_undefined: bool = False,
        source_file: str | None = None,
    ) -> list[SymbolInfo]:
        return [_main_symbol()]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    with pytest.warns(UserWarning, match="matches multiple symbols"):
        with pytest.raises(ValueError, match="missing symbols: main"):
            setup_trace(cbuild_run)

    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "setup": [
                {
                    "data": [
                        {
                            "location": "main",
                            "error": "location matches multiple symbols: main",
                        }
                    ]
                }
            ]
        }
    }


def test_setup_trace_enriches_numeric_location_from_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {"ctrace": {"setup": [{"data": [{"location": "0x8000100"}]}]}}
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    expected_elf = cbuild_run.parent / "Blinky/NUCLEO-L552ZE-Q/DebugSWO/Blinky.axf"

    def fake_resolve_symbols(
        path: Path,
        names: list[str] | None = None,
        include_undefined: bool = False,
        source_file: str | None = None,
    ) -> list[SymbolInfo]:
        return [_main_symbol()] if names is None else []

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    result = setup_trace(cbuild_run)

    assert result.symbols == ["main"]
    output_path = project / ".trace" / f"{trace_name}.ctrace-run.yml"
    assert read_yaml(output_path) == {
        "ctrace": {
            "setup": [
                {
                    "data": [
                        {
                            "location": 0x08000100,
                            "symbol-file": str(expected_elf.resolve(strict=False)),
                            "symbol": "main",
                            "address": 0x08000100,
                            "size": 64,
                            "type": "func",
                        }
                    ]
                }
            ]
        }
    }
    output_text = output_path.read_text(encoding="utf-8")
    assert "location: 0x08000100" in output_text
    assert "address: 0x08000100" in output_text


@pytest.mark.parametrize("location", ["0x20001000", 0x20001000])
def test_setup_trace_accepts_anonymous_fixed_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str | int,
) -> None:
    ctrace = {
        "ctrace": {
            "setup": [
                {
                    "pname": "CM4",
                    "data": [{"location": location, "size": 4}],
                }
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(
        tmp_path,
        ctrace=ctrace,
        outputs=[
            {
                "file": "Blinky/CM4/Blinky.axf",
                "type": "elf",
                "pname": "CM4",
            }
        ],
        processors=[{"core": "CM4", "pname": "CM4"}],
    )
    _patch_trace_resolver(monkeypatch, resolve_symbols=lambda *_args: [])

    result = setup_trace(cbuild_run)

    output_path = project / ".trace" / f"{trace_name}.ctrace-run.yml"
    output = read_yaml(output_path)
    entry = output["ctrace-run"]["setup"][0]["data"][0]
    assert entry == {
        "location": 0x20001000,
        "size": 4,
        "address": 0x20001000,
    }
    assert result.symbols == []
    assert result.missing == []
    ref = output["ctrace-run"]["ctrace-refs"][0]
    assert "error" not in ref
    assert ref["symbol-address"] == 0x20001000
    assert ref["regs"][0] == {"name": "DWT_COMP0", "value": 0x20001000}
    output_text = output_path.read_text(encoding="utf-8")
    assert "location: 0x20001000" in output_text
    assert "address: 0x20001000" in output_text


@pytest.mark.parametrize(
    "lookup_failure",
    ["no processor candidate", "missing ELF", "ambiguous symbols"],
)
def test_setup_trace_ignores_fixed_address_lookup_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lookup_failure: str,
) -> None:
    ctrace = {
        "ctrace": {
            "setup": [
                {"pname": "CM4", "data": [{"location": 0x20001000}]}
            ]
        }
    }
    output_pname = "CM7" if lookup_failure == "no processor candidate" else "CM4"
    outputs = [
        {"file": "first.axf", "type": "elf", "pname": output_pname}
    ]
    if lookup_failure == "ambiguous symbols":
        outputs.append(
            {"file": "second.axf", "type": "elf", "pname": "CM4"}
        )
    project, cbuild_run, trace_name = _write_trace_project(
        tmp_path,
        ctrace=ctrace,
        outputs=outputs,
    )
    if lookup_failure != "missing ELF":
        fixed_symbol = SymbolInfo(
            name="fixed",
            address=0x20001000,
            size=4,
            type="object",
            binding="global",
            visibility="default",
            section=".data",
            table=".symtab",
        )
        _patch_trace_resolver(
            monkeypatch,
            resolve_symbols=lambda *_args: [fixed_symbol],
        )

    result = setup_trace(cbuild_run)

    output = read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml")
    entry = output["ctrace"]["setup"][0]["data"][0]
    assert entry == {"location": 0x20001000, "address": 0x20001000}
    assert result.symbols == []
    assert result.missing == []


def test_setup_trace_preserves_consistent_manual_properties_without_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "data": [
                {
                    "symbol": "main",
                    "access": "w",
                    "address": "0x8000100",
                    "size": 64,
                    "type": "func",
                }
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)

    def fake_resolve_symbols(path: Path, names: list[str]) -> list[SymbolInfo]:
        return [_main_symbol()]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        setup_trace(cbuild_run)

    assert caught == []
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == ctrace


def test_setup_trace_enriches_missing_properties_without_overwriting_existing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "data": [
                {
                    "symbol": "main",
                    "access": "w",
                    "address": "0x8000100",
                }
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)

    def fake_resolve_symbols(path: Path, names: list[str]) -> list[SymbolInfo]:
        return [_main_symbol()]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    setup_trace(cbuild_run)

    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "data": [
                {
                    "symbol": "main",
                    "access": "w",
                    "address": "0x8000100",
                    "size": 64,
                    "type": "func",
                }
            ]
        }
    }


def test_setup_trace_preserves_inconsistent_manual_properties_and_warns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "data": [
                {
                    "symbol": "main",
                    "access": "w",
                    "address": "0xdeadbeef",
                    "size": "64",
                    "type": "object",
                }
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)

    def fake_resolve_symbols(path: Path, names: list[str]) -> list[SymbolInfo]:
        return [_main_symbol()]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    with pytest.warns(UserWarning) as caught:
        setup_trace(cbuild_run)

    messages = [str(item.message) for item in caught]
    assert len(messages) == 3
    assert any(
        "symbol 'main'" in message
        and "'address'" in message
        and "'0xdeadbeef'" in message
        and "'0x8000100'" in message
        and "keeping existing value" in message
        for message in messages
    )
    assert any(
        "symbol 'main'" in message
        and "'size'" in message
        and "'64'" in message
        and "64" in message
        and "keeping existing value" in message
        for message in messages
    )
    assert any(
        "symbol 'main'" in message
        and "'type'" in message
        and "'object'" in message
        and "'func'" in message
        and "keeping existing value" in message
        for message in messages
    )
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == ctrace


def test_setup_trace_accepts_manual_integer_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "data": [
                {
                    "symbol": "main",
                    "access": "w",
                    "address": 0x08000100,
                    "size": 64,
                    "type": "func",
                }
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)

    def fake_resolve_symbols(path: Path, names: list[str]) -> list[SymbolInfo]:
        return [_main_symbol()]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        setup_trace(cbuild_run)

    assert caught == []
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == ctrace


def test_setup_trace_resolves_symbol_metadata_from_manual_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {"ctrace": {"data": [{"address": "0x8000100", "access": "w"}]}}
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    calls: list[tuple[Path, list[str] | None]] = []

    def fake_resolve_symbols(
        path: Path,
        names: list[str] | None = None,
    ) -> list[SymbolInfo]:
        calls.append((path, names))
        assert path == cbuild_run.parent / "Blinky/NUCLEO-L552ZE-Q/DebugSWO/Blinky.axf"
        assert names is None
        return [_main_symbol()]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    result = setup_trace(cbuild_run)

    assert calls == [
        (cbuild_run.parent / "Blinky/NUCLEO-L552ZE-Q/DebugSWO/Blinky.axf", None)
    ]
    assert result.symbols == ["main"]
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "data": [
                {
                    "address": "0x8000100",
                    "access": "w",
                    "symbol": "main",
                    "size": 64,
                    "type": "func",
                }
            ]
        }
    }


def test_setup_trace_resolves_symbol_metadata_from_manual_integer_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {"ctrace": {"data": [{"address": 0x08000100, "access": "w"}]}}
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)

    def fake_resolve_symbols(
        path: Path,
        names: list[str] | None = None,
    ) -> list[SymbolInfo]:
        return [_main_symbol()]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    setup_trace(cbuild_run)

    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "data": [
                {
                    "address": 0x08000100,
                    "access": "w",
                    "symbol": "main",
                    "size": 64,
                    "type": "func",
                }
            ]
        }
    }


def test_setup_trace_preserves_address_entry_properties_and_warns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "data": [
                {
                    "address": "0x8000100",
                    "access": "w",
                    "symbol": "",
                    "size": 4,
                    "type": "object",
                }
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)

    def fake_resolve_symbols(
        path: Path,
        names: list[str] | None = None,
    ) -> list[SymbolInfo]:
        return [_main_symbol()]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    with pytest.warns(UserWarning) as caught:
        setup_trace(cbuild_run)

    messages = [str(item.message) for item in caught]
    assert len(messages) == 3
    assert any(
        "address 0x8000100" in message and "'symbol'" in message
        for message in messages
    )
    assert any(
        "address 0x8000100" in message and "'size'" in message
        for message in messages
    )
    assert any(
        "address 0x8000100" in message and "'type'" in message
        for message in messages
    )
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == ctrace


def test_setup_trace_leaves_unresolved_manual_address_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {"ctrace": {"data": [{"address": "0xdeadbeef", "access": "w"}]}}
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)

    def fake_resolve_symbols(
        path: Path,
        names: list[str] | None = None,
    ) -> list[SymbolInfo]:
        return [_main_symbol()]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    result = setup_trace(cbuild_run)

    assert result.symbols == []
    assert result.missing == []
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == ctrace


def test_setup_trace_resolves_dwarf_member_from_manual_address_and_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {"ctrace": {"data": [{"address": "0x20000028", "size": 4}]}}
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    member_calls: list[tuple[Path, list[tuple[int, int]]]] = []

    def fake_resolve_object_members_by_address(
        path: Path,
        members: list[tuple[int, int]],
    ) -> list[MemberInfo]:
        member_calls.append((path, list(members)))
        return [_curr_member()]

    def fake_resolve_symbols(
        path: Path,
        names: list[str] | None = None,
    ) -> list[SymbolInfo]:
        return []

    _patch_trace_resolver(
        monkeypatch,
        resolve_symbols=fake_resolve_symbols,
        resolve_object_members_by_address=fake_resolve_object_members_by_address,
    )

    result = setup_trace(cbuild_run)

    assert member_calls == [
        (
            cbuild_run.parent / "Blinky/NUCLEO-L552ZE-Q/DebugSWO/Blinky.axf",
            [(0x20000028, 4)],
        )
    ]
    assert result.symbols == ["osRtxInfo.thread.run.curr"]
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "data": [
                {
                    "address": "0x20000028",
                    "size": 4,
                    "symbol": "osRtxInfo.thread.run.curr",
                    "type": "pointer",
                }
            ]
        }
    }


def test_setup_trace_opens_each_elf_once_for_all_lookup_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "data": [
                {"symbol": "main"},
                {"address": "0x8000100"},
                {"address": "0x20000028", "size": 4},
            ]
        }
    }
    project, cbuild_run, _trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    expected_elf = cbuild_run.parent / "Blinky/NUCLEO-L552ZE-Q/DebugSWO/Blinky.axf"

    def fake_resolve_symbols(
        path: Path,
        names: list[str] | None = None,
    ) -> list[SymbolInfo]:
        assert path == expected_elf
        if names is None or "main" in names:
            return [_main_symbol()]
        return []

    def fake_resolve_object_members_by_address(
        path: Path,
        members: list[tuple[int, int]],
    ) -> list[MemberInfo]:
        assert path == expected_elf
        assert members == [(0x20000028, 4)]
        return [_curr_member()]

    fake_resolver = _patch_trace_resolver(
        monkeypatch,
        resolve_symbols=fake_resolve_symbols,
        resolve_object_members_by_address=fake_resolve_object_members_by_address,
    )

    result = setup_trace(cbuild_run)

    assert fake_resolver.opened_paths == [expected_elf]
    assert result.symbols == ["main", "main", "osRtxInfo.thread.run.curr"]
    assert (project / ".trace").exists()


def test_setup_trace_prefers_dwarf_member_over_symbol_for_sized_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {"ctrace": {"data": [{"address": "0x20000028", "size": 4}]}}
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    base_symbol = SymbolInfo(
        name="osRtxInfo",
        address=0x20000028,
        size=164,
        type="object",
        binding="global",
        visibility="default",
        section=".data",
        table=".symtab",
    )

    def fake_resolve_symbols(
        path: Path,
        names: list[str] | None = None,
    ) -> list[SymbolInfo]:
        return [base_symbol]

    _patch_trace_resolver(
        monkeypatch,
        resolve_symbols=fake_resolve_symbols,
        resolve_object_members_by_address=lambda *_: [_curr_member()],
    )

    result = setup_trace(cbuild_run)

    assert result.symbols == ["osRtxInfo.thread.run.curr"]
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "data": [
                {
                    "address": "0x20000028",
                    "size": 4,
                    "symbol": "osRtxInfo.thread.run.curr",
                    "type": "pointer",
                }
            ]
        }
    }


def test_setup_trace_falls_back_to_symbol_for_missing_or_non_integer_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "data": [
                {"address": "0x8000100"},
                {"address": "0x8000100", "size": "64"},
            ]
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    member_calls: list[list[tuple[int, int]]] = []

    def fake_resolve_object_members_by_address(
        path: Path,
        members: list[tuple[int, int]],
    ) -> list[MemberInfo]:
        member_calls.append(list(members))
        return [_curr_member()]

    def fake_resolve_symbols(
        path: Path,
        names: list[str] | None = None,
    ) -> list[SymbolInfo]:
        return [_main_symbol()]

    _patch_trace_resolver(
        monkeypatch,
        resolve_symbols=fake_resolve_symbols,
        resolve_object_members_by_address=fake_resolve_object_members_by_address,
    )

    with pytest.warns(UserWarning, match="'size'"):
        result = setup_trace(cbuild_run)

    assert member_calls == []
    assert result.symbols == ["main", "main"]
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "data": [
                {
                    "address": "0x8000100",
                    "symbol": "main",
                    "size": 64,
                    "type": "func",
                },
                {
                    "address": "0x8000100",
                    "size": "64",
                    "symbol": "main",
                    "type": "func",
                },
            ]
        }
    }


def test_setup_trace_leaves_ambiguous_dwarf_member_address_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {"ctrace": {"data": [{"address": "0x20000028", "size": 4}]}}
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    duplicate = MemberInfo(
        name="duplicateInfo.thread.run.curr",
        address=0x20000028,
        size=4,
        type="pointer",
        base_symbol="duplicateInfo",
        member_path="thread.run.curr",
        offset=0x14,
    )

    def fake_resolve_symbols(
        path: Path,
        names: list[str] | None = None,
    ) -> list[SymbolInfo]:
        return [_main_symbol()]

    _patch_trace_resolver(
        monkeypatch,
        resolve_symbols=fake_resolve_symbols,
        resolve_object_members_by_address=lambda *_: [_curr_member(), duplicate],
    )

    with pytest.warns(UserWarning, match="matches multiple DWARF object members"):
        result = setup_trace(cbuild_run)

    assert result.symbols == []
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == ctrace


def test_setup_trace_resolves_symbol_keys_anywhere_in_yaml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "data": [{"symbol": "main", "access": "w"}],
            "events": [
                {"watch": {"symbol": "osRtxInfo.thread.run.curr", "access": "r"}},
                {"groups": [[{"symbol": "main", "label": "duplicate"}]]},
                {"ignored": {"symbol": ""}},
                {"also_ignored": {"symbol": 123}},
            ],
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    calls: list[list[str]] = []

    def fake_resolve_symbols(
        path: Path,
        names: list[str],
    ) -> list[SymbolInfo | MemberInfo]:
        calls.append(list(names))
        return [
            SymbolInfo(
                name="main",
                address=0x08000100,
                size=64,
                type="func",
                binding="global",
                visibility="default",
                section=".text",
                table=".symtab",
            ),
            MemberInfo(
                name="osRtxInfo.thread.run.curr",
                address=0x20000028,
                size=4,
                type="pointer",
                base_symbol="osRtxInfo",
                member_path="thread.run.curr",
                offset=0x14,
            ),
        ]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    result = setup_trace(cbuild_run)

    assert calls == [["main", "osRtxInfo.thread.run.curr"]]
    assert result.symbols == ["main", "osRtxInfo.thread.run.curr", "main"]
    output = read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml")
    assert output["ctrace"]["data"][0] == {
        "symbol": "main",
        "access": "w",
        "address": "0x8000100",
        "size": 64,
        "type": "func",
    }
    assert output["ctrace"]["events"][0]["watch"] == {
        "symbol": "osRtxInfo.thread.run.curr",
        "access": "r",
        "address": "0x20000028",
        "size": 4,
        "type": "pointer",
    }
    assert output["ctrace"]["events"][1]["groups"][0][0] == {
        "symbol": "main",
        "label": "duplicate",
        "address": "0x8000100",
        "size": 64,
        "type": "func",
    }
    assert output["ctrace"]["events"][2]["ignored"] == {"symbol": ""}
    assert output["ctrace"]["events"][3]["also_ignored"] == {"symbol": 123}


@pytest.mark.parametrize("target_set", ["", "<default>"])
def test_setup_trace_supports_target_type_without_explicit_target_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_set: str,
) -> None:
    project, cbuild_run, trace_name = _write_trace_project(
        tmp_path,
        target_set=target_set,
    )

    def fake_resolve_symbols(path: Path, names: list[str]) -> list[SymbolInfo]:
        return []

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    with pytest.raises(ValueError, match="missing symbols: main"):
        setup_trace(cbuild_run)

    assert trace_name == "Blinky+NUCLEO-L552ZE-Q"
    assert not (project / ".trace" / f"{trace_name}.ctrace-run.yml").exists()


def test_setup_trace_uses_first_elf_that_resolves_symbol(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, cbuild_run, trace_name = _write_trace_project(
        tmp_path,
        symbols=["counter"],
        outputs=[
            {"file": "first.axf", "type": "elf"},
            {"file": "second.axf", "type": "elf"},
        ],
    )
    calls: list[tuple[str, list[str]]] = []

    def fake_resolve_symbols(
        path: Path,
        names: list[str],
    ) -> list[SymbolInfo]:
        calls.append((Path(path).name, list(names)))
        if Path(path).name == "second.axf":
            return [
                SymbolInfo(
                    name="counter",
                    address=0x20000000,
                    size=4,
                    type="object",
                    binding="global",
                    visibility="default",
                    section=".data",
                    table=".symtab",
                )
            ]
        return []

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    setup_trace(cbuild_run)

    assert calls == [("first.axf", ["counter"]), ("second.axf", ["counter"])]
    output = read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml")
    assert output["ctrace"]["data"][0]["address"] == "0x20000000"


def test_setup_trace_allow_missing_writes_unresolved_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "data": [{"symbol": "main", "access": "w"}],
            "events": [{"watch": {"symbol": "missing", "access": "r"}}],
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)

    def fake_resolve_symbols(path: Path, names: list[str]) -> list[SymbolInfo]:
        return []

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    result = setup_trace(cbuild_run, allow_missing=True)

    assert result.missing == ["main", "missing"]
    assert read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml") == {
        "ctrace": {
            "data": [{"symbol": "main", "access": "w"}],
            "events": [{"watch": {"symbol": "missing", "access": "r"}}],
        }
    }


def test_setup_trace_resolves_mixed_location_and_legacy_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "setup": [{"data": [{"location": "main"}]}],
            "data": [{"symbol": "counter"}],
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    counter = SymbolInfo(
        name="counter",
        address=0x20000000,
        size=4,
        type="object",
        binding="global",
        visibility="default",
        section=".data",
        table=".symtab",
    )

    def fake_resolve_symbols(path: Path, names: list[str]) -> list[SymbolInfo]:
        available = {"main": _main_symbol(), "counter": counter}
        return [available[name] for name in names if name in available]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)

    result = setup_trace(cbuild_run)

    output = read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml")
    assert result.symbols == ["main", "counter"]
    assert output["ctrace"]["setup"][0]["data"][0]["symbol"] == "main"
    assert output["ctrace"]["data"][0]["address"] == "0x20000000"


def test_setup_trace_writes_annotated_mixed_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrace = {
        "ctrace": {
            "setup": [{"data": [{"location": "missing_location"}]}],
            "data": [{"symbol": "missing_legacy"}],
        }
    }
    project, cbuild_run, trace_name = _write_trace_project(tmp_path, ctrace=ctrace)
    _patch_trace_resolver(monkeypatch, resolve_symbols=lambda *_: [])

    with pytest.raises(
        ValueError,
        match="missing symbols: missing_location, missing_legacy",
    ):
        setup_trace(cbuild_run)

    output = read_yaml(project / ".trace" / f"{trace_name}.ctrace-run.yml")
    assert output["ctrace"]["setup"][0]["data"][0]["error"] == (
        "symbol not found: missing_location"
    )
    assert output["ctrace"]["data"][0]["error"] == (
        "symbol not found: missing_legacy"
    )


def test_trace_transformation_does_not_mutate_source_document() -> None:
    source: dict[str, Any] = {"ctrace": {"data": [{"symbol": "main"}]}}
    original = json.loads(json.dumps(source))

    class FakeCatalog:
        def resolve_names(
            self,
            names: list[str],
        ) -> dict[str, SymbolInfo | MemberInfo]:
            return {"main": _main_symbol()} if "main" in names else {}

        def resolve_members_by_address(
            self,
            _members: list[tuple[int, int]],
        ) -> tuple[dict[tuple[int, int], MemberInfo], set[tuple[int, int]]]:
            return {}, set()

        def resolve_addresses(
            self,
            _addresses: list[int],
        ) -> dict[int, SymbolInfo | MemberInfo]:
            return {}

    result = transform_trace_document(
        cast(Any, source),
        cast(SymbolCatalog, FakeCatalog()),
    )

    assert source == original
    assert result.document is not source
    output = cast(dict[str, Any], result.document)
    assert output["ctrace"]["data"][0]["address"] == "0x8000100"


def test_setup_trace_requires_elf_outputs(tmp_path: Path) -> None:
    project, cbuild_run, trace_name = _write_trace_project(
        tmp_path,
        outputs=[{"file": "Blinky.hex", "type": "hex"}],
    )

    with pytest.raises(ValueError, match="at least one ELF file"):
        setup_trace(cbuild_run)

    assert not (project / ".trace" / f"{trace_name}.ctrace-run.yml").exists()


def test_trace_setup_cli_outputs_json_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _project, cbuild_run, _trace_name = _write_trace_project(tmp_path)

    def fake_setup_trace(path: Path, allow_missing: bool = False) -> Any:
        result = setup_trace(path, allow_missing=allow_missing)
        return result

    def fake_resolve_symbols(path: Path, names: list[str]) -> list[SymbolInfo]:
        return [
            SymbolInfo(
                name="main",
                address=0x08000100,
                size=64,
                type="func",
                binding="global",
                visibility="default",
                section=".text",
                table=".symtab",
            )
        ]

    _patch_trace_resolver(monkeypatch, resolve_symbols=fake_resolve_symbols)
    monkeypatch.setattr("pyts.cli.setup_trace", fake_setup_trace)

    assert main([str(cbuild_run), "--format", "json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["target"] == "NUCLEO-L552ZE-Q@SWO"
    assert payload["symbols"] == ["main"]
    assert payload["missing"] == []
    assert Path(payload["output"]).exists()


def test_trace_setup_cli_reports_missing_symbols(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_setup_trace(path: Path, allow_missing: bool = False) -> Any:
        raise ValueError("missing symbols: osRtxInfo.thread.run.curr")

    monkeypatch.setattr("pyts.cli.setup_trace", fake_setup_trace)

    assert main(["Blinky.cbuild-run.yml"]) == 2

    captured = capsys.readouterr()
    assert "missing symbols: osRtxInfo.thread.run.curr" in captured.err


def test_create_coresight_returns_version_specific_implementation() -> None:
    version_1 = create_coresight(Processor(core="CM4", pname=None, dwt_version=1))
    version_2 = create_coresight(Processor(core="CM33", pname=None, dwt_version=2))

    assert isinstance(version_1, CoreSight)
    assert isinstance(version_1, DwtV1CoreSight)
    assert isinstance(version_2, CoreSight)
    assert isinstance(version_2, DwtV2CoreSight)


def test_create_coresight_returns_none_for_unsupported_processor() -> None:
    processor = Processor(core="CA53", pname=None, dwt_version=None)

    assert create_coresight(processor) is None

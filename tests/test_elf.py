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

from collections.abc import Callable, Iterator
from collections import UserDict
from pathlib import Path
import shutil
import subprocess
from typing import Any, cast

import pytest

from pyts.elf import (
    ElfResolver,
    MemberInfo,
    SymbolInfo,
    missing_symbols,
)
from pyts.elf.dwarf_members import (
    canonical_dwarf_type,
    die_symbol_type,
    dwarf_type_name,
    dwarf_type_size,
    resolve_die_address,
)

ResolverFactory = Callable[[Any], ElfResolver]


@pytest.fixture
def resolver_factory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> ResolverFactory:
    pending: list[Any] = []
    created = 0

    def fake_elf_file(_stream: Any) -> Any:
        return pending.pop(0)

    monkeypatch.setattr("pyts.elf.resolver.ELFFile", fake_elf_file)

    def create(elf_file: Any) -> ElfResolver:
        nonlocal created
        path = tmp_path / f"fake-{created}.elf"
        created += 1
        path.write_bytes(b"")
        pending.append(elf_file)
        return ElfResolver(path)

    return create


def resolve_symbols_from_elf(
    resolver_factory: ResolverFactory,
    elf_file: Any,
    names: list[str],
    *,
    source_file: str | None = None,
) -> list[SymbolInfo | MemberInfo]:
    return resolver_factory(elf_file).resolve_symbols(
        names,
        source_file=source_file,
    )


def resolve_object_members_from_elf(
    resolver_factory: ResolverFactory,
    elf_file: Any,
    names: list[str],
    *,
    source_file: str | None = None,
) -> list[MemberInfo]:
    return cast(
        list[MemberInfo],
        resolver_factory(elf_file).resolve_symbols(
            names,
            source_file=source_file,
        ),
    )


def resolve_object_members_by_address_from_elf(
    resolver_factory: ResolverFactory,
    elf_file: Any,
    members: list[tuple[int, int]],
) -> list[MemberInfo]:
    return resolver_factory(elf_file).resolve_object_members_by_address(members)


class FakeSection:
    def __init__(self, name: str, symbols: list[FakeSymbol] | None = None) -> None:
        self.name = name
        self._symbols = symbols or []

    def iter_symbols(self) -> Iterator[FakeSymbol]:
        return iter(self._symbols)


class FakeSymbolTable(FakeSection):
    pass


class FakeSymbol:
    def __init__(self, name: str, entry: dict[str, Any]) -> None:
        self.name = name
        self.entry = entry


class FakeAttr:
    def __init__(self, value: Any) -> None:
        self.value = value


class FakeDie:
    def __init__(
        self,
        tag: str,
        name: str = "",
        type_die: FakeDie | None = None,
        attrs: dict[str, FakeAttr] | None = None,
        children: list[FakeDie] | None = None,
    ) -> None:
        self.tag = tag
        self.type_die = type_die
        self.attributes = attrs.copy() if attrs else {}
        if name:
            self.attributes["DW_AT_name"] = FakeAttr(name.encode())
        if type_die is not None:
            self.attributes["DW_AT_type"] = FakeAttr(0)
        self._children = children or []

    def get_DIE_from_attribute(self, name: str) -> FakeDie | None:
        if name != "DW_AT_type":
            raise KeyError(name)
        return self.type_die

    def iter_children(self) -> Iterator[FakeDie]:
        return iter(self._children)


class FakeCU:
    def __init__(
        self,
        dies: list[FakeDie],
        *,
        comp_dir: str = "/src",
    ) -> None:
        self.dies = dies
        self.structs = object()
        self.header = {"address_size": 4}
        self._top_die = FakeDie(
            "DW_TAG_compile_unit",
            attrs={"DW_AT_comp_dir": FakeAttr(comp_dir.encode())},
        )

    def iter_DIEs(self) -> Iterator[FakeDie]:
        return iter(self.dies)

    def get_top_DIE(self) -> FakeDie:
        return self._top_die


class FakeDwarfInfo:
    def __init__(self, cus: list[FakeCU], address: int = 0x20000014) -> None:
        self.cus = cus
        self._address = address

    def iter_CUs(self) -> Iterator[FakeCU]:
        return iter(self.cus)

    def get_addr(self, cu: FakeCU, address_index: int) -> int:
        assert address_index == 1
        return self._address

    def line_program_for_CU(self, cu: FakeCU) -> FakeLineProgram:
        return FakeLineProgram()


@pytest.mark.parametrize(
    ("source_name", "encoding", "expected"),
    [
        ("int", 0x05, "signed"),
        ("i32", "DW_ATE_signed", "signed"),
        ("unsigned int", 0x07, "unsigned"),
        ("u32", "DW_ATE_unsigned", "unsigned"),
        ("bool", 0x02, "bool"),
        ("float", 0x04, "float"),
        ("char32_t", 0x10, "char"),
    ],
)
def test_canonical_dwarf_base_types_ignore_language_spelling(
    source_name: str,
    encoding: int | str,
    expected: str,
) -> None:
    die = FakeDie(
        "DW_TAG_base_type",
        source_name,
        attrs={"DW_AT_encoding": FakeAttr(encoding)},
    )

    type_info = canonical_dwarf_type(die)

    assert type_info.name == expected
    assert type_info.source_name == source_name


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("DW_TAG_pointer_type", "pointer"),
        ("DW_TAG_reference_type", "reference"),
        ("DW_TAG_array_type", "array"),
        ("DW_TAG_enumeration_type", "enum"),
        ("DW_TAG_structure_type", "struct"),
        ("DW_TAG_class_type", "class"),
        ("DW_TAG_union_type", "union"),
        ("DW_TAG_subroutine_type", "function"),
        ("DW_TAG_string_type", "string"),
    ],
)
def test_canonical_dwarf_types_use_structural_tags(
    tag: str,
    expected: str,
) -> None:
    assert canonical_dwarf_type(FakeDie(tag)).name == expected


def test_canonical_dwarf_type_unwraps_qualifiers_and_preserves_typedef() -> None:
    base_type = FakeDie(
        "DW_TAG_base_type",
        "unsigned int",
        attrs={"DW_AT_encoding": FakeAttr(0x07)},
    )
    typedef = FakeDie("DW_TAG_typedef", "uint32_t", type_die=base_type)
    qualified = FakeDie("DW_TAG_const_type", type_die=typedef)

    type_info = canonical_dwarf_type(qualified)

    assert type_info.name == "unsigned"
    assert type_info.source_name == "uint32_t"


def test_unknown_dwarf_encoding_does_not_leak_source_type_name() -> None:
    die = FakeDie(
        "DW_TAG_base_type",
        "vendor_specific_number",
        attrs={"DW_AT_encoding": FakeAttr(0x80)},
    )

    type_info = canonical_dwarf_type(die)

    assert type_info.name == ""
    assert type_info.source_name == "vendor_specific_number"


def test_missing_dwarf_type_information_remains_undefined() -> None:
    missing_type = canonical_dwarf_type(None)
    dangling_wrapper = FakeDie("DW_TAG_const_type")
    wrapped_type = canonical_dwarf_type(dangling_wrapper)

    assert missing_type.name == ""
    assert missing_type.source_name is None
    assert wrapped_type.name == ""
    assert wrapped_type.source_name is None
    assert dwarf_type_size(FakeCU([]), dangling_wrapper) == 0


def test_base_type_without_encoding_remains_undefined() -> None:
    die = FakeDie("DW_TAG_base_type", "implementation-defined")

    assert dwarf_type_name(die) == ""


def test_dwarf_subprogram_has_generic_function_type() -> None:
    assert die_symbol_type(FakeDie("DW_TAG_subprogram", "main")) == "function"


class FakeLineProgram:
    def __init__(self) -> None:
        self.header = {
            "file_entry": [
                {
                    "name": b"rtx_kernel.c",
                    "dir_index": 0,
                }
            ],
            "include_directory": [],
        }


class FakeDwarfELF:
    def __init__(
        self,
        dwarf_info: FakeDwarfInfo,
        sections: list[FakeSection] | None = None,
    ) -> None:
        self._dwarf_info = dwarf_info
        self.sections = sections or []

    def has_dwarf_info(self) -> bool:
        return True

    def get_dwarf_info(self) -> FakeDwarfInfo:
        return self._dwarf_info

    def iter_sections(self) -> Iterator[FakeSection]:
        return iter(self.sections)

    def get_section(self, n: int) -> FakeSection:
        return self.sections[n]


class FakeDwarfExprParser:
    def __init__(self, structs: object) -> None:
        pass

    def parse_expr(self, expression: object) -> list[FakeOp]:
        return [FakeOp("DW_OP_addrx", [1])]


class FakeOp:
    def __init__(self, op_name: str, args: list[int]) -> None:
        self.op_name = op_name
        self.args = args


class ConfiguredDwarfExprParser:
    operation = FakeOp("DW_OP_addr", [0x08000101])

    def __init__(self, structs: object) -> None:
        pass

    def parse_expr(self, expression: object) -> list[FakeOp]:
        return [self.operation]


def test_normalizes_odd_low_pc_for_thumb_subprogram() -> None:
    die = FakeDie(
        "DW_TAG_subprogram",
        attrs={"DW_AT_low_pc": FakeAttr(0x08000101)},
    )

    assert resolve_die_address(FakeDwarfInfo([]), FakeCU([]), die) == 0x08000100


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        (FakeOp("DW_OP_addr", [0x08000101]), 0x08000100),
        (FakeOp("DW_OP_addrx", [1]), 0x20000014),
    ],
)
def test_normalizes_odd_dwarf_expression_address_for_thumb_subprogram(
    monkeypatch: pytest.MonkeyPatch,
    operation: FakeOp,
    expected: int,
) -> None:
    ConfiguredDwarfExprParser.operation = operation
    monkeypatch.setattr(
        "pyts.elf.dwarf_members.DWARFExprParser",
        ConfiguredDwarfExprParser,
    )
    die = FakeDie("DW_TAG_subprogram", attrs={"DW_AT_location": FakeAttr([0])})

    assert (
        resolve_die_address(
            FakeDwarfInfo([], address=0x20000015),
            FakeCU([]),
            die,
        )
        == expected
    )


def test_preserves_odd_dwarf_address_for_data_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ConfiguredDwarfExprParser.operation = FakeOp("DW_OP_addr", [0x20000029])
    monkeypatch.setattr(
        "pyts.elf.dwarf_members.DWARFExprParser",
        ConfiguredDwarfExprParser,
    )
    die = FakeDie("DW_TAG_variable", attrs={"DW_AT_location": FakeAttr([0])})

    assert resolve_die_address(FakeDwarfInfo([]), FakeCU([]), die) == 0x20000029


class FakeELF:
    def __init__(self) -> None:
        self.sections = [
            FakeSection(""),
            FakeSection(".text"),
            FakeSection(".data"),
            FakeSymbolTable(
                ".symtab",
                [
                    FakeSymbol(
                        "main",
                        {
                            "st_value": 0x08000101,
                            "st_size": 64,
                            "st_info": {"type": "STT_FUNC", "bind": "STB_GLOBAL"},
                            "st_other": {"visibility": "STV_DEFAULT"},
                            "st_shndx": 1,
                        },
                    ),
                    FakeSymbol(
                        "counter",
                        {
                            "st_value": 0x20000000,
                            "st_size": 4,
                            "st_info": {"type": "STT_OBJECT", "bind": "STB_LOCAL"},
                            "st_other": {"visibility": "STV_DEFAULT"},
                            "st_shndx": 2,
                        },
                    ),
                ],
            ),
        ]

    def iter_sections(self) -> Iterator[FakeSection]:
        return iter(self.sections)

    def get_section(self, n: int) -> FakeSection:
        return self.sections[n]


class CountingFakeELF(FakeELF):
    def __init__(self) -> None:
        super().__init__()
        self.iter_sections_count = 0

    def iter_sections(self) -> Iterator[FakeSection]:
        self.iter_sections_count += 1
        return super().iter_sections()


class CountingDwarfInfo(FakeDwarfInfo):
    def __init__(self, cus: list[FakeCU], address: int = 0x20000014) -> None:
        super().__init__(cus, address)
        self.iter_cus_count = 0

    def iter_CUs(self) -> Iterator[FakeCU]:
        self.iter_cus_count += 1
        return super().iter_CUs()


def test_resolves_symbol_metadata(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.symbol_table.SymbolTableSection", FakeSymbolTable)

    symbols = resolve_symbols_from_elf(resolver_factory, FakeELF(), ["main"])

    assert len(symbols) == 1
    assert symbols[0].name == "main"
    assert symbols[0].address == 0x08000100
    assert symbols[0].address_hex == "0x8000100"
    assert symbols[0].size == 64
    assert symbols[0].type == ""
    assert isinstance(symbols[0], SymbolInfo)
    assert symbols[0].binding == "global"
    assert symbols[0].section == ".text"
    assert symbols[0].table == ".symtab"


def test_normalizes_function_symbol_with_mapping_like_metadata(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.symbol_table.SymbolTableSection", FakeSymbolTable)
    elf = FakeELF()
    elf.sections[3] = FakeSymbolTable(
        ".symtab",
        [
            FakeSymbol(
                "main",
                {
                    "st_value": 0x08000101,
                    "st_size": 64,
                    "st_info": UserDict(
                        {"type": "STT_FUNC", "bind": "STB_GLOBAL"}
                    ),
                    "st_other": {"visibility": "STV_DEFAULT"},
                    "st_shndx": 1,
                },
            )
        ],
    )

    symbols = resolve_symbols_from_elf(resolver_factory, elf, ["main"])

    assert symbols[0].address == 0x08000100


def test_reports_missing_symbols(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.symbol_table.SymbolTableSection", FakeSymbolTable)

    symbols = resolve_symbols_from_elf(
        resolver_factory,
        FakeELF(),
        ["main", "missing"],
    )

    assert missing_symbols(symbols, ["main", "missing"]) == ["missing"]


def test_deduces_plain_symbol_type_from_dwarf(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.symbol_table.SymbolTableSection", FakeSymbolTable)
    unsigned_type = FakeDie(
        "DW_TAG_base_type",
        "unsigned int",
        attrs={"DW_AT_encoding": FakeAttr(0x07)},
    )
    dwarf_info = FakeDwarfInfo(
        [FakeCU([FakeDie("DW_TAG_variable", "counter", type_die=unsigned_type)])]
    )
    resolver = resolver_factory(
        FakeDwarfELF(dwarf_info, sections=FakeELF().sections)
    )

    assert resolver.resolve_symbols(["counter"])[0].type == "unsigned"
    address_symbol = resolver.resolve_address(0x20000000)
    assert address_symbol is not None
    assert address_symbol.type == "unsigned"


def test_leaves_plain_symbol_type_undefined_when_dwarf_type_is_ambiguous(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.symbol_table.SymbolTableSection", FakeSymbolTable)
    dwarf_info = FakeDwarfInfo(
        [
            FakeCU(
                [
                    FakeDie(
                        "DW_TAG_variable",
                        "counter",
                        type_die=FakeDie("DW_TAG_pointer_type"),
                    ),
                    FakeDie(
                        "DW_TAG_variable",
                        "counter",
                        type_die=FakeDie("DW_TAG_structure_type"),
                    ),
                ]
            )
        ]
    )

    symbols = resolve_symbols_from_elf(
        resolver_factory,
        FakeDwarfELF(dwarf_info, sections=FakeELF().sections),
        ["counter"],
    )

    assert symbols[0].type == ""


def test_elf_resolver_reuses_symbol_table_cache(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.symbol_table.SymbolTableSection", FakeSymbolTable)
    elf_file = CountingFakeELF()
    resolver = resolver_factory(elf_file)

    assert resolver.resolve_symbols(["main"])[0].name == "main"
    counter = resolver.resolve_address(0x20000000)
    assert counter is not None
    assert counter.name == "counter"
    assert resolver.resolve_address(0xDEADBEEF) is None
    assert [symbol.name for symbol in resolver.resolve_symbols()] == [
        "main",
        "counter",
    ]
    assert elf_file.iter_sections_count == 1


def test_elf_resolver_rejects_lookup_after_close(
    resolver_factory: ResolverFactory,
) -> None:
    resolver = resolver_factory(FakeELF())
    resolver.close()

    with pytest.raises(RuntimeError, match="closed"):
        resolver.resolve_symbols(["main"])


@pytest.mark.skipif(
    shutil.which("arm-none-eabi-gcc") is None,
    reason="arm-none-eabi-gcc is required for the real ELF integration test",
)
def test_resolves_symbol_from_real_elf_fixture(tmp_path: Path) -> None:
    source = tmp_path / "fixture.c"
    elf_path = tmp_path / "fixture.o"
    source.write_text("unsigned sample_counter = 7;\n", encoding="utf-8")
    subprocess.run(
        [
            "arm-none-eabi-gcc",
            "-g",
            "-O0",
            "-c",
            str(source),
            "-o",
            str(elf_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    with ElfResolver(elf_path) as resolver:
        symbols = resolver.resolve_symbols(["sample_counter"])

    assert len(symbols) == 1
    assert symbols[0].name == "sample_counter"
    assert symbols[0].size == 4


def _member(name: str, offset: int, type_die: FakeDie) -> FakeDie:
    return FakeDie(
        "DW_TAG_member",
        name,
        type_die=type_die,
        attrs={"DW_AT_data_member_location": FakeAttr(offset)},
    )


def _fake_os_rtx_info_dwarf() -> FakeDwarfInfo:
    thread_pointer = FakeDie("DW_TAG_pointer_type")
    run_type = FakeDie(
        "DW_TAG_structure_type",
        children=[
            _member("curr", 0, thread_pointer),
            _member("next", 4, thread_pointer),
        ],
    )
    thread_type = FakeDie(
        "DW_TAG_structure_type",
        children=[
            _member("run", 0, run_type),
            _member("idle", 20, thread_pointer),
        ],
    )
    info_struct = FakeDie(
        "DW_TAG_structure_type",
        attrs={"DW_AT_byte_size": FakeAttr(164)},
        children=[
            _member(
                "version",
                4,
                FakeDie(
                    "DW_TAG_base_type",
                    "unsigned int",
                    attrs={
                        "DW_AT_byte_size": FakeAttr(4),
                        "DW_AT_encoding": FakeAttr(0x07),
                    },
                ),
            ),
            _member("thread", 20, thread_type),
        ],
    )
    info_typedef = FakeDie("DW_TAG_typedef", "osRtxInfo_t", type_die=info_struct)
    variable = FakeDie(
        "DW_TAG_variable",
        "osRtxInfo",
        type_die=info_typedef,
        attrs={"DW_AT_location": FakeAttr([0])},
    )
    return FakeDwarfInfo([FakeCU([variable])])


def _fake_counting_os_rtx_info_dwarf() -> CountingDwarfInfo:
    dwarf_info = _fake_os_rtx_info_dwarf()
    return CountingDwarfInfo(dwarf_info.cus)


def test_resolves_nested_object_member(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr(
        "pyts.elf.dwarf_members.DWARFExprParser",
        FakeDwarfExprParser,
    )

    members = resolve_object_members_from_elf(
        resolver_factory,
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        ["osRtxInfo.thread.run.curr"],
    )

    assert members == [
        MemberInfo(
            name="osRtxInfo.thread.run.curr",
            address=0x20000028,
            size=4,
            type="pointer",
            base_symbol="osRtxInfo",
            member_path="thread.run.curr",
            offset=0x14,
        )
    ]


def test_resolved_member_uses_canonical_type_and_keeps_source_spelling(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    members = resolve_object_members_from_elf(
        resolver_factory,
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        ["osRtxInfo.version"],
    )

    assert members[0].type == "unsigned"
    assert members[0].source_type == "unsigned int"
    assert members[0].size == 4


def test_resolves_object_member_with_source_file_filter(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)
    dwarf_info = _fake_os_rtx_info_dwarf()
    dwarf_info.cus[0].dies[0].attributes["DW_AT_decl_file"] = FakeAttr(1)

    matching = resolve_object_members_from_elf(
        resolver_factory,
        FakeDwarfELF(dwarf_info),
        ["osRtxInfo.thread.run.curr"],
        source_file="rtx_kernel.c",
    )
    missing = resolve_object_members_from_elf(
        resolver_factory,
        FakeDwarfELF(dwarf_info),
        ["osRtxInfo.thread.run.curr"],
        source_file="other.c",
    )

    assert matching[0].name == "osRtxInfo.thread.run.curr"
    assert matching[0].source_file == "/src/rtx_kernel.c"
    assert missing == []


def test_resolves_plain_symbol_with_source_file_filter(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.symbol_table.SymbolTableSection", FakeSymbolTable)
    dwarf_info = FakeDwarfInfo(
        [
            FakeCU(
                [
                    FakeDie(
                        "DW_TAG_subprogram",
                        "main",
                        attrs={"DW_AT_decl_file": FakeAttr(1)},
                    )
                ]
            )
        ]
    )

    symbols = resolve_symbols_from_elf(
        resolver_factory,
        FakeDwarfELF(dwarf_info, sections=FakeELF().sections),
        ["main"],
        source_file="rtx_kernel.c",
    )

    assert symbols == [
        SymbolInfo(
            name="main",
            address=0x08000100,
            size=64,
            type="function",
            binding="global",
            visibility="default",
            section=".text",
            table=".symtab",
            source_file="/src/rtx_kernel.c",
        )
    ]


def test_elf_resolver_reuses_dwarf_member_address_cache(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)
    dwarf_info = _fake_counting_os_rtx_info_dwarf()
    resolver = resolver_factory(FakeDwarfELF(dwarf_info))

    assert resolver.resolve_object_members_by_address([(0x20000028, 4)])[0].name == (
        "osRtxInfo.thread.run.curr"
    )
    assert resolver.resolve_object_members_by_address([(0x2000002C, 4)])[0].name == (
        "osRtxInfo.thread.run.next"
    )
    assert dwarf_info.iter_cus_count == 1


def test_elf_resolver_reuses_dotted_member_cache(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)
    dwarf_info = _fake_counting_os_rtx_info_dwarf()
    resolver = resolver_factory(FakeDwarfELF(dwarf_info))

    assert resolver.resolve_symbols(["osRtxInfo.thread.run.curr"])[0].name == (
        "osRtxInfo.thread.run.curr"
    )
    assert resolver.resolve_symbols(["osRtxInfo.thread.run.curr"])[0].name == (
        "osRtxInfo.thread.run.curr"
    )
    assert dwarf_info.iter_cus_count == 1


def test_resolves_object_member_by_address_and_size(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    members = resolve_object_members_by_address_from_elf(
        resolver_factory,
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        [(0x20000028, 4)],
    )

    assert members == [
        MemberInfo(
            name="osRtxInfo.thread.run.curr",
            address=0x20000028,
            size=4,
            type="pointer",
            base_symbol="osRtxInfo",
            member_path="thread.run.curr",
            offset=0x14,
        )
    ]


def test_object_member_by_address_requires_matching_size(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    members = resolve_object_members_by_address_from_elf(
        resolver_factory,
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        [(0x20000028, 8)],
    )

    assert members == []


def test_object_member_by_address_reports_ambiguous_matches(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)
    dwarf_info = _fake_os_rtx_info_dwarf()
    variable = dwarf_info.cus[0].dies[0]
    duplicate = FakeDie(
        "DW_TAG_variable",
        "duplicateInfo",
        type_die=variable.type_die,
        attrs={"DW_AT_location": FakeAttr([0])},
    )
    dwarf_info.cus[0].dies.append(duplicate)

    members = resolve_object_members_by_address_from_elf(
        resolver_factory,
        FakeDwarfELF(dwarf_info),
        [(0x20000028, 4)],
    )

    assert [member.name for member in members] == [
        "osRtxInfo.thread.run.curr",
        "duplicateInfo.thread.run.curr",
    ]


def test_object_member_reports_missing_member(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    members = resolve_object_members_from_elf(
        resolver_factory,
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        ["osRtxInfo.thread.missing"],
    )

    assert members == []


def test_object_member_ignores_malformed_expressions(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    members = resolve_object_members_from_elf(
        resolver_factory,
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        ["osRtxInfo", "osRtxInfo.", ".thread"],
    )

    assert members == []


def test_resolve_symbols_falls_back_to_dwarf_members(
    monkeypatch: Any,
    resolver_factory: ResolverFactory,
) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    symbols = resolve_symbols_from_elf(
        resolver_factory,
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        ["osRtxInfo.thread.run.curr"],
    )

    assert symbols[0].name == "osRtxInfo.thread.run.curr"
    assert symbols[0].address_hex == "0x20000028"
    assert missing_symbols(symbols, ["osRtxInfo.thread.run.curr"]) == []

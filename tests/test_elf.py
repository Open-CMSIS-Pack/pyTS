from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest

from pyts.elf import (
    ElfResolver,
    MemberInfo,
    SymbolInfo,
    missing_symbols,
)


def resolve_symbols_from_elf(
    elf_file: Any,
    names: list[str],
    *,
    source_file: str | None = None,
) -> list[SymbolInfo | MemberInfo]:
    return ElfResolver.from_elf(elf_file).resolve_symbols(
        names,
        source_file=source_file,
    )


def resolve_object_members_from_elf(
    elf_file: Any,
    names: list[str],
    *,
    source_file: str | None = None,
) -> list[MemberInfo]:
    return ElfResolver.from_elf(elf_file).resolve_object_members(
        names,
        source_file=source_file,
    )


def resolve_object_members_by_address_from_elf(
    elf_file: Any,
    members: list[tuple[int, int]],
) -> list[MemberInfo]:
    return ElfResolver.from_elf(elf_file).resolve_object_members_by_address(members)


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

    def get_section(self, index: int) -> FakeSection:
        return self.sections[index]


class FakeDwarfExprParser:
    def __init__(self, structs: object) -> None:
        pass

    def parse_expr(self, expression: object) -> list[FakeOp]:
        return [FakeOp("DW_OP_addrx", [1])]


class FakeOp:
    def __init__(self, op_name: str, args: list[int]) -> None:
        self.op_name = op_name
        self.args = args


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
                            "st_value": 0x08000100,
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

    def get_section(self, index: int) -> FakeSection:
        return self.sections[index]


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


def test_resolves_symbol_metadata(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.symbol_table.SymbolTableSection", FakeSymbolTable)

    symbols = resolve_symbols_from_elf(FakeELF(), ["main"])

    assert len(symbols) == 1
    assert symbols[0].name == "main"
    assert symbols[0].address == 0x08000100
    assert symbols[0].address_hex == "0x8000100"
    assert symbols[0].size == 64
    assert symbols[0].type == "func"
    assert isinstance(symbols[0], SymbolInfo)
    assert symbols[0].binding == "global"
    assert symbols[0].section == ".text"
    assert symbols[0].table == ".symtab"


def test_reports_missing_symbols(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.symbol_table.SymbolTableSection", FakeSymbolTable)

    symbols = resolve_symbols_from_elf(FakeELF(), ["main", "missing"])

    assert missing_symbols(symbols, ["main", "missing"]) == ["missing"]


def test_elf_resolver_reuses_symbol_table_cache(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.symbol_table.SymbolTableSection", FakeSymbolTable)
    elf_file = CountingFakeELF()
    resolver = ElfResolver.from_elf(elf_file)

    assert resolver.resolve_symbols(["main"])[0].name == "main"
    counter = resolver.resolve_address(0x20000000)
    assert counter is not None
    assert counter.name == "counter"
    assert [symbol.name for symbol in resolver.resolve_symbols()] == [
        "main",
        "counter",
    ]
    assert elf_file.iter_sections_count == 1


def test_elf_resolver_rejects_lookup_after_close() -> None:
    resolver = ElfResolver.from_elf(FakeELF())
    resolver.close()

    with pytest.raises(RuntimeError, match="closed"):
        resolver.resolve_symbols(["main"])


def test_symbol_info_rejects_inconsistent_derived_address() -> None:
    with pytest.raises(ValueError, match="derived"):
        SymbolInfo(name="main", address=1, address_hex="0x2")


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

    with ElfResolver.from_path(elf_path) as resolver:
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
            _member("version", 4, FakeDie("DW_TAG_base_type", "unsigned int")),
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


def test_resolves_nested_object_member(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    members = resolve_object_members_from_elf(
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        ["osRtxInfo.thread.run.curr"],
    )

    assert members == [
        MemberInfo(
            name="osRtxInfo.thread.run.curr",
            address=0x20000028,
            address_hex="0x20000028",
            size=4,
            type="pointer",
            base_symbol="osRtxInfo",
            member_path="thread.run.curr",
            offset=0x14,
            offset_hex="0x14",
        )
    ]


def test_resolves_object_member_with_source_file_filter(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)
    dwarf_info = _fake_os_rtx_info_dwarf()
    dwarf_info.cus[0].dies[0].attributes["DW_AT_decl_file"] = FakeAttr(1)

    matching = resolve_object_members_from_elf(
        FakeDwarfELF(dwarf_info),
        ["osRtxInfo.thread.run.curr"],
        source_file="rtx_kernel.c",
    )
    missing = resolve_object_members_from_elf(
        FakeDwarfELF(dwarf_info),
        ["osRtxInfo.thread.run.curr"],
        source_file="other.c",
    )

    assert matching[0].name == "osRtxInfo.thread.run.curr"
    assert matching[0].source_file == "/src/rtx_kernel.c"
    assert missing == []


def test_resolves_plain_symbol_with_source_file_filter(monkeypatch: Any) -> None:
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
        FakeDwarfELF(dwarf_info, sections=FakeELF().sections),
        ["main"],
        source_file="rtx_kernel.c",
    )

    assert symbols == [
        SymbolInfo(
            name="main",
            address=0x08000100,
            address_hex="0x8000100",
            size=64,
            type="func",
            binding="global",
            visibility="default",
            section=".text",
            table=".symtab",
            source_file="/src/rtx_kernel.c",
        )
    ]


def test_elf_resolver_reuses_dwarf_member_address_cache(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)
    dwarf_info = _fake_counting_os_rtx_info_dwarf()
    resolver = ElfResolver.from_elf(FakeDwarfELF(dwarf_info))

    assert resolver.resolve_object_members_by_address([(0x20000028, 4)])[0].name == (
        "osRtxInfo.thread.run.curr"
    )
    assert resolver.resolve_object_members_by_address([(0x2000002C, 4)])[0].name == (
        "osRtxInfo.thread.run.next"
    )
    assert dwarf_info.iter_cus_count == 1


def test_elf_resolver_reuses_dotted_member_cache(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)
    dwarf_info = _fake_counting_os_rtx_info_dwarf()
    resolver = ElfResolver.from_elf(FakeDwarfELF(dwarf_info))

    assert resolver.resolve_object_members(["osRtxInfo.thread.run.curr"])[0].name == (
        "osRtxInfo.thread.run.curr"
    )
    assert resolver.resolve_object_members(["osRtxInfo.thread.run.curr"])[0].name == (
        "osRtxInfo.thread.run.curr"
    )
    assert dwarf_info.iter_cus_count == 1


def test_resolves_object_member_by_address_and_size(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    members = resolve_object_members_by_address_from_elf(
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        [(0x20000028, 4)],
    )

    assert members == [
        MemberInfo(
            name="osRtxInfo.thread.run.curr",
            address=0x20000028,
            address_hex="0x20000028",
            size=4,
            type="pointer",
            base_symbol="osRtxInfo",
            member_path="thread.run.curr",
            offset=0x14,
            offset_hex="0x14",
        )
    ]


def test_object_member_by_address_requires_matching_size(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    members = resolve_object_members_by_address_from_elf(
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        [(0x20000028, 8)],
    )

    assert members == []


def test_object_member_by_address_reports_ambiguous_matches(
    monkeypatch: Any,
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
        FakeDwarfELF(dwarf_info),
        [(0x20000028, 4)],
    )

    assert [member.name for member in members] == [
        "osRtxInfo.thread.run.curr",
        "duplicateInfo.thread.run.curr",
    ]


def test_object_member_reports_missing_member(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    members = resolve_object_members_from_elf(
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        ["osRtxInfo.thread.missing"],
    )

    assert members == []


def test_object_member_ignores_malformed_expressions(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    members = resolve_object_members_from_elf(
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        ["osRtxInfo", "osRtxInfo.", ".thread"],
    )

    assert members == []


def test_resolve_symbols_falls_back_to_dwarf_members(monkeypatch: Any) -> None:
    monkeypatch.setattr("pyts.elf.dwarf_members.DWARFExprParser", FakeDwarfExprParser)

    symbols = resolve_symbols_from_elf(
        FakeDwarfELF(_fake_os_rtx_info_dwarf()),
        ["osRtxInfo.thread.run.curr"],
    )

    assert symbols[0].name == "osRtxInfo.thread.run.curr"
    assert symbols[0].address_hex == "0x20000028"
    assert missing_symbols(symbols, ["osRtxInfo.thread.run.curr"]) == []

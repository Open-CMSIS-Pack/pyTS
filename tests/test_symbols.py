from __future__ import annotations

from pathlib import Path

import pytest

from pyts.symbols import SymbolCatalog, SymbolFile


def test_symbol_catalog_selects_qualified_files_in_order() -> None:
    files = [
        SymbolFile(Path("first.elf"), frozenset({"first"}), "app"),
        SymbolFile(Path("second.elf"), frozenset({"second"}), "net"),
    ]

    with SymbolCatalog(files) as catalog:
        assert catalog.candidates("net") == [files[1]]
        assert catalog.candidates("first") == [files[0]]
        assert catalog.candidates() == files


def test_symbol_catalog_rejects_use_after_close() -> None:
    catalog = SymbolCatalog([])
    catalog.close()

    with pytest.raises(RuntimeError, match="closed"):
        catalog.candidates()

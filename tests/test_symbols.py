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

from pathlib import Path

import pytest

from pyts.symbols import SymbolCatalog, SymbolFile


def test_symbol_catalog_selects_qualified_files_in_order() -> None:
    files = [
        SymbolFile(Path("first.elf"), frozenset({"first"}), "app", "CM7"),
        SymbolFile(Path("second.elf"), frozenset({"second"}), "net", "CM4"),
    ]

    with SymbolCatalog(files) as catalog:
        assert catalog.candidates("net") == [files[1]]
        assert catalog.candidates("first") == [files[0]]
        assert catalog.candidates(pname="CM7") == [files[0]]
        assert catalog.candidates("app", pname="CM4") == []
        assert catalog.candidates() == files


def test_symbol_catalog_rejects_use_after_close() -> None:
    catalog = SymbolCatalog([])
    catalog.close()

    with pytest.raises(RuntimeError, match="closed"):
        catalog.candidates()

from collections.abc import Iterator
from typing import Any, Protocol

class ELFSymbol(Protocol):
    name: str
    entry: dict[str, Any]

    def __getitem__(self, key: str) -> Any: ...

class SymbolTableSection:
    name: str

    def iter_symbols(self) -> Iterator[ELFSymbol]: ...

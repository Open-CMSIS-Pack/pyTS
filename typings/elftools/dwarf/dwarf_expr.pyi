from dataclasses import dataclass

@dataclass(frozen=True)
class DWARFExprOp:
    op: int
    op_name: str
    args: list[int]
    offset: int

class DWARFExprParser:
    def __init__(self, structs: object) -> None: ...

    def parse_expr(self, expr: object) -> list[DWARFExprOp]: ...

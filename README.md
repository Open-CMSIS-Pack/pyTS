# pyTS

Python Trace Setup utility complementing pyOCD for CMSIS Debug integration

## Install for development

Create a virtual environment for PyTS:

```sh
> python3 -m venv .venv
> source .venv/bin/activate
> which pip
.venv/bin/pip
```

Install pyTS itself and its runtime dependencies into the virtual environment in editable mode:

```sh
> pip install -e .
> which pyts
.venv/bin/pyts
```

Installing test tooling:

```sh
> pip install -e '.[test]'
```

Install type-check tooling:

```sh
> pip install -e '.[lint]'
```

Run tests and strict type checks:

```sh
> pytest -q
> pyright
> mypy
```

### Windows user

Run pip commands with double-quotes, e.g.

```cmd
> .venv/bin/activate.bat
> where pip
.venv/Scripts/pip.exe
> pip install -e ".[test]"
```

## CLI

Generate a trace run configuration from a CMSIS cbuild-run file:

```sh
pyts <cbuild-run.yml>
```

The command reads `.cmsis/<solution>+<target-type>[@<target-set>].ctrace.yml`, resolves
symbols from the cbuild-run ELF outputs, and writes the generated trace setup to
`.trace/<solution>+<target-type>[@<target-set>].ctrace-run.yml`.

When `cbuild-run.system-resources.processors` is available, pyTS uses each
processor's `core` and `pname` to generate CMSIS `ctrace-run.ctrace-refs` entries.
Their `regs` lists contain masked architectural ITM and DWT register writes for
ITM channels, timestamps, basic DWTv1/DWTv2 data trace, exception trace, event
trace, PC sampling, and DWT synchronization. Unsupported processor or feature
combinations are reported on the corresponding reference with `error`.
The `ctrace-run` node also retains the complete source `ctrace` content with
resolved location metadata. Addresses and register values and masks are written
as 32-bit hexadecimal YAML integers.
Location-style and legacy `symbol`/`address` entries may coexist in one trace
document; pyTS resolves both styles in document order using the same ELF cache.

Data trace supports the CMSIS output modes `value`, `address`, `PC`, `match`,
`PC+value`, `address+value`, and `PC+address`. DWTv1 supports `value`,
`address`, `PC+value`, and `address+value` for all access types, plus `PC` for
`RW`; it cannot produce `match` or `PC+address`. One DWTv1 `match:` condition
per processor can use the portable comparator 0/1 address-value pair with any
otherwise supported output. Its address range size and matched data width are
encoded independently. DWTv2 Main Extension processors support all output
modes. Cortex-M23 cannot generate the required data trace packets.

DWTv2 address output and arbitrary or unaligned ranges consume consecutive
lower/limit comparator pairs. A one-byte range cannot emit an address packet.
A DWTv2 `match:` condition consumes an address/linked-value pair. The requested
`output` applies to the address comparator (default `value`), while the linked
value comparator implicitly uses `match` output. Data and match sizes must be
equal and naturally aligned. Match sizes are 1, 2, or 4 bytes (default 4), and
values must be unsigned and fit the selected width. Requests that cannot be
represented exactly are reported on the corresponding reference with `error`
and no register setup.

## Packaging

The project uses a `src/` layout and `pyproject.toml` metadata for PyPI
distribution. Build a source distribution and wheel with:

```sh
.venv/bin/python -m pip install build
.venv/bin/python -m build
```

## pyInstaller Builds

```sh
.venv/bin/python -m pip install pyinstaller
pyinstaller --clean --noconfirm --onefile --name pyTS src/pyts/__main__.py
```

No need at this point to commit the generated `./pyTS.spec` to the repository.
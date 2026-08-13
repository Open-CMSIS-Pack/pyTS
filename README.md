[![Maintainability](https://qlty.sh/badges/ad8ffd83-bf17-42f6-9c06-7df734a3ee74/maintainability.svg)](https://qlty.sh/gh/Open-CMSIS-Pack/projects/pyTS)
[![Code Coverage](https://qlty.sh/badges/ad8ffd83-bf17-42f6-9c06-7df734a3ee74/coverage.svg)](https://qlty.sh/gh/Open-CMSIS-Pack/projects/pyTS)

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
The `ctrace-run.ctrace-setup` node retains the original source `ctrace.setup`
content. Enriched location metadata is used internally when generating
`ctrace-refs`. Symbol extents and types are emitted as `data[].symbol-size`
and `data[].symbol-type` in the generated references; `data[].size` remains
the trace access size. DWARF types use language-neutral categories derived from
their tags and encodings, such as `signed`, `unsigned`, `bool`, `float`,
`pointer`, `array`, and `struct`; source-language type names are not emitted.
When a symbol type cannot be deduced from DWARF, `symbol-type` is omitted.
Addresses and register values and masks are written as 32-bit hexadecimal YAML
integers. The generated
`ctrace-run` mapping contains only `generated-by`, `ctrace-setup`, and
`ctrace-refs`; other source `ctrace` properties are not copied.
Location-style and legacy `symbol`/`address` entries may coexist in one trace
document; pyTS resolves both styles in document order using the same ELF cache.
PC sampling periods use integer CPU-cycle counts: `0` disables sampling, while
supported enabled periods are powers of two from `64` through `16384`.

Data trace supports the CMSIS output modes `value`, `offset`, `PC`, `match`,
`PC+value`, `offset+value`, and `PC+offset`. DWTv1 supports `value`,
`offset`, `PC+value`, and `offset+value` for all access types, plus `PC` for
`RW`; it cannot produce `match` or `PC+offset`. One DWTv1 `match:` condition
per processor can use the portable comparator 0/1 address-value pair with any
otherwise supported output. Its address range size and matched data width are
encoded independently. DWTv2 Main Extension processors support all output
modes. Cortex-M23 cannot generate the required data trace packets.

DWTv2 offset output and arbitrary or unaligned ranges consume consecutive
lower/limit comparator pairs. A one-byte range cannot emit an offset packet.
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

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes
and submit fixes or enhancements as pull requests. Before submitting a change,
run the tests and strict type checks described in
[Install for development](#install-for-development).

By submitting a contribution, you agree that it may be distributed under the
project's Apache License 2.0.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
Third-party dependencies remain subject to their respective licenses; see the
[Third-Party Intellectual Property notice](TPIP.md), generated with
[`pip-licenses`](https://github.com/raimon49/pip-licenses).

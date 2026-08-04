# AI agent instructions

These instructions apply to the entire repository.

## Before completing a change

- Inspect the relevant existing code and tests before editing.
- Add or update tests for behaviour changes and bug fixes.
- Run all of these checks after making changes:

  ```sh
  python -m pytest
  python -m pyright
  python -m mypy
  ```

- Treat failures in any of the three checks as unresolved unless the failure is
  demonstrably unrelated to the change. If a check cannot be run, report that
  clearly and explain why.
- Keep changes focused; do not reformat or modify unrelated files.

The test and type-checking configuration is defined in `pyproject.toml` and
`pyrightconfig.json`. Development dependencies can be installed with:

```sh
python -m pip install -e '.[test,typecheck]'
```

## Coverage and Qlty

- Install the test package in editable mode before generating coverage so the
  report references the checked-out `src/pyts` files:

  ```sh
  python -m pip install -e '.[lint]'
  ```

- Generate the XML and HTML reports with:

  ```sh
  python -m pytest -q --cov=src/pyts \
    --cov-report=xml:coverage.xml \
    --cov-report=html:coverage-html
  ```

- Qlty coverage uses `add-prefix: src/pyts` because Cobertura filenames are
  relative to the package source directory. Do not replace it with a
  workspace `strip-prefix` unless the coverage report contains absolute
  workspace paths.
- Check changed-line coverage with `diff-cover` against `origin/main` and
  require 100% coverage for newly added executable lines:

  ```sh
  diff-cover coverage.xml --compare-branch=origin/main --fail-under=100
  ```

- Fetch full Git history before running `diff-cover` so `origin/main` is
  available for comparison.

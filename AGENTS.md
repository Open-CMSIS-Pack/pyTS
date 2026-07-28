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

# Agent guidance

`pywax` is a Python client and CLI for Netgear WAX access points.

## Development

- Keep the CLI and library behavior aligned with `README.md`; package metadata and Ruff settings are in `pyproject.toml`.
- Run `ruff check .` for linting and `pywax --help` to inspect CLI help without contacting a device.
- Use synthetic API responses for validation. Do not use production credentials or change a live access point while testing.
- Load the `nix` skill before changing the flake or Nix files.

## Shared GitHub Actions

- Before changing GitHub Actions, inspect the current guidance in `pschmitt/ci-workflows`. Use `@main` in every `uses:` reference to a shared workflow or action.

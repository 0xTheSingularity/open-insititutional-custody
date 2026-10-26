# Contributing

Start with the [development guide](docs/development.md). For setup problems,
use [troubleshooting](docs/getting-started.md#troubleshooting).

## Reporting a bug

[Open an issue](https://github.com/0xTheSingularity/open-insititutional-custody/issues/new/choose)
with the commit, exact command, toolchain version, expected result, and the
full error output. **Keep keys, shares, passphrases, and secret files out of
reports.**

For a suspected security vulnerability, do not open a public issue — follow
[SECURITY.md](SECURITY.md).

## Pull requests

- Build with the pinned toolchain: `cargo +1.95.0 build --locked`.
- Run the tests that cover your change; `docs/getting-started.md#run-the-full-suite`
  describes the full suite and its lower-disk profile.
- Golden vectors pin the canonical encoding. If an encoding test fails, treat
  it as a compatibility break to justify, not a fixture to regenerate.
- Keep the demo honest: `oic demo` and `oic demo --check` must pass.
- Update `CHANGELOG.md` under `Unreleased` for user-facing changes.

## License

Contributions are accepted under [Apache-2.0](LICENSE), matching the package
metadata in [Cargo.toml](Cargo.toml).

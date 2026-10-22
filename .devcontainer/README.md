# Dev container (GitHub Codespaces / VS Code)

This folder lets anyone open the repository in a browser with zero local
install and run the custody demo:

```sh
cargo run -p oic-cli -- demo
```

Open it in one click:
<https://codespaces.new/0xTheSingularity/open-insititutional-custody?quickstart=1>

## What the container does

`devcontainer.json` is intentionally **plain JSON with no comments** so it
parses with a strict JSON parser (the dev-container spec also allows JSONC, but
we keep the explanations here instead). It:

- Bases on `mcr.microsoft.com/devcontainers/rust:1-bookworm`.
- `onCreateCommand` adds the native build dependencies the workspace needs that
  the base image does not already carry — a C/C++ toolchain, `cmake`, and
  `mold` — plus `pkg-config`, `clang`, `curl`, and `jq`. (These mirror the
  prerequisites in [`docs/local-stack.md`](../docs/local-stack.md); TLS is
  `rustls`, so no OpenSSL/`libssl-dev` is required.)
- `postCreateCommand` pins the toolchain to the workspace MSRV
  (`rust-version = "1.95"` in the root `Cargo.toml`) with
  `rustup toolchain install 1.95 && rustup default 1.95`, then pre-builds the
  demo with `CARGO_PROFILE_DEV_DEBUG=0 cargo build -p oic-cli` so the first
  `oic demo` starts quickly.
- `postAttachCommand` prints the one-line run hint.

## First build takes a few minutes

`oic-cli` links the whole custody workspace, so the one-time `postCreateCommand`
compile is heavy. `hostRequirements` requests a **4-core / 8 GB** machine; pick
that machine type (or larger) when Codespaces prompts. After the first build,
`cargo run -p oic-cli -- demo` reuses the cached `target/` and is fast.

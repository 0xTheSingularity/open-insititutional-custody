# GHCR image for the `oic` custody demo.
#
# Location decision: this Dockerfile lives at the REPO ROOT (not cli/oic/)
# because `cargo build -p oic-cli --release` needs the entire Cargo workspace
# (all member crates + Cargo.lock) in the build context. A root Dockerfile makes
# the natural `docker build .` context the workspace root.
#
#   docker build -t ghcr.io/0xthesingularity/open-insititutional-custody:latest .
#   docker run --rm ghcr.io/0xthesingularity/open-insititutional-custody:latest
#
# `docker run` with no args executes `oic demo` (the zero-prompt quickstart).

# ---- builder ----------------------------------------------------------------
FROM rust:1.95 AS builder

# Trims debug info to cut build time and disk use (the workspace release profile
# is otherwise unchanged). An unset build-arg would reach cargo as an empty string,
# which it rejects, so it defaults to 0.
ARG CARGO_PROFILE_RELEASE_DEBUG=0
ENV CARGO_PROFILE_RELEASE_DEBUG=${CARGO_PROFILE_RELEASE_DEBUG}

WORKDIR /src

# Copy the whole workspace so path dependencies resolve, then build just the CLI.
# Only a failed `strip` is tolerated; a failed build fails this step.
COPY . .
RUN cargo build -p oic-cli --release --locked \
    && cp target/release/oic /usr/local/bin/oic \
    && { strip /usr/local/bin/oic || true; }

# ---- runtime ----------------------------------------------------------------
FROM debian:stable-slim AS runtime

# Minimal runtime deps: TLS roots for any outbound HTTPS the stack may attempt.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user.
RUN useradd --create-home --uid 10001 --user-group oic
USER oic
WORKDIR /home/oic

COPY --from=builder /usr/local/bin/oic /usr/local/bin/oic

# `docker run <image>` runs the zero-prompt custody demo.
ENTRYPOINT ["oic"]
CMD ["demo"]

# Multi-stage OCI build for stoa daemons.
#
# Build context: the *parent* directory of this repo, not this repo itself.
# The parent must contain both stoa/ and JMAP/ so that the path dependency
# crates/mail/Cargo.toml → ../../../JMAP/... resolves correctly.
#
# Build from the PROJECT root:
#   docker build -f stoa/Dockerfile -t stoa:dev .
#
# Or use the justfile target (run from the stoa/ directory):
#   just docker-build
#
# For CI with a git SHA tag:
#   docker build -f stoa/Dockerfile -t ghcr.io/markatwood/stoa:sha-$(git rev-parse --short HEAD) .

# ---------------------------------------------------------------------------
# Stage 1 — builder
# Pin Rust to the workspace MSRV (rust-version = "1.80" in member Cargo.tomls;
# imap crate requires 1.85, so we pin the builder to stable which is ≥ 1.85).
# ---------------------------------------------------------------------------
FROM rust:1.85-slim AS builder

# Install build-time deps: git (for build.rs SHA injection) and strip.
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        git \
        binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the JMAP path-dep crates so cargo can resolve them.
# Layout must match the relative paths in crates/mail/Cargo.toml:
#   jmap-types  = { path = "../../../JMAP/crate-jmap-types" }
#   jmap-server = { path = "../../../JMAP/crate-jmap-server" }
# which resolves from /build/stoa/crates/mail/ to /build/JMAP/.
COPY JMAP/ ./JMAP/
COPY stoa/  ./stoa/

# Guard: verify the JMAP sibling directory was present in the build context.
# If the build is run from the wrong directory (e.g. inside stoa/ rather than
# its parent), COPY JMAP/ silently creates an empty directory and cargo will
# fail with a confusing path-dependency resolution error.  Fail early with a
# clear message instead.
RUN test -d /build/JMAP && \
    test -n "$(ls /build/JMAP/ 2>/dev/null)" || { \
        echo "ERROR: /build/JMAP is empty or missing."; \
        echo "Build the Docker image from the PROJECT root (parent of stoa/):"; \
        echo "  docker build -f stoa/Dockerfile -t stoa:dev ."; \
        exit 1; \
    }

WORKDIR /build/stoa

# Build release binaries with locked deps.
RUN cargo build --release --locked --workspace

# Strip all binaries to reduce image size.
RUN find target/release -maxdepth 1 -type f -executable \
        ! -name '*.d' \
    | xargs -I{} strip --strip-all {}

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# gcr.io/distroless/cc-debian12 provides glibc + libgcc but no shell,
# no package manager, and no unnecessary binaries — minimal attack surface.
# UID 65532 ("nonroot") is the distroless convention for running as non-root.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Copy all stoa binaries.
COPY --from=builder /build/stoa/target/release/stoa-mail     /usr/local/bin/stoa-mail
COPY --from=builder /build/stoa/target/release/stoa-smtp     /usr/local/bin/stoa-smtp
COPY --from=builder /build/stoa/target/release/stoa-imap     /usr/local/bin/stoa-imap
COPY --from=builder /build/stoa/target/release/stoa-reader   /usr/local/bin/stoa-reader
COPY --from=builder /build/stoa/target/release/stoa-transit  /usr/local/bin/stoa-transit
COPY --from=builder /build/stoa/target/release/stoa-rnews    /usr/local/bin/stoa-rnews
COPY --from=builder /build/stoa/target/release/stoa-ctl      /usr/local/bin/stoa-ctl

# Default entrypoint is stoa-mail (the JMAP/HTTP server).
# Override ENTRYPOINT in a derived image or docker run --entrypoint to run
# a different daemon.
ENTRYPOINT ["/usr/local/bin/stoa-mail"]

# Expose JMAP HTTP port (default listen addr configured via STOA_LISTEN_ADDR).
EXPOSE 8080

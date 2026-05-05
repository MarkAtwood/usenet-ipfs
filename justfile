# usenet-ipfs development tasks
# Run `just --list` to see all available recipes.

default: list

# List all available recipes
list:
    @just --list

# Build all workspace crates
build:
    cargo build --workspace

# Run all tests (use `just nextest` for faster parallel runs with cargo-nextest)
test:
    cargo test --workspace

# Run clippy lints (fail on warnings)
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-features -- -D warnings

# Auto-fix formatting
fmt:
    cargo fmt --all

# Run benchmarks
bench:
    cargo bench --workspace

# Remove build artifacts
clean:
    cargo clean

# Build and open documentation
doc:
    cargo doc --workspace --open

# Generate a test operator key pair in /tmp/
key:
    #!/usr/bin/env bash
    set -euo pipefail
    KEYFILE=/tmp/usenet-ipfs-test-key.json
    if command -v openssl &>/dev/null; then
        openssl genpkey -algorithm ed25519 -out /tmp/usenet-ipfs-test-key.pem 2>/dev/null
        echo "Ed25519 private key written to /tmp/usenet-ipfs-test-key.pem"
    else
        echo "openssl not found; skipping key generation"
        exit 1
    fi

# Run tests with cargo-nextest (install with: cargo install cargo-nextest)
nextest:
    cargo nextest run --workspace

# Check for compilation errors without building
check:
    cargo check --workspace --all-features

# Watch for changes and re-run tests (install cargo-watch: cargo install cargo-watch)
watch:
    cargo watch -x "test --workspace"

# Watch for changes and re-run check only (faster feedback)
watch-check:
    cargo watch -x "check --workspace --all-features"

# Build the OCI container image (must run from stoa/ directory; builds from parent context).
# Requires Docker 20.10+.
docker-build tag="stoa:dev":
    #!/usr/bin/env bash
    set -euo pipefail
    PARENT="$(dirname "$(pwd)")"
    echo "Building from context: $PARENT"
    docker build -f "$(pwd)/Dockerfile" -t "{{tag}}" "$PARENT"

# Build and tag OCI image with the current git SHA.
docker-build-sha:
    #!/usr/bin/env bash
    set -euo pipefail
    SHA=$(git rev-parse --short HEAD)
    just docker-build "stoa:sha-${SHA}"
    echo "Built: stoa:sha-${SHA}"

set shell := ["bash", "-cu"]

# Default task when invoking `just` with no arguments.
default: help

help:
    @printf "Available recipes:\n"
    @printf "  build          Build all workspace crates\n"
    @printf "  build-release  Build all workspace crates in release mode\n"
    @printf "  check          Check all workspace crates\n"
    @printf "  test           Run workspace tests\n"
    @printf "  clippy         Run clippy for all targets and workspace crates\n"
    @printf "  clippy-fix     Run clippy with --fix for all targets and workspace crates\n"
    @printf "  crap           Run CRAP\n"
    @printf "  crap-summary   Run CRAP and get a summary\n"
    @printf "  fmt            Format all workspace crates\n"
    @printf "  fmt-check      Check formatting for all workspace crates\n"
    @printf "  clean          Remove build artifacts\n"
    @printf "  doc            Build workspace documentation\n"
    @printf "  boundary-check Check server dependency boundaries\n"
    @printf "  idp CONFIG     Run the standalone IdP server\n"
    @printf "  management CONFIG Run the standalone Management server\n"
    @printf "  storage CONFIG Run the standalone Storage server\n"
    @printf "  unified CONFIG Run the unified server\n"

build:
    cargo build --workspace

build-release:
    cargo build --workspace --release

check:
    cargo check --workspace

test:
    cargo hack test --feature-powerset --workspace --all-targets

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

clippy-fix:
    cargo clippy --workspace --all-targets --fix --allow-dirty --broken-code -- -D warnings

crap *args:
    RUST_MIN_STACK=67108864 cargo llvm-cov --workspace --lcov --output-path /tmp/lcov.info && cargo crap --workspace --lcov /tmp/lcov.info  {{ args }}

crap-summary:
    just crap --summary

cov:
    RUST_MIN_STACK=67108864 cargo llvm-cov --workspace --open

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clean:
    cargo clean

doc:
    cargo doc --workspace --no-deps

boundary-check:
    python3 scripts/check_server_dependencies.py

idp config:
    cargo run -p idp-server --features cli --bin idp-server -- --config {{config}}

management config:
    cargo run -p management-server --features cli --bin management-server -- --config {{config}}

storage config:
    cargo run -p storage-server --features cli --bin storage-server -- --config {{config}}

unified config:
    cargo run -p unified-server --features cli --bin unified-server -- --config {{config}}

api:
    pnpx portless api cargo run -- -c ./config/primary/config.yaml

api-secondary:
    pnpx portless api-secondary cargo run -- -c ./config/secondary/config.yaml

FROM rust:1.99-trixie AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

COPY of/ /workspace/of/
COPY ofdb/ /workspace/ofdb/
COPY offs/ /workspace/offs/
COPY ofnet/ /workspace/ofnet/
WORKDIR /workspace/of
RUN cargo build --locked --release -p unified-server --features cli --bin unified-server

FROM debian:trixie-slim
LABEL org.opencontainers.image.source=https://github.com/aicacia/rs-local

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /workspace/of/target/release/unified-server /app/run
USER 65532:65532
ENTRYPOINT ["/app/run"]
CMD ["-c", "/app/config.yaml", "serve"]

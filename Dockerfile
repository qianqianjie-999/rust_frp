# Multi-stage build for FRP Server and Client
# Usage:
#   docker build --target frps -t frps .
#   docker build --target frpc -t frpc .

FROM rust:1.80-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY rust_frp_core/Cargo.toml rust_frp_core/
COPY rust_frp_server/Cargo.toml rust_frp_server/
COPY rust_frp_client/Cargo.toml rust_frp_client/
COPY rust_frp_config/Cargo.toml rust_frp_config/
COPY rust_frp_net/Cargo.toml rust_frp_net/
COPY rust_frp_auth/Cargo.toml rust_frp_auth/
COPY rust_frp_plugin/Cargo.toml rust_frp_plugin/
COPY rust_frp_util/Cargo.toml rust_frp_util/

RUN mkdir -p rust_frp_core/src rust_frp_server/src rust_frp_client/src \
    rust_frp_config/src rust_frp_net/src rust_frp_auth/src \
    rust_frp_plugin/src rust_frp_util/src && \
    echo 'fn main() {}' > rust_frp_server/src/main.rs && \
    echo 'fn main() {}' > rust_frp_client/src/main.rs && \
    echo 'pub fn dummy() {}' > rust_frp_core/src/lib.rs && \
    echo 'pub fn dummy() {}' > rust_frp_server/src/lib.rs && \
    echo 'pub fn dummy() {}' > rust_frp_client/src/lib.rs && \
    echo 'pub fn dummy() {}' > rust_frp_config/src/lib.rs && \
    echo 'pub fn dummy() {}' > rust_frp_net/src/lib.rs && \
    echo 'pub fn dummy() {}' > rust_frp_auth/src/lib.rs && \
    echo 'pub fn dummy() {}' > rust_frp_plugin/src/lib.rs && \
    echo 'pub fn dummy() {}' > rust_frp_util/src/lib.rs

RUN cargo build --release \
    && rm -rf rust_frp_server/src rust_frp_client/src rust_frp_core/src \
    rust_frp_config/src rust_frp_net/src rust_frp_auth/src \
    rust_frp_plugin/src rust_frp_util/src

COPY . .
RUN touch rust_frp_core/src/lib.rs rust_frp_server/src/lib.rs rust_frp_client/src/lib.rs \
    rust_frp_config/src/lib.rs rust_frp_net/src/lib.rs rust_frp_auth/src/lib.rs \
    rust_frp_plugin/src/lib.rs rust_frp_util/src/lib.rs

RUN cargo build --release

FROM debian:bookworm-slim AS frps
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/rust_frps /usr/local/bin/rust_frps
COPY frps.toml /etc/frp/frps.toml
EXPOSE 9300 8080 8443 7500
ENTRYPOINT ["rust_frps"]
CMD ["-c", "/etc/frp/frps.toml"]

FROM debian:bookworm-slim AS frpc
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/rust_frpc /usr/local/bin/rust_frpc
COPY frpc.toml /etc/frp/frpc.toml
ENTRYPOINT ["rust_frpc"]
CMD ["-c", "/etc/frp/frpc.toml"]

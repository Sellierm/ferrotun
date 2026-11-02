# syntax=docker/dockerfile:1.7

FROM rust:1.99-alpine3.24 AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/ferrotun /ferrotun

FROM alpine:3.24
# wireguard-go: fallback when the kernel module is missing; iproute2: debugging only
RUN apk add --no-cache nftables wireguard-go tini iproute2 ca-certificates
COPY --from=builder /ferrotun /usr/local/bin/ferrotun

LABEL org.opencontainers.image.title="ferrotun" \
      org.opencontainers.image.description="Containerized WireGuard client with a kill-switch, written in Rust" \
      org.opencontainers.image.licenses="MIT"

EXPOSE 8000/tcp

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --start-interval=3s --retries=3 \
    CMD ["/usr/local/bin/ferrotun", "healthcheck"]

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/ferrotun"]

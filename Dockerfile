# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.90.0
FROM rust:${RUST_VERSION}-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS builder

WORKDIR /workspace
COPY Cargo.toml Cargo.lock rust-toolchain rustfmt.toml ./
COPY crates ./crates

RUN cargo build --locked --release --package thunderboltd --package thunderbolt-cli

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime

ARG VERSION=1.0.0-rc.1
ARG REVISION=unknown
ARG SOURCE=https://github.com/RiemaLabs/thunderbolt-lib

LABEL org.opencontainers.image.title="Bitcoin Thunderbolt" \
      org.opencontainers.image.description="Bitcoin Thunderbolt reference daemon and operator CLI" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 thunderbolt \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /var/lib/thunderbolt --shell /usr/sbin/nologin thunderbolt \
    && install --directory --owner 10001 --group 10001 --mode 0700 /var/lib/thunderbolt /var/lib/thunderbolt/auth \
    && install --directory --owner 10001 --group 10001 --mode 0750 /etc/bitcoin-thunderbolt

COPY --from=builder --chown=0:0 /workspace/target/release/thunderboltd /usr/local/bin/thunderboltd
COPY --from=builder --chown=0:0 /workspace/target/release/thunderbolt-cli /usr/local/bin/thunderbolt-cli
COPY --chown=0:0 LICENSE NOTICE /usr/share/doc/bitcoin-thunderbolt/
COPY --chown=0:0 deploy/regtest/thunderbolt.toml /etc/bitcoin-thunderbolt/thunderbolt.toml

USER 10001:10001
WORKDIR /var/lib/thunderbolt
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=4 \
    CMD ["/usr/local/bin/thunderbolt-cli", "--config", "/etc/bitcoin-thunderbolt/thunderbolt.toml", "health"]

ENTRYPOINT ["/usr/local/bin/thunderboltd"]
CMD ["--config", "/etc/bitcoin-thunderbolt/thunderbolt.toml", "start"]

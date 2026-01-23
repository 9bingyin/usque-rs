FROM rust:1.93 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    cmake \
    git \
    libclang-dev \
    pkg-config \
    perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM bitnami/minideb:latest

RUN install_packages ca-certificates curl

WORKDIR /app

COPY --from=builder /app/target/release/usque-rs /usr/local/bin/
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

EXPOSE 1080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/healthcheck.sh"]

ENTRYPOINT ["/entrypoint.sh"]

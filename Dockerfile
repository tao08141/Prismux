FROM rust:slim-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --create-home prismux

WORKDIR /app
COPY --from=builder /build/target/release/prismux /usr/local/bin/prismux
COPY examples /app/examples
RUN cp /app/examples/basic.yaml /app/config.yaml \
    && chown -R prismux:prismux /app

USER prismux

ENTRYPOINT ["prismux"]
CMD ["-c", "/app/config.yaml"]

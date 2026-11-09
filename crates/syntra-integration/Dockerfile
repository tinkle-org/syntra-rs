FROM rust:1.89-bookworm AS builder
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p syntra-integration --bin peer
FROM debian:bookworm-slim
COPY --from=builder /work/target/release/peer /usr/local/bin/peer
EXPOSE 7001 7002
ENTRYPOINT ["/usr/local/bin/peer"]

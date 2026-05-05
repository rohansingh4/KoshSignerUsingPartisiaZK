FROM rust:1.82-slim AS builder
RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY backend/ backend/
COPY contracts/ contracts/
COPY services/kosh-chain-relay/ services/kosh-chain-relay/
COPY services/kosh-keystore/ services/kosh-keystore/
COPY services/kosh-pqc/ services/kosh-pqc/
COPY services/proto/ services/proto/
RUN cargo build --release -p kosh-keystore

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/kosh-keystore /kosh-keystore
EXPOSE 50070
ENTRYPOINT ["/kosh-keystore"]

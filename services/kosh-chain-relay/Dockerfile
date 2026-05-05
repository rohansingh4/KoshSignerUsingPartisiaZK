FROM rust:1.82-slim AS builder
RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
# Copy workspace Cargo files
COPY Cargo.toml Cargo.lock ./
# Copy all crates so workspace resolves
COPY backend/ backend/
COPY contracts/ contracts/
COPY services/kosh-chain-relay/ services/kosh-chain-relay/
COPY services/kosh-keystore/ services/kosh-keystore/
COPY services/kosh-pqc/ services/kosh-pqc/
COPY services/proto/ services/proto/
RUN cargo build --release -p kosh-chain-relay

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/kosh-chain-relay /kosh-chain-relay
EXPOSE 50053
ENTRYPOINT ["/kosh-chain-relay"]

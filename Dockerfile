# ─── Build stage ───
FROM rust:latest AS builder

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true

# Build actual source
COPY . .
RUN cargo build --release

# ─── Runtime stage ───
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/lurk-key-system .

ENV PORT=10000
EXPOSE 10000

CMD ["./lurk-key-system"]

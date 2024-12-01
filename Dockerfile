FROM rust:1.82.0 as cargo-build

WORKDIR /usr/src/onetun
COPY Cargo.toml Cargo.toml

# Placeholder to download dependencies and cache them using layering
RUN mkdir src/
RUN touch src/lib.rs
RUN echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs
RUN cargo build --release
RUN rm -f target/x86_64-unknown-linux-musl/release/deps/myapp*

# Build the actual project
COPY . .
RUN cargo build --release

FROM debian:11-slim
RUN apt-get update \
    && apt-get install dumb-init -y \
    && rm -rf /var/lib/apt/lists/*

COPY --from=cargo-build /usr/src/onetun/target/release/onetun /usr/local/bin/onetun

# Run as non-root
USER 1000

ENTRYPOINT ["dumb-init", "/usr/local/bin/onetun"]

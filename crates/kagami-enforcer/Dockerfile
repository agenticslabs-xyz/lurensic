# kagami-enforcer as a small container. Build from the repository root.
#
#   docker build -f crates/kagami-enforcer/Dockerfile -t kagami-enforcer .
#   docker run --rm -e CLOUDFLARE_API_TOKEN -e CLOUDFLARE_ACCOUNT_ID -e KAGAMI_CLOUDFLARE_LIST_ID \
#     -v /var/lib/myapp:/data:ro kagami-enforcer cloudflare sync --from /data/contained.json --watch 30

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p kagami-enforcer

# Distroless, no shell, runs as an unprivileged user.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/kagami-enforcer /usr/local/bin/kagami-enforcer
USER nonroot
ENTRYPOINT ["/usr/local/bin/kagami-enforcer"]

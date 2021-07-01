# Build container
FROM clux/muslrust:latest AS builder
WORKDIR /volume
ADD . /volume/
RUN cargo build --release

# Main container
FROM alpine:3
LABEL maintainer="Alexander Verhaar <averhaar@schubergphilis.com>"

RUN mkdir /opt/socks5-proxy
COPY --from=builder /volume/target/x86_64-unknown-linux-musl/release/socks5-proxy /opt/socks5-proxy/socks5-proxy
COPY socks5.conf /opt/socks5-proxy/socks5.conf

EXPOSE 1080

ENV CONFIG /opt/socks5-proxy/socks5.conf
ENV RUST_LOG info

ENTRYPOINT ["/opt/socks5-proxy/socks5-proxy"]
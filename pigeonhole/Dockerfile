# pigeonhole -- PidgeIoT MQTT broker. Build from the REPO ROOT context
# (cargo needs the whole workspace's manifests to resolve `-p pigeonhole`):
#
#   docker build -f pigeonhole/Dockerfile -t pigeonhole .
#
# This path is documentation-grade, for developers self-hosting the bridge.
# Production is the bare binary under infra/pigeonhole.service. See
# docs/infra/mqtt-broker.md.

FROM rust:1-trixie AS build
WORKDIR /src
COPY . .
RUN cargo build -p pigeonhole --release

FROM debian:trixie-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends libssl3t64 ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  # Check at image build time that this OpenSSL lists the constrained-device
  # PSK suites the broker is configured for. A silently PSK-less build would
  # refuse every PSK device at handshake instead.
  #
  # Worth knowing what this does and does not prove: it proves the suites are
  # in the library's cipher table, not that a handshake will negotiate one.
  # On some builds PSK-AES128-CCM8 lists here and still cannot be negotiated
  # by an OpenSSL peer at all; the real CCM8 client is mbedTLS on the device,
  # so CCM8 is verified there rather than here.
  && openssl ciphers 'PSK-AES128-CCM8:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256' \
     | grep -q PSK-AES128-CCM8 \
  && useradd --system --no-create-home pigeonhole
COPY --from=build /src/target/release/pigeonhole /usr/local/bin/pigeonhole
USER pigeonhole
# One TLS listener. There is no port 1883 in any deployment shape.
EXPOSE 8883/tcp
ENTRYPOINT ["/usr/local/bin/pigeonhole"]

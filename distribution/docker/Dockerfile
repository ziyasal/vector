#-------------------------------------------------------------------------------
# Declare the base images that are used in this Dockerfile
ARG ALPINE_IMAGE=alpine:3.15.4
ARG DEBIAN_IMAGE=debian:bullseye-slim
ARG DISTROLESS_CC_IMAGE=gcr.io/distroless/cc-debian11
ARG DISTROLESS_STATIC_IMAGE=gcr.io/distroless/static-debian11

#-------------------------------------------------------------------------------
# Start a new stage for staging
FROM ${ALPINE_IMAGE} AS staging

# Set a well-known working directory for staging
WORKDIR /staging

# Prepare a staging root filesystem
RUN mkdir -p \
  rootfs/etc/vector \
  rootfs/usr/bin \
  rootfs/var/lib/vector

#-------------------------------------------------------------------------------
# Start a new stage for GNU libc staging
FROM staging AS staging-gnu

COPY debian.docker-entrypoint.sh rootfs/usr/bin/docker-entrypoint.sh
# Copy and unpack Vector distribution
COPY vector-*-unknown-linux-gnu*.tar.gz .
RUN mkdir vector \
  && tar zxvf vector-*-"$(cat /etc/apk/arch)"-unknown-linux-gnu*.tar.gz \
    -C vector --strip-components=2

# Prepare Vector in the staging root filesystem
RUN cp vector/bin/* rootfs/usr/bin/ \
  && cp vector/config/vector.toml rootfs/etc/vector/vector.toml

#-------------------------------------------------------------------------------
# Start a new stage for musl staging
FROM staging AS staging-musl

COPY alpine.docker-entrypoint.sh rootfs/usr/bin/docker-entrypoint.sh
# Copy and unpack Vector distribution
COPY vector-*-unknown-linux-musl*.tar.gz .
RUN mkdir vector \
  && tar zxvf vector-*-"$(cat /etc/apk/arch)"-unknown-linux-musl*.tar.gz \
    -C vector --strip-components=2

# Prepare Vector in the staging root filesystem
RUN cp vector/bin/* rootfs/usr/bin/ \
  && cp vector/config/vector.toml rootfs/etc/vector/vector.toml

#-------------------------------------------------------------------------------
# Start a new stage for the debian variant
FROM ${DEBIAN_IMAGE} AS debian

# Set image labels
ARG VECTOR_VERSION
LABEL org.opencontainers.image.source="https://github.com/vectordotdev/vector" \
  org.opencontainers.image.title="Vector (Debian variant)" \
  org.opencontainers.image.url="https://vector.dev/" \
  org.opencontainers.image.version="${VECTOR_VERSION}"

# Copy root filesystem from GNU libc staging
COPY --from=staging-gnu /staging/rootfs/ /

RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    gosu \
    tzdata \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system \
    --shell /sbin/nologin \
    --user-group vector

# Configure the image entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["vector"]

#-------------------------------------------------------------------------------
# Start a new stage for the distroless-libc variant
FROM ${DISTROLESS_CC_IMAGE} AS distroless-libc

# Set image labels
ARG VECTOR_VERSION
LABEL org.opencontainers.image.source="https://github.com/vectordotdev/vector" \
  org.opencontainers.image.title="Vector (Distroless variant)" \
  org.opencontainers.image.url="https://vector.dev/" \
  org.opencontainers.image.version="${VECTOR_VERSION}"

# Copy root filesystem from GNU libc staging
COPY --from=staging-gnu /staging/rootfs/ /

# Configure the image entrypoint
ENTRYPOINT ["vector"]

#-------------------------------------------------------------------------------
# Start a new stage for the alpine variant
FROM ${ALPINE_IMAGE} AS alpine

# Set image labels
ARG VECTOR_VERSION
LABEL org.opencontainers.image.source="https://github.com/vectordotdev/vector" \
  org.opencontainers.image.title="Vector (Alpine variant)" \
  org.opencontainers.image.url="https://vector.dev/" \
  org.opencontainers.image.version="${VECTOR_VERSION}"

# Copy root filesystem from musl staging
COPY --from=staging-musl /staging/rootfs/ /

RUN apk update && apk --no-cache add \
  ca-certificates \
  su-exec \
  tzdata \
  && addgroup -S vector \
  && adduser -S -H \
  -s /sbin/nologin \
  -G vector vector \
  && chown vector /etc/vector /var/lib/vector

# Configure the image entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["vector"]

#-------------------------------------------------------------------------------
# Start a new stage for the distroless-static variant
FROM ${DISTROLESS_STATIC_IMAGE} AS distroless-static

# Set image labels
ARG VECTOR_VERSION
LABEL org.opencontainers.image.source="https://github.com/vectordotdev/vector" \
  org.opencontainers.image.title="Vector (Distroless static variant)" \
  org.opencontainers.image.url="https://vector.dev/" \
  org.opencontainers.image.version="${VECTOR_VERSION}"

# Copy root filesystem from musl staging
COPY --from=staging-musl /staging/rootfs/ /

# Configure the image entrypoint
ENTRYPOINT ["vector"]

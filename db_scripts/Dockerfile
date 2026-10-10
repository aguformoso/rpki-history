ARG PY_VERSION=3.14
ARG RPKI_CLIENT_VERSION=9.9

FROM python:${PY_VERSION}-alpine AS build
ARG RPKI_CLIENT_VERSION

RUN apk update \
    && apk add build-base libpq-dev musl-fts-dev signify libretls-dev openssl-dev expat-dev zlib-dev rsync

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

# Adapted from https://github.com/rpki-client/rpki-client-container/blob/master/Dockerfile
COPY rpki-client.pub /
RUN set -x && \
  wget "https://ftp.openbsd.org/pub/OpenBSD/rpki-client/rpki-client-${RPKI_CLIENT_VERSION}.tar.gz" && \
  wget https://ftp.openbsd.org/pub/OpenBSD/rpki-client/SHA256.sig && \
  signify -C -p rpki-client.pub -x SHA256.sig "rpki-client-${RPKI_CLIENT_VERSION}.tar.gz" && \
  tar xfz "rpki-client-${RPKI_CLIENT_VERSION}.tar.gz" && \
  cd "rpki-client-${RPKI_CLIENT_VERSION}/"; \
  ./configure \
    --prefix=/usr \
    --with-user=rpki-client \
    --with-tal-dir=/etc/tals \
    --with-base-dir=/var/cache/rpki-client \
    --with-output-dir=/var/lib/rpki-client && \
  make && \
  make install-strip INSTALL='install -p'

FROM python:${PY_VERSION}-alpine AS final
ARG RPKI_CLIENT_VERSION
ARG PY_VERSION

RUN apk update \
    && apk upgrade \
    && apk add --no-cache libpq expat libretls musl-fts tar zstd jq

COPY --from=build "/usr/local/lib/python${PY_VERSION}/site-packages/" "/usr/local/lib/python${PY_VERSION}/site-packages/"
COPY --from=build "rpki-client-${RPKI_CLIENT_VERSION}/src/rpki-client" /usr/sbin/
COPY --from=build /etc/tals/ /etc/tals/

# rpki-client
RUN set -x && \
  addgroup -g 900 -S rpki-client && \
  adduser -h /var/lib/rpki-client -G rpki-client -S -D -u 900 rpki-client && \
  mkdir -p /var/cache/rpki-client /var/lib/rpki-client

WORKDIR /app

COPY rpki-history-db.py ./

ENTRYPOINT [ "python", "rpki-history-db.py"]
ARG PY_VERSION=3.14
FROM python:${PY_VERSION}-alpine AS build

RUN apk update \
    && apk add build-base libpq-dev

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

FROM python:${PY_VERSION}-alpine AS final
ARG PY_VERSION

RUN apk update \
    && apk upgrade \
    && apk add --no-cache libpq

WORKDIR /app

RUN addgroup -S rpki \
    && adduser -G rpki -S -H rpki

COPY . ./
# Make static files read-only for API user.
RUN chmod 500 html/ \
    && chmod 400 html/* \
    && chown -R rpki:rpki html/

COPY --from=build "/usr/local/lib/python${PY_VERSION}/site-packages/" "/usr/local/lib/python${PY_VERSION}/site-packages/"
COPY --from=build /usr/local/bin/gunicorn /usr/local/bin/gunicorn

USER rpki:rpki

EXPOSE 8000
CMD [ "gunicorn", "--no-control-socket", "-b", "0.0.0.0:8000", "rpki-history-api"]
FROM aquasec/trivy:0.76.1 AS trivy

FROM python:3.14-alpine3.22

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN addgroup -g 10001 watcher \
    && adduser -D -H -u 10001 -G watcher watcher \
    && mkdir -p /data \
    && chown 10001:10001 /data

WORKDIR /app
COPY watcher.py .

USER 10001:10001
ENV DATA_DIR=/data \
    TMPDIR=/data/tmp \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "-u", "/app/watcher.py"]

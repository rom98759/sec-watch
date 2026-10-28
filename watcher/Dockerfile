FROM aquasec/trivy:0.76.1 AS trivy

FROM python:3.14-alpine3.23

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# watcher.py is stdlib only: pip and its vendored packages are dead weight with their own CVEs
RUN python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.14/ensurepip \
    && addgroup -g 10001 watcher \
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

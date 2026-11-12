# Secure look-alike of the Dockerfile: pinned digest, non-root, no baked secrets.
FROM python:3.12.4-slim@sha256:2b0e5a4aa2b0d1d6d0d5c1a0e4c8f9b8f0c1e2d3a4b5c6d7e8f9a0b1c2d3e4f5

ENV APP_HOME=/srv/app
WORKDIR $APP_HOME

COPY --chown=10001:10001 . $APP_HOME

# A dedicated unprivileged user; no capabilities added.
USER 10001:10001

CMD ["python", "-m", "app"]

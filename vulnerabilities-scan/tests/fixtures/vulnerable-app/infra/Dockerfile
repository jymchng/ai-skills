# Intentionally insecure Dockerfile for the fixture.
FROM ubuntu:latest

# docker-secret-env: a credential baked into the image environment
ENV DATABASE_PASSWORD=examplefabricatedpassword

RUN apt-get update && apt-get install -y curl

# docker-privileged: a privileged build step
RUN --privileged mount /dev/sda1 /mnt

# docker-latest-tag: fetched remote ADD instead of a copied, verified artefact
ADD https://example.invalid/tool.tar.gz /opt/tool.tar.gz

# docker-root-user: the container runs as root
USER root

CMD ["/opt/start.sh"]

FROM python:3.12-slim

LABEL maintainer="team@voidly.ai"
LABEL description="Voidly Community Probe — Help measure internet censorship"
LABEL org.opencontainers.image.source="https://github.com/voidly-ai/community-probe"

WORKDIR /app

# Copy full package
COPY setup.py .
COPY README.md .
COPY voidly_probe.py .

# Install the package so voidly-probe CLI works
RUN pip install --no-cache-dir .

# Persist config (node ID + token) across container restarts
# Mount this volume: docker run -v voidly-data:/data/.voidly ...
ENV VOIDLY_CONFIG_DIR=/data/.voidly
VOLUME ["/data/.voidly"]

HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
  CMD test -f /data/.voidly/node.json || exit 1

ENTRYPOINT ["voidly-probe"]
CMD ["--consent"]

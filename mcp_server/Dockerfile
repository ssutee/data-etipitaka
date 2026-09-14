FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY etipitaka_mcp ./etipitaka_mcp
RUN pip install --no-cache-dir .

# Runs the remote (streamable-http) resource server; compose supplies the
# ETIPITAKA_* environment. Local stdio use never touches this image.
ENV ETIPITAKA_TRANSPORT=http
EXPOSE 8001
CMD ["etipitaka-mcp"]

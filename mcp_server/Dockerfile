FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN groupadd -r app && useradd -r -g app app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml ./
COPY etipitaka_mcp ./etipitaka_mcp
RUN pip install --no-cache-dir --no-deps .

USER app

# Runs the remote (streamable-http) resource server; compose supplies the
# ETIPITAKA_* environment. Local stdio use never touches this image.
ENV ETIPITAKA_TRANSPORT=http
EXPOSE 8001
CMD ["etipitaka-mcp"]

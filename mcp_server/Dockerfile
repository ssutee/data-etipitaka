FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN groupadd -r app && useradd -r -g app app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml ./
COPY etipitaka_mcp ./etipitaka_mcp
# --no-deps: only the packages already pinned in requirements.txt get
# installed. Keep requirements.txt in sync with the dependencies list in
# pyproject.toml -- --no-deps will not catch a dependency added to one but
# not the other; the image still builds fine and fails at runtime instead,
# with an ImportError.
RUN pip install --no-cache-dir --no-deps .

USER app

# Runs the remote (streamable-http) resource server; compose supplies the
# ETIPITAKA_* environment. Local stdio use never touches this image.
ENV ETIPITAKA_TRANSPORT=http
EXPOSE 8001
CMD ["etipitaka-mcp"]

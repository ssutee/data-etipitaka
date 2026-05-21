#!/bin/sh
# Server-side deploy script. Run on the production server, from the repo root,
# after `git pull`. CI invokes it over SSH; it is also safe to run by hand.
set -e

# Production runs Docker Compose v1 (`docker-compose`); dev/CI run v2
# (`docker compose`). Detect whichever is available.
if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    echo "[deploy] no Docker Compose found" >&2
    exit 1
fi
echo "[deploy] using: $DC"

$DC up -d --build
$DC run --rm web python manage.py migrate --noinput
$DC run --rm web python manage.py collectstatic --noinput

sleep 5
if curl -fsS -o /dev/null http://localhost:1338/; then
    echo "[deploy] health check passed"
else
    echo "[deploy] health check FAILED" >&2
    exit 1
fi
echo "[deploy] done"

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

# Build the nginx image and validate its config before rolling it out --
# `up -d --build` below would otherwise recreate the currently-running
# nginx container straight from a possibly-broken config and take the site
# down. No --no-deps: nginx.conf's upstream blocks name the `web` and `mcp`
# services, and nginx resolves those hostnames at config-parse time (even
# for `-t`), not lazily -- with --no-deps, a first deploy or a check run
# after `docker compose down` would find neither container's name in
# Docker's embedded DNS and fail with "host not found in upstream", which
# looks exactly like a broken config but isn't one. Letting `run` start its
# declared dependencies first (the default) keeps the names resolvable.
$DC build nginx
if $DC run --rm nginx nginx -t; then
    echo "[deploy] nginx config check passed"
else
    echo "[deploy] nginx config check FAILED" >&2
    exit 1
fi

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
if curl -fsS http://localhost:1338/.well-known/apple-app-site-association | grep -q '"webcredentials"'; then
    echo "[deploy] passkey association check passed"
else
    echo "[deploy] passkey association check FAILED" >&2
    exit 1
fi
# The check above only proves this container serves the file; it says
# nothing about whether the host-level TLS terminator in front of it (see
# docs/remote-mcp-oauth-deploy.md) actually routes this path -- that is the
# failure that breaks iOS in practice. Best-effort and non-fatal: a deploy
# run somewhere without public DNS/TLS for the production host (a staging
# box, a sandbox) should not fail here, but the operator must be able to
# tell a real routing problem apart from an environment that never had
# public access to begin with.
if curl -fsS https://data.etipitaka.com/.well-known/apple-app-site-association \
        | grep -q '"webcredentials"'; then
    echo "[deploy] public passkey association check passed"
else
    echo "[deploy] public passkey association check skipped or FAILED (non-fatal --" \
         "verify the host TLS terminator routes /.well-known/apple-app-site-association)" >&2
fi
echo "[deploy] done"

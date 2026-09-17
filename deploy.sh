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

# Build the web image and run Django's system checks against it FIRST,
# before anything below ever runs `docker compose run --rm nginx ...` --
# otherwise `up -d --build` recreates the currently-running web container
# straight from a possibly-broken config (e.g. a bad
# PASSKEY_ANDROID_CERT_SHA256) and takes passkey ceremonies down:
# login/begin still 200s (it never touches the Android config), but
# login/finish, register/finish, signup/finish and recover/finish all raise
# a raw ValueError -> 500, and /.well-known/assetlinks.json 404s. `migrate`
# further down does run system checks too, but only *after* the bad image
# is already live. See user_data/checks.py.
#
# This has to come before the nginx block, not just before `up -d --build`:
# nginx's `depends_on: web: condition: service_started` means the nginx
# preflight run below (needed to resolve nginx.conf's upstream hostnames --
# see its own comment) will itself recreate web-1 from whatever `.env` /
# image is current if compose considers its config stale, as a side effect
# of satisfying that dependency -- independently of `up -d --build`.
# Measured: editing .env to add a bad PASSKEY_ANDROID_CERT_SHA256 and then
# running only `$DC run --rm nginx nginx -t` recreated the live web-1
# container with that bad env. So the only way to guarantee a bad config
# never goes live is to fail before the nginx block runs at all.
$DC build web
if $DC run --rm web python manage.py check; then
    echo "[deploy] django config check passed"
else
    echo "[deploy] django config check FAILED" >&2
    exit 1
fi

# Build the nginx image and validate its config before rolling it out --
# `up -d --build` below would otherwise recreate the currently-running
# nginx container straight from a possibly-broken config and take the site
# down. No --no-deps: nginx.conf's upstream blocks name the `web` and `mcp`
# services, and nginx resolves those hostnames at config-parse time (even
# for `-t`), not lazily -- with --no-deps, a first deploy or a check run
# after `docker compose down` would find neither container's name in
# Docker's embedded DNS and fail with "host not found in upstream", which
# looks exactly like a broken config but isn't one. Letting `run` start its
# declared dependencies first (the default) keeps the names resolvable --
# by this point the web config it may recreate has already passed the
# Django check above.
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

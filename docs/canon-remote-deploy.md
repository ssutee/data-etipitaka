# Deploying the canon databases (remote canon search)

The public `/api/canon/*` endpoints read the canon edition / dictionary SQLite
files from `settings.CANON_RESOURCES_DIR`. In production that directory is a
bind mount holding the ~1.4 GB of `.sqlite` files (17 files). They are **not**
in git and are **not** shipped by `git pull` — you transfer them once, out of
band, and point the container at them via a **gitignored** override so the
tracked config (and `git pull --ff-only`) stays untouched.

## 1. Upload the SQLite files (one-time, ~1.4 GB)

From the developer Mac, copy only the `.sqlite` files to a directory on the
prod host (example: `/srv/etipitaka/canon`):

```bash
ssh <user>@<prod-host> 'mkdir -p /srv/etipitaka/canon'
rsync -avz --progress \
  --include='*.sqlite' --exclude='*' \
  /Users/sutee/Works/watnapahpong/E-Tipitaka-PC/resources/ \
  <user>@<prod-host>:/srv/etipitaka/canon/
```

Re-run the same command later to update editions; `rsync` sends only changes.

## 2. Point the container at them (prod-side override)

On the prod host, in the repo root, create `docker-compose.override.yml`
(gitignored, so `git pull` never touches it). Compose auto-merges it on
`up -d` (both v1 `docker-compose` and v2 `docker compose`):

```yaml
services:
  web:
    environment:
      CANON_RESOURCES_DIR: /canon
    volumes:
      - /srv/etipitaka/canon:/canon:ro
```

The mount is read-only (`:ro`) — the endpoints open every file immutable /
read-only, so the canon data can never be mutated through the app.

## 3. Deploy and verify

```bash
git pull --ff-only && ./deploy.sh
```

Then check the editions report the files as present:

```bash
curl -fsS https://data.etipitaka.com/api/canon/editions/
```

Each uploaded edition/dictionary should show `"present": true`. A quick search:

```bash
curl -fsS 'https://data.etipitaka.com/api/canon/search/?edition=thaiwn&query=อานาปานสติ&limit=3'
```

## Notes

- If `CANON_RESOURCES_DIR` is unset it defaults to `media/canon`; a search
  against an edition whose file is absent returns HTTP 503 ("edition not
  available on server"), never a crash.
- The endpoints are public (no auth) by design — canon is public scripture.
- `search` is a `content LIKE` substring scan over large files; the per-request
  `limit` is clamped to 200. Consider a CDN / cache or FTS5 if load grows.

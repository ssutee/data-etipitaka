# GitHub Migration + CI/CD Auto-Deploy — Design

**Date:** 2026-05-21
**Project:** data-etipitaka — E-Tipitaka-Plus Account backend
**Goal:** Move the repository from GitLab to GitHub, and add a GitHub Actions pipeline that auto-deploys `master` to the production server after tests pass and a manual approval.

## Summary

The repo currently lives on GitLab (`origin` = `git@gitlab.com:sutee-docker-projects/data-etipitaka.git`) and has a GitHub Actions workflow (`.github/workflows/ci.yml`) running two test jobs. This project moves the canonical repo to GitHub and adds a third job that deploys to production over SSH.

Production is a single server (the `128.199.181.198` / `data.etipitaka.com` droplet) running the app via Docker Compose. Deploy = SSH in, `git pull`, run a committed `deploy.sh`. A push to `master` runs the test jobs; if they pass, the deploy job waits for a one-click manual approval, then deploys.

## Decisions (locked)

| Topic | Decision |
|---|---|
| Production hosting | Plain server (droplet), Docker Compose, SSH access |
| Build location | On the server (`docker compose up -d --build`) — no registry |
| Deploy trigger | Push to `master` → tests → **manual approval** (GitHub Environment) → deploy |
| Deploy mechanism | Raw `ssh` from CI runs a committed `deploy.sh` on the server |
| GitHub CLI | `gh` 2.92 installed, authenticated as `ssutee` (`repo`+`workflow` scopes) — used to script repo/secrets/environment setup |
| Compose on prod | Production runs Docker Compose **v1** (`docker-compose`); `deploy.sh` auto-detects v1 vs v2 |

## Section 1 — Repo migration (GitLab → GitHub)

1. **Create the GitHub repo:** `gh repo create ssutee/data-etipitaka --private`.
2. **Re-point local remotes:** rename the current `origin` → `gitlab` (kept as a cold backup), add GitHub as the new `origin`, then `git push -u origin master`. Only `master` exists — the Django-migration feature branch was already merged and deleted.
3. **GitLab repo:** left intact as a backup. Deleted later, manually, when the user is confident.
4. **Production server's clone:** its `origin` still points at GitLab; it is switched to GitHub during the one-time server setup (Section 4).

`gh`'s `repo` and `workflow` scopes also allow scripting the GitHub Secrets and the approval Environment (Sections 3 and 6), minimising manual clicking.

## Section 2 — CI/CD pipeline structure

Extend `.github/workflows/ci.yml` with a third job:

```
push to master ──► unit-tests ─┐
                                ├──► deploy  (needs both, gated)
                   golden-harness ┘
```

- **`unit-tests`** — existing (pytest + coverage gate).
- **`golden-harness`** — existing (golden + behavioral suites, Dockerised).
- **`deploy`** — new:
  - `needs: [unit-tests, golden-harness]` — runs only if both pass.
  - `if: github.event_name == 'push' && github.ref == 'refs/heads/master'` — never on pull requests or other branches.
  - `environment: production` — binds the job to a GitHub Environment with a required-reviewer protection rule. The job parks at "Waiting" until a reviewer clicks **Approve** in the Actions UI.
  - Steps: configure the SSH key, then `ssh` to the server to run the deploy.

Pull requests run both test jobs and never deploy. A push to `master` runs the tests, waits for approval, then deploys.

## Section 3 — SSH deploy mechanics and `deploy.sh`

### Authentication

A dedicated deploy keypair (ed25519), separate from any personal key:

- private key → GitHub Secret `DEPLOY_SSH_KEY`
- public key → appended to the server deploy user's `~/.ssh/authorized_keys`
- server host and SSH user → secrets `DEPLOY_HOST`, `DEPLOY_USER`

### Deploy job step

Raw `ssh` — no third-party marketplace action (avoids handing the production SSH key to an external action):

```sh
mkdir -p ~/.ssh
echo "$DEPLOY_SSH_KEY" > ~/.ssh/deploy_key
chmod 600 ~/.ssh/deploy_key
ssh-keyscan -H "$DEPLOY_HOST" >> ~/.ssh/known_hosts
ssh -i ~/.ssh/deploy_key "$DEPLOY_USER@$DEPLOY_HOST" \
  'cd /srv/data-etipitaka && git pull --ff-only && ./deploy.sh'
```

### `deploy.sh` (committed to the repo root, runs on the server)

```sh
#!/bin/sh
set -e

# Production runs Docker Compose v1; dev/CI run v2. Detect which exists.
if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    echo "[deploy] no Docker Compose found"; exit 1
fi

$DC up -d --build
$DC run --rm web python manage.py migrate --noinput
$DC run --rm web python manage.py collectstatic --noinput

sleep 5
if curl -fsS -o /dev/null http://localhost:1338/; then
    echo "[deploy] healthy"
else
    echo "[deploy] health check FAILED"
    exit 1
fi
```

`$DC run --rm web` relies on `entrypoint.sh`'s Postgres-wait, so `migrate` is race-safe against a still-starting database. A failed health check exits non-zero, which fails the GitHub job and surfaces the problem.

### Rollback

Manual, kept deliberately simple: SSH to the server, `git reset --hard <previous-sha>`, re-run `./deploy.sh`. No automatic rollback is built — flagged here as an accepted limitation.

## Section 4 — One-time server prerequisites

Before auto-deploy works, the production server needs the following (one-time, manual — to be captured as a checklist in the implementation plan):

1. **Repo clone** at a fixed path (`/srv/data-etipitaka`). The existing production checkout's remote is switched from GitLab to GitHub (`git remote set-url origin <github-url>`), or it is fresh-cloned there.
2. **Server → GitHub read access.** The repo is private, so the server must authenticate to pull it. Generate a keypair on the server; add its public key to the GitHub repo as a **read-only Deploy Key**. The server can then `git pull`.
3. **Deploy user.** The SSH account CI logs in as. It must be in the `docker` group and own the repo directory. The CI deploy *public* key (Section 3) is added to its `~/.ssh/authorized_keys`.
4. **`.env` / `.env.db`.** Already present on the server with production secrets. Untouched by deploys.
5. **Docker + Docker Compose.** Already present (production runs via Compose v1).

Two distinct keypairs are involved:
- **CI → server:** CI holds the private key; the server's `authorized_keys` holds the public key.
- **Server → GitHub:** the server holds the private key; the GitHub repo's Deploy Key holds the public key.

## Section 5 — First-deploy cutover (one-time, manual — NOT automated)

Production currently runs the **old Python 2 / Django 1.9 stack on PostgreSQL 12**. The migrated `master` requires PostgreSQL 16. Therefore the *first* production deploy of this code is a cutover, not a routine deploy, and the pipeline must not attempt it.

`deploy.sh` runs `docker compose up -d --build`, and `docker-compose.yml` pins `postgres:16-alpine` — a PG16 server will not start on the existing PG12 data volume. Auto-deploy would fail until the database is upgraded.

**The cutover — performed by hand, in a maintenance window, once:**

1. Maintenance window and a verified database backup.
2. Server setup from Section 4 (repo → GitHub remote, deploy keys, deploy user).
3. Run `docs/runbooks/postgres-12-to-16-upgrade.md` — dump PG12 → wipe the volume → start PG16 → restore.
4. `docker compose up -d --build`, `migrate`, `collectstatic`.
5. Verify the site.

After the cutover, the server runs the migrated stack on PG16, and routine pushes to `master` auto-deploy normally.

**Rule:** the PostgreSQL upgrade stays manual / runbook-driven — it is never folded into `deploy.sh`. Routine auto-deploy assumes PG16 is already running.

**Cutover risk:** production's Docker Compose v1 may reject the version-less `docker-compose.yml` (the `version:` key was removed during the Django migration for Compose v2). If so, at cutover time either re-add a `version:` key to the file or upgrade the server's Compose. Decided at cutover; not pre-emptively changed.

## Section 6 — Secrets and settings inventory

**GitHub Secrets** (set via `gh secret set`):

| Secret | Purpose |
|---|---|
| `DEPLOY_SSH_KEY` | private SSH key — CI authenticates to the production server |
| `DEPLOY_HOST` | production server IP / hostname |
| `DEPLOY_USER` | SSH login user on the server |

`DEPLOY_PATH` (`/srv/data-etipitaka`) is a plain repo **variable**, not a secret — it is not sensitive.

**GitHub Environment** — `production`, with a required-reviewer protection rule (the manual approval gate from Section 2). Created via `gh api`.

**Server-side** (not stored in GitHub):
- the CI deploy *public* key, in the deploy user's `~/.ssh/authorized_keys`
- the server → GitHub read key: private key on the server, public key added as the repo's read-only Deploy Key

The existing CI test jobs use the committed, non-secret `.env.ci` / `.env.db.ci` files — unchanged. Production's real `.env` / `.env.db` stay on the server and are never placed in GitHub.

## Out of scope

- Automatic rollback (rollback is a documented manual procedure).
- Upgrading the production server's Docker Compose to v2 (`deploy.sh` accommodates v1).
- Staging / pre-production environments — single production target only.
- Container registry / pushing built images — the server builds locally.

## Success criteria

1. The repository is on GitHub; `master` is pushed; CI runs there.
2. A push to `master` runs both test jobs; on success the `deploy` job waits for manual approval.
3. Approving the deploy SSHes into the server, pulls `master`, runs `deploy.sh`, and the health check passes.
4. A failed test job, or a failed health check, fails the pipeline and blocks/aborts the deploy.
5. The first production cutover (PG12→16 + migrated stack) is performed manually per the runbook; routine deploys are automatic thereafter.

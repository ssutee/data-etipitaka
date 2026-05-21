# Media Volume → Host Bind Mount Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Relocate production media (user uploads) from the Docker named volume `dataetipitaka_media_volume` to the host folder `~/data.etipitaka/media`, exposed via a bind mount.

**Architecture:** Swap the `media_volume` named volume for a `./media` bind mount in `docker-compose.yml`. Copy the existing 279 MB / 4326 files from the named volume to the host folder during a short maintenance window, chown them to the container's `app` user (uid 999), then recreate the `web` and `nginx` containers against the bind mount. The old named volume is kept untouched as rollback.

**Tech Stack:** Docker Compose v2, Django 5.2 web app, nginx, on the production server `data.etipitaka.com`.

**Reference spec:** `docs/superpowers/specs/2026-05-21-media-volume-to-host-design.md`

---

## Important context for the implementer

- This is an infrastructure change, not application code — there are no unit tests. Each task ends with an explicit **verification step** instead of a TDD cycle.
- Tasks 1 is done on the **developer machine** (repo edits). Tasks 2-4 are done on the **production server** over SSH and form a single maintenance window.
- The production repo lives at `~/data.etipitaka` on the server, checked out on branch `master`, remote `origin` = GitHub.
- The container's `app` user is **uid 999**. Existing media files are owned by **uid 100** (the retired old stack). The chown in Task 2 fixes this.
- Do NOT delete the named volume `dataetipitaka_media_volume` until Task 4 — it is the rollback path.
- SSH to the server: `ssh -i ~/.ssh/data_etipitaka_deploy sutee@data.etipitaka.com`.

---

## Task 1: Repo changes — bind mount + gitignore

**Files:**
- Modify: `docker-compose.yml`
- Modify: `.gitignore`

- [ ] **Step 1: Change the `web` service media mount**

In `docker-compose.yml`, the `web` service `volumes:` block currently reads:

```yaml
    volumes:
      - ./app:/home/app/web
      - static_volume:/home/app/web/static
      - media_volume:/home/app/web/media
```

Change the media line to a bind mount:

```yaml
    volumes:
      - ./app:/home/app/web
      - static_volume:/home/app/web/static
      - ./media:/home/app/web/media
```

- [ ] **Step 2: Change the `nginx` service media mount**

In `docker-compose.yml`, the `nginx` service `volumes:` block currently reads:

```yaml
    volumes:
      - static_volume:/home/app/web/static
      - media_volume:/home/app/web/media
```

Change the media line:

```yaml
    volumes:
      - static_volume:/home/app/web/static
      - ./media:/home/app/web/media
```

- [ ] **Step 3: Remove the `media_volume` top-level volume declaration**

In `docker-compose.yml`, the top-level `volumes:` block currently reads:

```yaml
volumes:
  postgres_data:
  static_volume:
  media_volume:
```

Remove the `media_volume:` line:

```yaml
volumes:
  postgres_data:
  static_volume:
```

- [ ] **Step 4: Add `media/` to `.gitignore`**

`.gitignore` currently reads:

```
*.pyc
*.pyo
~*
*.swp
static/
tests/golden/.venv/
.coverage
graphify-out/
```

Add `media/` after the `static/` line:

```
*.pyc
*.pyo
~*
*.swp
static/
media/
tests/golden/.venv/
.coverage
graphify-out/
```

- [ ] **Step 5: Verify the compose file is still valid**

Run: `docker compose -f docker-compose.yml config >/dev/null && echo OK`
Expected: `OK` (no YAML or schema errors). If `docker compose` is unavailable on the dev machine, skip — Task 2 Step 7 re-validates on the server.

- [ ] **Step 6: Commit and push**

```bash
git add docker-compose.yml .gitignore
git commit -m "feat: serve media from a host bind mount instead of a named volume"
git push origin master
```

---

## Task 2: Server cutover — copy data and switch

All steps run **on the production server**. SSH in first:
`ssh -i ~/.ssh/data_etipitaka_deploy sutee@data.etipitaka.com`, then `cd ~/data.etipitaka`.

- [ ] **Step 1: Record the current media volume size for later comparison**

Run: `docker run --rm -v dataetipitaka_media_volume:/m alpine sh -c 'du -sh /m && find /m -type f | wc -l'`
Expected: roughly `279M` and `4326` files. Note the exact numbers — Task 3 compares against them.

- [ ] **Step 2: Stop the app containers**

Run: `docker compose stop web nginx`
Expected: `web` and `nginx` stop; `db` keeps running. The site is now offline — the maintenance window has started.

- [ ] **Step 3: Create the host media folder**

Run: `mkdir -p ~/data.etipitaka/media`
Expected: no output. Verify with `ls -ld ~/data.etipitaka/media`.

- [ ] **Step 4: Copy the volume contents to the host folder**

Run:
```bash
docker run --rm \
  -v dataetipitaka_media_volume:/src \
  -v ~/data.etipitaka/media:/dst \
  alpine cp -a /src/. /dst/
```
Expected: no output, exit code 0. `cp -a` preserves attributes and copies the directory contents (the trailing `/.` copies contents, not the directory itself).

- [ ] **Step 5: Verify the copy is complete BEFORE switching**

Run: `du -sh ~/data.etipitaka/media && find ~/data.etipitaka/media -type f | wc -l`
Expected: size and file count match Step 1 (≈279M, 4326 files). **If they do not match, stop** — re-run Step 4; do not proceed.

- [ ] **Step 6: Fix ownership for the container's `app` user**

Run: `sudo chown -R 999:999 ~/data.etipitaka/media`
Expected: no output. Verify: `ls -ln ~/data.etipitaka/media | head -3` shows files owned by `999 999`. This lets the `app` user (uid 999) read existing media and write new uploads.

- [ ] **Step 7: Pull the new compose config and recreate the stack**

```bash
cd ~/data.etipitaka
git pull --ff-only origin master
docker compose up -d
```
Expected: `git pull` fast-forwards to the Task 1 commit. `docker compose up -d` recreates `web` and `nginx` (now bind-mounting `./media`); `db` stays. All three containers end up `running`.

- [ ] **Step 8: Confirm containers are healthy**

Run: `docker compose ps`
Expected: `dataetipitaka-web-1`, `dataetipitaka-nginx-1`, `dataetipitaka-db-1` all `running` / `Up`.

---

## Task 3: Verify media serving and uploads

All steps run on the production server (or from anywhere for the HTTP check).

- [ ] **Step 1: Confirm the site is up**

Run: `curl -sS -o /dev/null -w "%{http_code}\n" https://data.etipitaka.com/`
Expected: `200`.

- [ ] **Step 2: Confirm an existing media file is served**

Pick a real media file path from the folder:
Run: `find ~/data.etipitaka/media -type f | head -1`

Take the path after `media/` and request it through nginx (media is served under `/media/`):
Run: `curl -sS -o /dev/null -w "%{http_code}\n" "https://data.etipitaka.com/media/<relative-path>"`
Expected: `200`. This proves nginx serves files from the bind mount.

- [ ] **Step 3: Confirm the `app` user can write into the media folder**

Run:
```bash
docker compose exec -T web sh -c 'touch /home/app/web/media/.write_test && echo WRITE_OK && rm /home/app/web/media/.write_test'
```
Expected: `WRITE_OK`, no permission error. This proves the chown worked and new uploads will succeed.

- [ ] **Step 4: Confirm the file count is intact**

Run: `find ~/data.etipitaka/media -type f | wc -l`
Expected: matches Task 2 Step 1 (≈4326). The maintenance window can now end.

---

## Task 4: Remove the old named volume

Do this only after Task 3 fully passes and you are confident the bind mount works. Leave a gap (e.g. a day) if you want extra safety.

- [ ] **Step 1: Confirm nothing still references the old volume**

Run: `docker ps -a --filter volume=dataetipitaka_media_volume`
Expected: no containers listed. (The recreated `web`/`nginx` use the bind mount now.)

- [ ] **Step 2: Remove the old named volume**

Run: `docker volume rm dataetipitaka_media_volume`
Expected: prints `dataetipitaka_media_volume`. If it errors "volume is in use", a container still references it — investigate before forcing.

- [ ] **Step 3: Confirm removal**

Run: `docker volume ls | grep media`
Expected: only `etipitaka_media_volume` (the unrelated other project) remains; `dataetipitaka_media_volume` is gone.

---

## Rollback

If verification fails at any point in Task 2 or 3, before Task 4:

1. On the server: `cd ~/data.etipitaka && git revert --no-edit HEAD` (reverts the Task 1 commit), or manually restore the `media_volume` lines in `docker-compose.yml`.
2. `docker compose up -d` — the containers re-attach to `dataetipitaka_media_volume`, which still holds the original, untouched data.
3. The site returns to the pre-change state with no data loss.

---

## Self-review notes

- Spec "Changes → docker-compose.yml" → Task 1 Steps 1-3. Spec "Changes → .gitignore" → Task 1 Step 4.
- Spec "Cutover procedure" steps 1-5 → Task 2 Steps 2-7.
- Spec "Verification" → Task 3.
- Spec "Rollback" → Rollback section.
- The chown target `999:999` is consistent across the spec and Task 2 Step 6 / Task 3 Step 3.
- The volume name `dataetipitaka_media_volume` is used consistently in Tasks 2 and 4.
- No application code changes, so no unit tests — verification steps stand in, as noted in the context section.

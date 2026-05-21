# GitHub Migration + CI/CD Auto-Deploy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the repo from GitLab to GitHub and add a GitHub Actions job that deploys `master` to the production server over SSH after tests pass and a manual approval.

**Architecture:** Two code changes (a committed `deploy.sh`, a new `deploy` job in `.github/workflows/ci.yml`), then operator setup steps (GitHub repo, secrets, the approval Environment, one-time server prep) and a one-time manual production cutover.

**Tech Stack:** GitHub Actions, `gh` CLI 2.92 (authenticated as `ssutee`), SSH, Docker Compose, a POSIX `sh` deploy script.

**Spec:** `docs/superpowers/specs/2026-05-21-github-cicd-deploy-design.md`

---

## Who runs what

Tasks are tagged:
- **[code]** — repository changes; an engineer or agent can do these.
- **[operator]** — needs the user's GitHub account or SSH access to the production server. The user runs these (the commands are exact).

Order matters: do **[code]** Tasks 1–2 first, then **[operator]** Tasks 3–7 in sequence.

## File structure

```
deploy.sh                      NEW — server-side deploy script (committed, run on the server)
.github/workflows/ci.yml        MODIFY — add the `deploy` job
```

Everything else (repo creation, remotes, secrets, the Environment, server prep, the cutover) is operator action, not files.

---

## Task 1 [code]: Create `deploy.sh`

**Files:**
- Create: `deploy.sh`

- [ ] **Step 1: Create `deploy.sh`** with exactly this content:

```sh
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
```

- [ ] **Step 2: Make it executable and verify syntax**

Run:
```bash
chmod +x deploy.sh
sh -n deploy.sh && echo "SYNTAX_OK"
```
Expected: `SYNTAX_OK`. If `shellcheck` is installed, also run `shellcheck deploy.sh` and expect no errors.

- [ ] **Step 3: Commit**

```bash
git add deploy.sh
git commit -m "feat: server-side deploy script"
```

> Note: `git add` preserves the executable bit set in Step 2.

---

## Task 2 [code]: Add the `deploy` job to `ci.yml`

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the `deploy` job.** Add this job to the `jobs:` mapping in `.github/workflows/ci.yml`, after the existing `golden-harness` job (same indentation as `unit-tests` / `golden-harness`):

```yaml
  deploy:
    needs: [unit-tests, golden-harness]
    if: github.event_name == 'push' && github.ref == 'refs/heads/master'
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy to production over SSH
        env:
          DEPLOY_SSH_KEY: ${{ secrets.DEPLOY_SSH_KEY }}
          DEPLOY_HOST: ${{ secrets.DEPLOY_HOST }}
          DEPLOY_USER: ${{ secrets.DEPLOY_USER }}
          DEPLOY_PATH: ${{ vars.DEPLOY_PATH }}
        run: |
          mkdir -p ~/.ssh
          printf '%s\n' "$DEPLOY_SSH_KEY" > ~/.ssh/deploy_key
          chmod 600 ~/.ssh/deploy_key
          ssh-keyscan -H "$DEPLOY_HOST" >> ~/.ssh/known_hosts 2>/dev/null
          ssh -i ~/.ssh/deploy_key "$DEPLOY_USER@$DEPLOY_HOST" \
            "cd '$DEPLOY_PATH' && git pull --ff-only && ./deploy.sh"
```

- [ ] **Step 2: Validate the workflow YAML**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('YAML_OK')"
```
Expected: `YAML_OK`. (If `pyyaml` is unavailable, visually confirm the `deploy` job is correctly nested under `jobs:` with consistent indentation.)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add manual-approval production deploy job"
```

> The `deploy` job will not run successfully until Tasks 3–5 are done (repo on GitHub, secrets, the `production` environment, server prep). That is expected — committing it now is harmless; it only triggers on a push to `master` on GitHub.

---

## Task 3 [operator]: Create the GitHub repo and migrate remotes

Runs on the developer machine. Uses the authenticated `gh` CLI.

- [ ] **Step 1: Create the private GitHub repo**

```bash
gh repo create ssutee/data-etipitaka --private
```
Expected: confirms creation of `https://github.com/ssutee/data-etipitaka`.

- [ ] **Step 2: Re-point the git remotes**

```bash
cd /Volumes/SeagateBackup/Works/watnapahpong/data-etipitaka
git remote rename origin gitlab
git remote add origin git@github.com:ssutee/data-etipitaka.git
git remote -v
```
Expected: `gitlab` points at the old GitLab URL; `origin` points at the new GitHub URL.

- [ ] **Step 3: Push `master` to GitHub**

```bash
git push -u origin master
```
Expected: `master` appears on GitHub; the local `master` tracks `origin/master`.

- [ ] **Step 4: Confirm**

```bash
gh repo view ssutee/data-etipitaka --json name,visibility,defaultBranchRef
```
Expected: name `data-etipitaka`, visibility `PRIVATE`, default branch `master`.

> The GitLab repo is left untouched as a backup. Delete it later, manually, once the GitHub setup is proven.

---

## Task 4 [operator]: Deploy keypair, GitHub Secrets, repo variable, Environment

Runs on the developer machine. You need the production server's IP/hostname and the SSH username CI will log in as.

- [ ] **Step 1: Generate a dedicated deploy keypair**

```bash
ssh-keygen -t ed25519 -f ~/.ssh/data_etipitaka_deploy -N "" -C "github-actions-deploy"
```
This creates `~/.ssh/data_etipitaka_deploy` (private) and `~/.ssh/data_etipitaka_deploy.pub` (public). The public key is installed on the server in Task 5; the private key becomes a GitHub Secret next.

- [ ] **Step 2: Set the GitHub Secrets**

Replace `PROD_HOST` and `PROD_USER` with the real values:
```bash
gh secret set DEPLOY_SSH_KEY --repo ssutee/data-etipitaka < ~/.ssh/data_etipitaka_deploy
gh secret set DEPLOY_HOST --repo ssutee/data-etipitaka --body "PROD_HOST"
gh secret set DEPLOY_USER --repo ssutee/data-etipitaka --body "PROD_USER"
```

- [ ] **Step 3: Set the deploy-path repo variable**

```bash
gh variable set DEPLOY_PATH --repo ssutee/data-etipitaka --body "/srv/data-etipitaka"
```
(Use the actual path where the repo will live on the server — must match Task 5.)

- [ ] **Step 4: Create the `production` Environment with a required reviewer**

```bash
gh api -X PUT repos/ssutee/data-etipitaka/environments/production \
  -F "reviewers[][type]=User" \
  -F "reviewers[][id]=$(gh api user --jq .id)"
```
Expected: a JSON response describing the `production` environment. This makes the `deploy` job pause for a one-click approval in the Actions UI.

- [ ] **Step 5: Verify**

```bash
gh secret list --repo ssutee/data-etipitaka
gh variable list --repo ssutee/data-etipitaka
gh api repos/ssutee/data-etipitaka/environments --jq '.environments[].name'
```
Expected: secrets `DEPLOY_SSH_KEY`, `DEPLOY_HOST`, `DEPLOY_USER`; variable `DEPLOY_PATH`; environment `production`.

---

## Task 5 [operator]: One-time production server setup

Runs on the **production server** (SSH in as an admin user). Done once. `<github-deploy-key>` and the deploy user below are set up here.

- [ ] **Step 1: Choose the deploy user and repo path**

Use an existing user or create a dedicated `deploy` user. It MUST be in the `docker` group:
```bash
sudo usermod -aG docker DEPLOY_USER   # DEPLOY_USER = the value from Task 4 Step 2
```
The repo will live at `/srv/data-etipitaka` (the `DEPLOY_PATH` from Task 4 Step 3). The deploy user must own it.

- [ ] **Step 2: Install the CI deploy public key**

Paste the contents of `~/.ssh/data_etipitaka_deploy.pub` (generated in Task 4 Step 1) into the deploy user's `~/.ssh/authorized_keys`:
```bash
sudo -u DEPLOY_USER sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys'
# paste the .pub line, then Ctrl-D
sudo -u DEPLOY_USER chmod 600 ~/.ssh/authorized_keys
```

- [ ] **Step 3: Create a server→GitHub read key and register it as a Deploy Key**

On the server, as the deploy user:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/github_readonly -N "" -C "data-etipitaka-server"
cat ~/.ssh/github_readonly.pub
```
Copy that public key. On the developer machine, register it as a **read-only** Deploy Key:
```bash
gh repo deploy-key add ~/.ssh/github_readonly.pub --repo ssutee/data-etipitaka --title "prod-server-readonly"
```
Then on the server, point SSH at that key for github.com — add to the deploy user's `~/.ssh/config`:
```
Host github.com
    IdentityFile ~/.ssh/github_readonly
    IdentitiesOnly yes
```

- [ ] **Step 4: Point the production checkout at GitHub**

If the production repo is already cloned on the server, switch its remote:
```bash
cd /srv/data-etipitaka
git remote set-url origin git@github.com:ssutee/data-etipitaka.git
git fetch origin
```
If it is not yet cloned there, clone it as the deploy user:
```bash
sudo -u DEPLOY_USER git clone git@github.com:ssutee/data-etipitaka.git /srv/data-etipitaka
```

- [ ] **Step 5: Verify SSH access from CI's perspective**

From the developer machine:
```bash
ssh -i ~/.ssh/data_etipitaka_deploy DEPLOY_USER@PROD_HOST \
  "cd /srv/data-etipitaka && git pull --ff-only && docker compose version 2>/dev/null || docker-compose version"
```
Expected: a clean `git pull` and a Docker Compose version string. This proves the CI→server key, the server→GitHub key, and Docker access all work.

---

## Task 6 [operator]: First production cutover (one-time, manual)

Production currently runs the old Python 2 / Django 1.9 stack on PostgreSQL 12. The first deploy of the migrated `master` is a cutover and must be done by hand — `deploy.sh` does NOT do the database upgrade.

- [ ] **Step 1: Schedule a maintenance window** and take a verified backup of the production database.

- [ ] **Step 2: Ensure `/srv/data-etipitaka` is on `master`** (the migrated code):
```bash
cd /srv/data-etipitaka && git pull --ff-only origin master
```

- [ ] **Step 3: Run the PostgreSQL 12→16 upgrade** following `docs/runbooks/postgres-12-to-16-upgrade.md` exactly (dump PG12 → wipe the volume → start PG16 → restore).

- [ ] **Step 4: Bring up the migrated stack**
```bash
./deploy.sh
```
(`deploy.sh` builds, migrates, collects static, health-checks.) If the server's Compose v1 rejects the version-less `docker-compose.yml`, either add a `version: '3.7'` line back to it (commit that), or install the Compose v2 plugin — decide in the window.

- [ ] **Step 5: Verify** the production site loads and login works.

> After this cutover, routine deploys are automatic (Task 7). The PG upgrade is never repeated and never enters `deploy.sh`.

---

## Task 7 [operator]: Verify the auto-deploy pipeline end-to-end

- [ ] **Step 1: Make a trivial change on `master`** (e.g. a one-line edit to `README.md`), commit, and push:
```bash
git commit -am "chore: trigger deploy pipeline test"
git push origin master
```

- [ ] **Step 2: Watch the run**
```bash
gh run watch --repo ssutee/data-etipitaka
```
Expected: `unit-tests` and `golden-harness` run and pass; `deploy` then shows status **Waiting** (pending approval).

- [ ] **Step 3: Approve the deployment.** In the GitHub Actions UI (or `gh`), approve the `production` environment deployment. The `deploy` job then runs.

- [ ] **Step 4: Confirm the deploy succeeded** — the `deploy` job is green, its log shows `[deploy] health check passed`, and the production site is up.

- [ ] **Step 5: Confirm the gate works** — open a pull request with any change; verify `unit-tests` and `golden-harness` run but `deploy` does **not** appear/run for the PR.

---

## Self-review notes

- Spec Section 1 (repo migration) → Task 3. Section 2 (pipeline structure) → Task 2. Section 3 (SSH mechanics, `deploy.sh`) → Tasks 1, 2, 4. Section 4 (server prerequisites) → Task 5. Section 5 (cutover) → Task 6. Section 6 (secrets inventory) → Task 4. Verification → Task 7.
- `DEPLOY_PATH` / `/srv/data-etipitaka` is used consistently across Tasks 2, 4, 5, 6.
- The `deploy.sh` command names (`$DC`, the migrate/collectstatic/health-check sequence) match the spec's Section 3 listing.

## Out of scope (per spec)

- Automatic rollback — rollback is the manual procedure in the spec's Section 3.
- Upgrading the production server's Docker Compose to v2 — `deploy.sh` auto-detects v1.
- Staging environments; container registry.

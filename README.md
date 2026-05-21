# E-Tipitaka-Plus Account Backend

Back-end server for the **E-Tipitaka-Plus** project. Handles user accounts, authentication, and per-user data sync for the iOS client.

## Stack

- Python 3.13 / Django 5.2 LTS
- Django REST Framework (token auth)
- PostgreSQL 16 (via psycopg3)
- gunicorn + nginx
- Docker Compose

## Services (docker-compose)

| Service | Image / build | Role | Port |
|---------|---------------|------|------|
| `web`   | `app/Dockerfile` | Django app under gunicorn | 8000 (internal) |
| `db`    | `postgres:16-alpine` | database | 5432 (internal) |
| `nginx` | `nginx/Dockerfile` | reverse proxy + static/media | **1338 → 80** |

App is reachable at `http://localhost:1338`.

## Prerequisites

- Docker + Docker Compose v2 (`docker compose`)
- Two environment files in the repo root (not committed — they hold secrets):
  - `.env` — web service config
  - `.env.db` — database credentials

### `.env`

```
DEBUG=1
SQL_ENGINE=django.db.backends.postgresql
SQL_DATABASE=etipitaka_data
SQL_USER=etipitaka
SQL_PASSWORD=<password>
SQL_HOST=db
SQL_PORT=5432
DATABASE=postgres
```

### `.env.db`

```
POSTGRES_DB=etipitaka_data
POSTGRES_USER=etipitaka
POSTGRES_PASSWORD=<password>
```

`SQL_*` and `POSTGRES_*` passwords must match. For CI, committed non-secret
equivalents `.env.ci` / `.env.db.ci` are used.

## Development

### Start

```sh
docker compose up -d --build
```

Starts `web`, `db`, `nginx`. The `web` service bind-mounts `./app`, so host
code edits are live (gunicorn restart picks up Python changes).

### Initialise the database

First run only — apply migrations, collect static files, load the seed fixture:

```sh
./init.sh
```

Or step by step:

```sh
docker compose exec web python manage.py migrate --noinput
docker compose exec web python manage.py collectstatic --noinput
docker compose exec web python manage.py loaddata seed.json
```

For a deterministic test dataset (fixed users `alice`/`bob`, known tokens):

```sh
docker compose exec web python manage.py seed_golden
```

### Email

In development `EMAIL_BACKEND` is the console backend — verification emails
print to the `web` container log (`docker compose logs web`). No SMTP needed.

### Common commands

```sh
docker compose logs -f web                       # tail app logs
docker compose exec web python manage.py shell    # Django shell
docker compose exec web python manage.py createsuperuser
docker compose down                               # stop
```

## Testing

Two suites.

### Unit tests (pytest-django)

```sh
docker compose exec -u root web pip install -r requirements-dev.txt   # once per container
docker compose exec web python -m pytest
```

Coverage is gated at 90% (`app/pytest.ini`).

### Golden harness — cross-stack HTTP regression suite

Runs against the live app over HTTP. See `tests/golden/README.md`.

```sh
python3 -m venv tests/golden/.venv
. tests/golden/.venv/bin/activate
pip install -r tests/golden/requirements.txt

docker compose exec web python manage.py seed_golden
python -m pytest tests/golden --base-url http://localhost:1338
```

CI (`.github/workflows/ci.yml`) runs both suites on every push.

## Production

Deployment uses the same Docker Compose stack with production values.

1. Provide real `.env` / `.env.db` with production secrets.
2. Override development-only settings:
   - set an SMTP `EMAIL_BACKEND` (development defaults to the console backend)
   - serve with `DEBUG=0`
3. Build and start:

   ```sh
   docker compose up -d --build
   docker compose exec web python manage.py migrate --noinput
   docker compose exec web python manage.py collectstatic --noinput
   ```

4. Put a TLS-terminating proxy in front of nginx (`1338`), or adjust the
   `nginx` service for the production host.

### Upgrading an existing production database

Django 5.2 requires PostgreSQL 14+. A pre-existing PostgreSQL 12 database
must be upgraded before deploying this release — follow
`docs/runbooks/postgres-12-to-16-upgrade.md`.

## Project layout

```
app/                     Django project
  etipitaka_auth/        settings, urls, wsgi
  user_data/             the account/data-sync app (models, views, auth, tests)
  Dockerfile  requirements.txt  requirements-dev.txt
nginx/                   reverse-proxy image + config
tests/golden/            cross-stack HTTP golden harness
docs/                    design spec, implementation plan, runbooks
docker-compose.yml  init.sh
```

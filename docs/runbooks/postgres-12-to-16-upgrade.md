# Production PostgreSQL 12 → 16 upgrade

Required before the Django 5.2 release can be deployed — Django 5.2 refuses
to connect to PostgreSQL < 14.

## Preconditions
- Maintenance window (the app is offline during the upgrade).
- Verified, restorable backup of the PG12 database.

## Procedure (dump / restore)

1. Stop the application containers (leave `db` running):
   `docker compose stop web nginx`

2. Dump the PG12 database:
   `docker compose exec db pg_dump -U etipitaka -Fc etipitaka_data > etipitaka_data.dump`

3. Stop and remove the PG12 container and its volume:
   `docker compose stop db`
   `docker compose rm -f db`
   `docker volume rm data-etipitaka_postgres_data`

4. Pull the new image and start a fresh PG16 instance:
   `docker compose up -d db`
   (compose now pins `postgres:16-alpine`; the empty volume initialises a PG16 cluster.)

5. Restore the dump into PG16:
   `cat etipitaka_data.dump | docker compose exec -T db pg_restore -U etipitaka -d etipitaka_data --clean --if-exists`

6. Start the app and run migrations:
   `docker compose up -d web nginx`
   `docker compose exec web python manage.py migrate --noinput`

7. Smoke-test, then delete `etipitaka_data.dump`.

## Rollback
If restore fails, recreate the PG12 container (temporarily repin `postgres:12.0-alpine`)
and restore the dump there; the application stays on the old release until resolved.

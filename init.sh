#!/bin/sh
docker compose run --rm web python manage.py migrate --noinput
docker compose run --rm web python manage.py collectstatic --noinput
docker compose run --rm web python manage.py loaddata seed.json

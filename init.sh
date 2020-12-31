#!/bin/sh

docker-compose run --rm web python manage.py migrate
docker-compose run --rm web python manage.py collectstatic
docker-compose run --rm web python manage.py loaddata dump.json


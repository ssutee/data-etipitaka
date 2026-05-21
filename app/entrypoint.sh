#!/bin/sh

if [ "$DATABASE" = "postgres" ]
then
    echo "Waiting for postgres..."

    until python -c "import socket,os,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex((os.environ['SQL_HOST'],int(os.environ['SQL_PORT'])))==0 else 1)"; do
      sleep 0.1
    done

    echo "PostgreSQL started"
fi

exec "$@"

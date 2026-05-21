# Golden test harness

Cross-stack HTTP regression harness. Talks to the app over HTTP only — no Django import — so the same tests run against the old (Py2/Django1.9) and new (Py3/Django5.2) stack.

## Setup

    python3 -m venv .venv && . .venv/bin/activate
    pip install -r tests/golden/requirements.txt

## Record (against the OLD app)

    docker compose up -d
    docker compose exec web python manage.py seed_golden
    pytest tests/golden/test_golden.py --record --base-url http://localhost:1338

## Assert (against the NEW app, after migration)

    docker compose up -d
    docker compose exec web python manage.py seed_golden
    pytest tests/golden -v --base-url http://localhost:1338

A failing test = a behavior regression.

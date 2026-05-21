# Project Overview

This is the back-end server side of E-Tipitaka-Plus project (~/Works/objc/E-Tipitaka-Plus) that handle Account feature.

## Development Stack
1. Django 5.2 LTS web framework (Python 3.13)
2. Django REST Framework for the API
3. PostgreSQL 16 via psycopg3
4. Docker Compose for local dev and deployment

## Testing
- Unit tests: `docker compose exec web python -m pytest` (pytest-django, coverage-gated at 90%)
- Golden harness: see `tests/golden/README.md` — cross-stack HTTP regression suite

## Note
1. always use docker compose for run and test the program

## Context Navigation (Graphify)

### 3-Layer Query Rule
1. **First:** query `graphify-out/graph.json` or `graphify-out/wiki/index.md`
   to understand code structure and connections
2. **Second:** query the Obsidian vault for decisions, progress, and project context
3. **Third:** only read raw code files when editing
   or when the first two layers don't have the answer

### When to rebuild the graph
- After structural changes (new modules, major refactors)
- Command: `graphify . --update` (only processes modified files)
- The graph is persistent — NO need to rebuild every session

### Do NOT
- Don't manually modify files inside `graphify-out/`
- Don't re-read the entire codebase if the graph already has the information
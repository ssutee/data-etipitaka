# E-Tipitaka MCP Server

Exposes a user's personal E-Tipitaka data (bookmarks, highlights, tags,
history, saved lexicon) and the Buddhist canon (search, passage read, Pali/Thai
dictionaries, and personal→canon cross-reference) to MCP-capable AI clients.

## Install

```bash
cd mcp_server
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

## Configuration (environment variables)

- `ETIPITAKA_BASE_URL` — default `https://data.etipitaka.com`. Serves both the
  personal-data API and the public canon API.

Personal data (choose ONE auth method):
- `ETIPITAKA_USERNAME` + `ETIPITAKA_PASSWORD` — your web login; exchanged once
  for a token, which is cached at `~/.config/etipitaka-mcp/token` (mode 0600).
  The password is never stored.
- or `ETIPITAKA_TOKEN` — a pre-existing DRF token.

Canon:
- Canon search/read/dictionary is served **remotely** by the server at
  `ETIPITAKA_BASE_URL` (`/api/canon/*`, public — no auth). No local resource
  files are needed by the MCP anymore.
- `ETIPITAKA_DEFAULT_EDITION` (optional) — default edition for `search_canon`
  when the tool call omits one (e.g. `thaiwn`).

## Tools

Personal: `list_bookmarks`, `list_highlights`, `list_tags`, `list_history`,
`list_lexicon`, `get_summary`, `whoami`.
Canon: `list_editions`, `search_canon`, `get_passage`, `resolve_reference`,
`lookup_dictionary`.

## Tests

```bash
cd mcp_server
. .venv/bin/activate
pip install -e '.[dev]'
pytest -v
```

## Claude Desktop / Claude Code config

Add to `claude_desktop_config.json` (or an `.mcp.json`):

```json
{
  "mcpServers": {
    "etipitaka": {
      "command": "/absolute/path/to/mcp_server/.venv/bin/etipitaka-mcp",
      "env": {
        "ETIPITAKA_USERNAME": "your-username",
        "ETIPITAKA_PASSWORD": "your-password",
        "ETIPITAKA_DEFAULT_EDITION": "thai"
      }
    }
  }
}
```

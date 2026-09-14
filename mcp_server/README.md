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
- **Token file (recommended)** — write a DRF token to
  `~/.config/etipitaka-mcp/token` (mode 0600). When `ETIPITAKA_TOKEN` is unset,
  the server reads this file. Keeps the secret out of any client config:
  ```bash
  mkdir -p ~/.config/etipitaka-mcp
  printf '%s' 'YOUR_DRF_TOKEN' > ~/.config/etipitaka-mcp/token
  chmod 600 ~/.config/etipitaka-mcp/token
  ```
- `ETIPITAKA_TOKEN` — a pre-existing DRF token passed as an env var.
- `ETIPITAKA_USERNAME` + `ETIPITAKA_PASSWORD` — your web login; exchanged once
  for a token, then cached at `~/.config/etipitaka-mcp/token` (0600). The
  password is never stored.

> Security: never place your password or token in a client config file (it is
> stored in plaintext). Prefer the token file above. An AI agent installing this
> MUST NOT enter your token/password — you set the token file yourself.

Canon:
- Canon search/read/dictionary is served **remotely** by the server at
  `ETIPITAKA_BASE_URL` (`/api/canon/*`, public — no auth). No local resource
  files are needed by the MCP anymore, and canon tools work with no credentials.
- `ETIPITAKA_DEFAULT_EDITION` (optional) — default edition for `search_canon`
  when the tool call omits one (e.g. `thai`).

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

## Install with an AI agent (Claude Code)

An agent can install this end to end. The steps below never expose the user's
secret — the agent registers with no credentials, and the user sets the token
file themselves.

1. Install into a venv:
   ```bash
   cd mcp_server && python3 -m venv .venv && .venv/bin/pip install -e .
   ```
2. Register the server (stdio) with an **absolute** path to the entry point.
   Include only non-secret env here:
   ```bash
   claude mcp add etipitaka -s local \
     -e ETIPITAKA_BASE_URL=https://data.etipitaka.com \
     -e ETIPITAKA_DEFAULT_EDITION=thai \
     -- /ABS/PATH/TO/mcp_server/.venv/bin/etipitaka-mcp
   ```
   Scope: `-s local` (this project, private) or `-s user` (all projects). Avoid
   `-s project` — that writes `.mcp.json` into the repo.
3. **User** sets the token (agent must not do this) — see the token file under
   Configuration. Canon tools already work without it.
4. **Restart the Claude session.** MCP servers load at session start; a running
   session will not see the newly added server until it restarts.
5. Verify: `claude mcp get etipitaka` shows `✔ Connected`; then call
   `list_editions` (14 editions, all `present: true`) and, once the token file
   is set, `whoami` (returns your pk / username / email).

## Claude Desktop config (JSON)

For Claude Desktop, add to `claude_desktop_config.json` — **no secrets**; set
the token via the token file instead (see Configuration):

```json
{
  "mcpServers": {
    "etipitaka": {
      "command": "/absolute/path/to/mcp_server/.venv/bin/etipitaka-mcp",
      "env": {
        "ETIPITAKA_BASE_URL": "https://data.etipitaka.com",
        "ETIPITAKA_DEFAULT_EDITION": "thai"
      }
    }
  }
}
```

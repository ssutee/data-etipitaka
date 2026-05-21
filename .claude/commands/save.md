---
description: Write a session log to the Obsidian vault and commit the repo
---

Save the current working session to the Obsidian vault, then commit.

## Steps

1. **Access the vault.** Use the Obsidian MCP tools (`mcp__obsidian__*` — load them with ToolSearch if not already available). They operate on the configured Obsidian vault. Check `data-etipitaka/logs/` with `obsidian_list_files_in_dir`; if the folder does not exist yet, it is created implicitly when the first note is written into it.

2. **Create the session log.** Write a new note at `data-etipitaka/logs/YYYY-MM-DD-<short-description>.md` in the vault — use today's date and a 2–4 word kebab-case description of this session. Use `obsidian_append_content` to create it.

3. **Record the session.** The note must contain exactly these three sections:
   - `## What was done` — the concrete changes and actions taken this session.
   - `## Decisions` — choices made this session and the reasoning behind them.
   - `## Pending` — open items, follow-ups, and anything left to do.

4. **Add wikilinks.** For every note created or modified in the vault during this session, reference it with `[[wikilink]]` syntax in the relevant section. If no other vault notes were touched, skip this step.

5. **Commit the repo.** If the current working directory is a git repository: stage the session's changes, create a commit with a concise message describing the session, and `git push` if a remote is configured. If it is not a git repository, skip this step and say so explicitly.

Report the session-log path and the commit SHA (if a commit was made).

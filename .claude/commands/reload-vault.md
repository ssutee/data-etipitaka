---
description: Summarize the most recent session logs from the Obsidian vault
---

Reload working context from recent Obsidian session logs.

## Steps

1. **Access the vault.** Use the Obsidian MCP tools (`mcp__obsidian__*` — load them with ToolSearch if not already available). They operate on the configured Obsidian vault.

2. **Find the recent logs.** List `data-etipitaka/logs/` with `obsidian_list_files_in_dir`. Session logs are named `YYYY-MM-DD-<description>.md`; select the **3 most recent** by the date in the filename.

3. **Read them.** Read those 3 logs (use `obsidian_batch_get_file_contents` to fetch them in one call).

4. **Summarize.** Produce a concise summary with two sections:
   - **Current state** — where the project stands now, synthesized from the logs.
   - **What's left** — the pending items and follow-ups still open.

If `data-etipitaka/logs/` contains fewer than 3 logs, use whatever exists. If the folder is empty or missing, say so and stop.

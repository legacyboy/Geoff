# Security Notes

## Known Issue: OLLAMA_API_KEY in Git History

### Summary

An `OLLAMA_API_KEY` value was committed to git history in `.env` before the file was
removed from tracking. The key is no longer in HEAD (`.env` has been gitignored since
commit `8660bcbc`, 2026-05-22), but it remains visible in older commits via `git log -p`.

### Key value affected

```
OLLAMA_API_KEY=7be76563b7a04e93989180aa36aa6504.UscdScTsKD5tNfd1EAd_0_uN
```

This value appears in approximately 7 commits prior to `8660bcbc`.

### What was done

- `8660bcbc` (2026-05-22): `.env` untracked and added to `.gitignore`. Commit message noted
  the key must be rotated.
- `7835af5` (subsequent): Second `.gitignore` cleanup commit confirming removal.
- **History was NOT rewritten.** `git filter-branch` / `git filter-repo` were intentionally
  not run because: (a) the repo is public and any force-push rewrites history for all
  downstream clones; (b) if the key is already rotated, the value in history is a dead
  credential and history rewrite provides no additional security benefit while creating
  confusion in the commit graph.

### Action required before final submission

**Dan must verify whether the key has been rotated:**

```bash
# Check if old key is still accepted
curl -s -H "Authorization: Bearer 7be76563b7a04e93989180aa36aa6504.UscdScTsKD5tNfd1EAd_0_uN" \
     https://ollama.com/api/tags 2>&1 | grep -E "401|403|unauthorized|invalid"
# If this returns 401/403 → key is dead (acceptable)
# If this returns 200 → key is still live; rotate immediately at your Ollama account console
```

**If the key is still live:**
1. Log in to your Ollama account and revoke / regenerate the API key.
2. Update your local `.env` with the new key value.
3. Optionally run `git filter-repo --path .env --invert-paths` on a fresh clone to scrub
   history, then force-push. Document the force-push in the submission notes.

**If the key is already dead (rotated):**
- The value in history is harmless. No further action is required.
- Note this in the Devpost submission if a judge asks.

### Evidence path validation (separate security boundary)

Evidence paths submitted to Geoff's API are validated against a strict allowlist before
use. Paths containing shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `()`, newlines)
are rejected to prevent command injection via maliciously named evidence files. This is a
code-enforced (architectural) guardrail, not prompt-enforced. See `src/geoff_routes.py`.

### MCP server network binding

The MCP server (`src/geoff_mcp_server.py`) binds to `127.0.0.1` only by default.
Remote analysts must connect via SSH tunnel. This means the network layer itself is the
authentication boundary for the MCP interface — no token is required for local connections.

### API authentication

`GEOFF_API_KEY` (optional) enables bearer-token authentication on all HTTP endpoints.
When unset, the server is unauthenticated — appropriate only for local-only use on a
single-user workstation. See `.env.example` for configuration details.

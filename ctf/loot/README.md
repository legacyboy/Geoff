# Loot Database

Store sensitive findings here. This directory is for:

- Credentials (username/password combos)
- API keys and tokens
- Flags obtained
- Hashes (cracked or uncracked)
- Session cookies
- SSH keys
- Screenshots with sensitive data

## Security Notice

⚠️ **This directory may contain sensitive information.**

- Never commit this to public repositories
- Clear out after CTF completion
- Use `git-crypt` or similar for real engagements
- Encrypt if storing long-term

## File Organization

```
loot/
├── flags.md          # Flag submission tracking
├── credentials.md    # Credentials database
├── hashes/           # Hash files for cracking
├── keys/             # API keys, tokens, SSH keys
└── screenshots/      # Evidence screenshots
```

## Flag Tracking Format

```markdown
| CTF | Challenge | Flag | Points | Solved |
|-----|-----------|------|--------|--------|
| CTF Name | Challenge Name | `flag{...}` | 100 | Y/N |
```

## Credential Format

```markdown
| Source | Service | Username | Password | Notes |
|--------|---------|----------|----------|-------|
| [CTF/Host] | [service] | [user] | [pass] | [notes] |
```

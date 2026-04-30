# PB-SIFT-031 — Enterprise Collaboration Forensics

**Phase:** Collection / Analysis
**Auto-triggered when:** Microsoft Teams, Slack, Discord, Skype, or Zoom local artifacts detected
**Specialist:** `collaboration`

## Objective

Extract and analyze local databases, caches, and logs from enterprise collaboration applications to reconstruct conversations, detect data exfiltration via chat, identify unauthorized file sharing, and surface insider threat activity through messaging platforms.

## Steps

### Microsoft Teams Analysis (`collaboration.analyze_teams`)

- Parse Teams LevelDB databases in `%LocalAppData%\Microsoft\Teams\IndexedDB\`
- Extract conversation threads, messages, timestamps, and participants
- Parse `Cookies` database for Teams authentication tokens and session data
- Identify file attachments shared in Teams chats and channels
- Detect "Download" and "Open" events for files shared via Teams
- Check for external guest accounts in team memberships
- Flag messages in incident window containing sensitive keywords (password, secret, confidential)
- Extract call and meeting history (participants, duration, start/end times)

### Slack Analysis (`collaboration.analyze_slack`)

- Parse Slack Cache databases (`%AppData%\Slack\Cache\Cache_Data\`)
- Extract workspace URLs, user IDs, and channel memberships
- Parse `Cookies` and `Local Storage` for authentication tokens
- Identify files uploaded/downloaded via Slack File Manager
- Check for DMs (direct messages) with external email addresses
- Detect workspace exports or bulk downloads initiated by user
- Flag keywords in cached message content
- Detect Slack Connect channels (cross-organizational communication)

### Discord Analysis (`collaboration.analyze_discord`)

- Parse Discord LevelDB databases (`%AppData%\Discord\Local Storage\leveldb\`)
- Extract server memberships, channel lists, and DM conversations
- Parse `Cookies` for Discord authentication tokens
- Identify file uploads/downloads via Discord CDN links
- Detect bot integrations and webhook configurations
- Flag Nitro purchases or subscription changes during incident window
- Extract voice channel join/leave timestamps
- Detect deleted messages (may be partially recoverable in cache)

### Skype Analysis (`collaboration.analyze_skype`)

- Parse Skype `main.db` (legacy) or `skype.db` / IndexedDB (modern Skype/UWP)
- Extract contacts, messages, call history, and file transfers
- Identify Skype-to-phone calls (paid service = potential exfiltration channel)
- Detect screen sharing sessions and their participants
- Flag messages with file attachments during incident window
- Extract account creation date and last login timestamp

### Zoom Analysis (`collaboration.analyze_zoom`)

- Parse Zoom logs in `%AppData%\Zoom\logs\`
- Extract meeting history: meeting IDs, participant names, start/end times
- Identify recordings saved locally vs cloud
- Detect screen sharing events and who initiated them
- Check for meeting join links shared via other channels
- Parse Zoom chat logs for messages exchanged during meetings
- Flag meetings with unusual participants (external domains, anonymous)
- Detect Zoom plugin/add-on installations

## Indicators of Interest

- Sensitive files shared via Teams/Slack DMs to external accounts
- "Deleted" messages in chat apps that appear in local cache
- Bulk file downloads from Teams/Slack channels during incident window
- Authentication tokens found in local databases (possible token theft)
- Screen sharing sessions with unknown participants
- Zoom meetings joined from suspicious IP addresses
- Discord bot webhooks configured during incident window
- Skype calls to international numbers after compromise
- Workspace export initiated by compromised account
- Messages containing passwords, API keys, or credentials

## Output

```json
{
  "apps_found": ["teams", "slack", "zoom"],
  "teams": {
    "account": "user@company.com",
    "conversations": 23,
    "messages_during_window": 145,
    "files_shared": 12,
    "external_participants": 3,
    "meetings": 8,
    "suspicious_keywords": 2
  },
  "slack": {
    "workspaces": 2,
    "channels": 45,
    "dms": 12,
    "files_uploaded": 34,
    "external_contacts": 1
  },
  "zoom": {
    "meetings": 23,
    "recordings": 2,
    "screen_shares": 5,
    "chat_messages": 67,
    "anonymous_joins": 1
  },
  "exfiltration_indicators": [
    "customer_database.csv shared via Slack DM to external email"
  ],
  "findings": []
}
```

## Tools Required

- `LevelDB` parser (Python `plyvel`) — Teams, Slack, Discord IndexedDB/Local Storage
- `SQLite3` — Skype main.db, Zoom chat logs
- `strings` — raw extraction from collaboration app caches
- `plistlib` — macOS collaboration app artifacts

## Notes

- Local databases often persist deleted messages longer than server-side
- Authentication tokens in local storage can be stolen by malware
- Cross-reference collaboration timestamps with email and browser artifacts
- Teams/Slack may have cloud audit logs available via admin portals
- Discord messages are client-side encrypted but metadata is recoverable

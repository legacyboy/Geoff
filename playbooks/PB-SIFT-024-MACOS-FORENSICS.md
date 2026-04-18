# PB-SIFT-024 — macOS Forensics

**Phase:** Discovery  
**Auto-triggered when:** OS detected as `macos`  
**Specialist:** `macos`

## Objective

Perform macOS-specific forensic analysis covering persistence mechanisms, Unified Log, launch agents/daemons, and FSEvents to surface attacker activity on Apple endpoints.

## Steps

### Plist Parsing (`parse_plist`)

- Parse all `.plist` files found in evidence using Python `plistlib`
- Extract launch agent and daemon definitions
- Parse `com.apple.loginitems.plist` for login items
- Parse application `Info.plist` files for bundle identifiers and entitlements
- Flag plist files in unusual locations (e.g., `/tmp`, user's `Downloads`)

### Unified Log Analysis (`parse_unified_log`)

- Query the Unified Log using `log show` with relevant subsystem filters
- Extract process execution events, network connections, and authentication events
- Filter for events in the incident window
- Flag processes spawned by unusual parents
- Flag sudo and privilege escalation events
- Flag TCC (Transparency, Consent, and Control) bypass attempts

### Launch Agent / Daemon Analysis (`analyze_launch_agents`)

- Enumerate all plists in:
  - `/Library/LaunchAgents/`
  - `/Library/LaunchDaemons/`
  - `~/Library/LaunchAgents/`
  - `/System/Library/LaunchAgents/` (for anomalies only)
- Extract `ProgramArguments`, `RunAtLoad`, `KeepAlive`, and `StartInterval` values
- Flag agents/daemons with non-standard paths or obfuscated command lines
- Flag recently-modified (mtime within incident window) persistence entries
- Cross-reference program paths against known malware launch agent names

### FSEvents Analysis (`analyze_fseventsd`)

- Parse FSEvents log from `/.fseventsd/` using `fsevents_parser`
- Reconstruct file creation, modification, deletion, and rename events
- Identify newly-created executables, scripts, and libraries
- Surface deleted files that were removed to cover tracks
- Flag changes to system directories (`/usr/local/bin`, `/etc`)

## Indicators of Interest

- Launch agents with `RunAtLoad = true` pointing to scripts in `~/Library` or `/tmp`
- Processes spawned by `osascript`, `bash -c`, or `python3 -c` with encoded payloads
- TCC database modifications (granting screen recording or full disk access)
- `AuthorizationExecuteWithPrivileges` calls from non-Apple applications
- Kernel extensions or system extensions loaded outside of Software Update
- `crontab` entries or `periodic` scripts added during incident window
- FSEvents showing mass file access or deletion in user home directories

## Output

```json
{
  "os_version": "macOS 14.2 Sonoma",
  "hostname": "MacBook-Pro-Dan",
  "launch_agents_total": 23,
  "launch_agents_suspicious": 1,
  "fsevent_entries": 14820,
  "unified_log_events": 8341,
  "suspicious_agents": ["/tmp/updater.sh"],
  "findings": []
}
```

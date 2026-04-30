# PB-SIFT-024 — macOS Forensics

**Phase:** Discovery
**Auto-triggered when:** OS detected as `macos`
**Specialist:** `macos`

## Objective

Perform comprehensive macOS-specific forensic analysis covering persistence mechanisms, Unified Log, launch agents/daemons, FSEvents, APFS snapshots, Spotlight databases, secure boot artifacts, system logs, application bundles, and Gatekeeper to surface attacker activity on Apple endpoints.

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

### APFS Snapshot Analysis (`analyze_apfs_snapshot`)

- Enumerate APFS snapshots using `apfsutil` or `snaputil`
- Extract snapshot metadata: name, creation time, transaction ID, and flags
- Mount read-only snapshot views for historical file system analysis
- Compare snapshot file listings with current filesystem for tampering detection
- Identify snapshots created after incident detection (anti-forensics)
- Detect deleted snapshots (missing snapshot IDs in sequence)
- Extract files from snapshots that were deleted in the live filesystem

### Spotlight Database Parsing (`parse_spotlight`)

- Parse Spotlight databases (`.store.db`, `.store.updates`, `.store.spotlight`)
- Extract file index entries with paths, timestamps, and content metadata
- Reconstruct file system state at time of last Spotlight indexing
- Identify files that existed in Spotlight index but are now missing (deletion)
- Extract application usage data from Spotlight `kMDItemLastUsedDate`
- Flag files with suspicious content types in index (executables in unusual locations)
- Cross-reference Spotlight paths with current filesystem for anti-forensics

### T2 / Apple Silicon Secure Boot Analysis (`analyze_t2_secureboot`)

- Detect T2 chip presence vs Intel-only Mac (T2 = Secure Enclave + secure boot)
- Parse `bridgeOS` / `iBoot` version strings from boot artifacts
- Check Secure Boot settings: Full Security, Medium Security, or No Security
- Verify System Integrity Protection (SIP) status (`csrutil` state)
- Detect Recovery OS boot artifacts (used for system modification)
- Check for `Allow booting from external media` setting
- Flag disabled Secure Boot or SIP as potential anti-forensics
- Extract firmware update history from `com.apple.MobileAsset.plist`

### Apple System Log (ASL) Parsing (`parse_asl_logs`)

- Parse `asl` log files in `/var/log/asl/` and `/private/var/log/asl/`
- Extract syslog-style entries with timestamp, process, PID, and message
- Filter for authentication events (sudo, loginwindow, screensaver)
- Flag kernel panics and system crashes during incident window
- Detect hardware-related errors that may indicate tampering
- Cross-reference ASL timestamps with Unified Log for corroboration
- Parse legacy `system.log` and `kernel.log` if present

### Application Bundle Analysis (`analyze_app_bundles`)

- Enumerate all `.app` bundles in `/Applications` and `~/Applications`
- Parse `Info.plist` for bundle identifier, version, and code signing info
- Extract entitlements from code signature (`codesign -d --entitlements`)
- Check code signing status: signed, ad-hoc signed, or unsigned
- Flag applications with entitlements allowing dangerous capabilities (keychain, full disk access, accessibility)
- Detect modified Apple applications (invalid code signature)
- Cross-reference bundle IDs against known malware families
- Extract Mach-O binary metadata for threat intelligence matching

### Gatekeeper / XProtect / Notarization (`check_gatekeeper`)

- Check Gatekeeper status (`spctl --status`) — enabled or disabled
- Parse Gatekeeper assessment log for quarantined applications
- Check XProtect definitions version and last update
- Verify Notarization status of downloaded applications
- Flag applications that bypassed Gatekeeper (quarantine attribute removed)
- Detect `xattr -d com.apple.quarantine` commands in shell history
- Check for disabled XProtect (anti-forensics or malware persistence)
- Identify notarized malware (signed and notarized but malicious)

## Indicators of Interest

- Launch agents with `RunAtLoad = true` pointing to scripts in `~/Library` or `/tmp`
- Processes spawned by `osascript`, `bash -c`, or `python3 -c` with encoded payloads
- TCC database modifications (granting screen recording or full disk access)
- `AuthorizationExecuteWithPrivileges` calls from non-Apple applications
- Kernel extensions or system extensions loaded outside of Software Update
- `crontab` entries or `periodic` scripts added during incident window
- FSEvents showing mass file access or deletion in user home directories
- **Unsigned kernel extensions (kexts) or system extensions loaded**
- **Gatekeeper disabled (`spctl --master-disable`) after incident detection**
- **Notarized malware — signed application with known malicious behavior**
- **APFS snapshots deleted or created after incident detection**
- **Missing files in current filesystem but present in Spotlight index**
- **Applications with excessive entitlements (keychain access, full disk access)**
- **SIP disabled or Secure Boot set to "No Security"**
- **Apple System Log entries deleted or truncated during incident window**
- **Modified Apple system applications with invalid code signatures**
- **XProtect disabled or definitions outdated for months**

## Output

```json
{
  "os_version": "macOS 14.2 Sonoma",
  "hostname": "MacBook-Pro-Dan",
  "chip": "Apple M2 Pro",
  "secure_boot": "Full Security",
  "sip_enabled": true,
  "gatekeeper_enabled": true,
  "xprotect_version": "2201",
  "launch_agents_total": 23,
  "launch_agents_suspicious": 1,
  "fsevent_entries": 14820,
  "unified_log_events": 8341,
  "asl_entries": 4521,
  "apfs_snapshots": 5,
  "snapshots_suspicious": 1,
  "spotlight_indexed_files": 234567,
  "spotlight_missing_files": 12,
  "app_bundles": 187,
  "unsigned_apps": 3,
  "apps_with_dangerous_entitlements": 2,
  "quarantined_apps": 5,
  "notarized_malware_detected": 0,
  "suspicious_agents": ["/tmp/updater.sh"],
  "findings": []
}
```

## Tools Required

- `plistlib` (Python) — plist parsing
- `log` / `log show` — Unified Log queries
- `fsevents_parser` — FSEvents log parsing
- `apfs-fuse` / `apfsutil` — APFS snapshot mounting
- `codesign` — code signature verification
- `spctl` — Gatekeeper status
- `snaputil` — APFS snapshot management
- `asl` / `syslog` — Apple System Log parsing
- `sqlite3` — Spotlight database parsing

## Notes

- APFS snapshots are read-only — mount them safely for historical analysis
- Spotlight databases contain metadata even for deleted files
- T2/Apple Silicon secure boot artifacts may be in firmware, not filesystem
- Gatekeeper quarantine attributes (`com.apple.quarantine`) are easily bypassed
- Notarized malware is increasingly common — signature alone is not trust
- SIP disabled allows root-level modifications that would otherwise be blocked
- ASL logs rotate — check `/var/log/asl/Logs/` for archived entries

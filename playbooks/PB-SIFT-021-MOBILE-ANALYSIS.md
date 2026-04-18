# PB-SIFT-021 — Mobile Analysis

**Phase:** Collection  
**Auto-triggered when:** Mobile backup files detected (iTunes backup directories, Android data directories)  
**Specialist:** `mobile`

## Objective

Extract and analyse iOS and Android device artefacts from local backups and acquired data directories to surface user activity, installed applications, communications, and indicators of compromise on mobile devices.

## Steps

### iOS Backup Analysis (`analyze_ios_backup`)

- Locate and parse the `Manifest.db` SQLite database
- Enumerate installed applications from `Manifest.plist`
- Extract SMS and iMessage records from `3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28`
- Extract call history from `2b/2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca`
- Extract Safari browsing history and bookmarks
- Extract photos metadata (EXIF, GPS co-ordinates)
- Parse `Info.plist` for device hostname, UDID, iOS version, last backup date
- Flag large data transfers or unusual app activity

### Android Data Analysis (`analyze_android`)

- Parse `packages.xml` for installed and recently-uninstalled applications
- Extract SMS database (`mmssms.db`) for messages and contacts
- Extract call log database
- Extract browser history from Chrome/Firefox databases
- Parse account manager data for synced accounts
- Extract location history if present
- Flag sideloaded APKs (not from Play Store) and suspicious permissions

## Indicators of Interest

- Communication with known C2 infrastructure
- Sideloaded or self-signed applications
- Messaging apps with ephemeral/disappearing messages enabled
- Large file transfers over cellular shortly before or after incident window
- Device enrolled in MDM but MDM profile recently removed
- GPS data placing device at sensitive locations
- Evidence of device rooting or jailbreaking

## Output

```json
{
  "device_model": "iPhone 14 Pro",
  "ios_version": "16.6.1",
  "last_backup": "2024-01-15T08:42:00",
  "installed_apps": 87,
  "sms_count": 1203,
  "suspicious_apps": ["AltStore", "Cydia"],
  "findings": []
}
```

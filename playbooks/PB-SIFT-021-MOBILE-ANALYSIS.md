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
- Parse `Info.plist` for device hostname, UDID, iOS version, IMEI, ICCID, last backup date, encryption status

### iOS SMS and iMessage Extraction (`extract_ios_sms`)

- Extract SMS and iMessage records from `sms.db` via `Manifest.db` file ID resolution
- Capture sender handle, message text, timestamp, service (SMS vs iMessage), and direction (sent/received)
- Flag messages deleted at the application layer (absent rows with WAL residue — see `recover_deleted_sqlite_messages`)

### iOS Call History (`extract_ios_call_history`)

- Parse `CallHistory.storedata` for all call records
- Capture number, name, duration, call type, service provider, country code, and direction
- Identify calls to/from numbers not in the contacts list

### iOS Contacts (`extract_ios_contacts`)

- Parse `AddressBook.sqlitedb` (domain: `HomeDomain`, path: `Library/AddressBook/AddressBook.sqlitedb`)
- Extract first/last name, organisation, all phone numbers (property 3) and email addresses (property 4)
- Cross-reference contact list against SMS handles and call log numbers

### iOS Mail (`extract_ios_mail`)

- Parse `Mail Envelope Index` (domain: `AppDomain-com.apple.mobilemail`, path: `Library/Mail/Envelope Index`)
- Extract subject, sender, date received/sent, read/flagged status, and mailbox folder for up to 500 messages
- Flag unread messages in the incident window and messages marked flagged

### iOS Safari History (`extract_ios_safari_history`)

- Extract browsing history and visit counts from `Safari/History.db`
- Identify searches, file downloads, and visits to cloud storage or exfiltration-adjacent services

### iOS Location History (`extract_ios_location`)

- Parse `routined/Local.sqlite` (`ZRTVISIT` table) for significant visited locations with enter/leave timestamps
- Parse `Maps/GeoHistory.mapsdata` plist for Apple Maps search and navigation history
- Flag locations coinciding with the incident window

### iOS Jailbreak Indicators (`detect_jailbreak_indicators`)

- Check `Manifest.db` for Cydia, Zebra, Sileo, TrollStore, Dopamine, and p0sixspwn domains
- Flag Cydia preferences in HomeDomain
- Flag absence of passcode (`PasscodeSet = false`)

### iOS WhatsApp Messages (`extract_whatsapp`, platform=ios)

- Locate `ChatStorage.sqlite` in `AppDomainGroup-group.net.whatsapp.WhatsApp.shared` or `AppDomain-net.whatsapp.WhatsApp`
- Extract message text, timestamp, direction, contact JID, and contact display name from `ZWAMESSAGE`/`ZWACHATSESSION` join
- Note: encrypted backups require prior decryption

### iOS Telegram Messages (`extract_telegram`, platform=ios)

- Search for `postbox.sqlite` or `db_sqlite` in the backup tree
- Extract message rows if schema is accessible; report `encrypted` status if the database is locked
- Note: recent Telegram iOS versions encrypt the local database

### iOS Photo EXIF & GPS (`extract_mobile_photo_exif`, platform=ios)

- Run `exiftool -json -GPS* -DateTimeOriginal -Make -Model -r` over `CameraRollDomain/Media/DCIM` subtree
- Fall back to Pillow JPEG EXIF parsing if `exiftool` is unavailable
- Surface GPS coordinates, capture timestamps, device make/model for all photos with location data

### iOS WAL/Deleted Message Recovery (`recover_deleted_sqlite_messages`)

- Check for `-wal` and `-journal` files alongside `sms.db`, `CallHistory.storedata`, and `ChatStorage.sqlite`
- Copy database + WAL/SHM to a temp directory and issue `PRAGMA wal_checkpoint(FULL)` to incorporate uncommitted transactions
- Re-query all tables and diff against the primary extraction to identify recovered rows

### iLEAPP Full Extraction (`run_ileapp`)

- Run iLEAPP if installed (`/opt/ileapp/ileapp.py` or `$PATH`) against the iTunes backup
- Parse `ILEAPP_report.json` for additional artefact coverage not handled above

---

### Android Data Analysis (`analyze_android`)

- Parse `packages.xml` for installed and recently-uninstalled applications
- Flag sideloaded APKs (not from Play Store) and applications with dangerous permissions
- Inventory databases and shared preferences

### Android SMS/MMS (`extract_android_sms`)

- Query `mmssms.db` SMS and MMS tables for address, body, timestamp, type (received/sent/draft), and read status

### Android Call Logs (`extract_android_call_logs`)

- Query `calllog.db` or `contacts2.db` for number, name, duration, type (incoming/outgoing/missed), and geocoded location

### Android Contacts (`extract_android_contacts`)

- Query `contacts2.db` joining `contacts` and `data` tables for display name, phone numbers, email addresses, and contact frequency

### Android Email (`extract_android_email`)

- Search for `mailstore.*.db` (Gmail) and extract messages with sender, recipients, subject, snippet, and timestamp
- Fall back to `EmailProviderBody.db` / `EmailProvider.db` (Samsung/AOSP Mail) if Gmail store absent

### Android Browser History (`extract_android_browser_history`)

- Query Chrome `History`, legacy `browser.db`, and `webview.db` for URLs, titles, visit counts, and timestamps
- Convert Chrome epoch (microseconds since 1601-01-01) to UTC

### Android Location History (`extract_android_location`)

- Parse Google Takeout `Location History.json` for lat/lon, timestamp, and accuracy
- Query `cache.wifi`, `gps.db`, `location.db`, `cache.cell` for cached location records

### Android WhatsApp Messages (`extract_whatsapp`, platform=android)

- Locate `msgstore.db` in `com.whatsapp/databases/`
- Query `message` table (new schema) or `messages` table (legacy) for text, timestamp, direction, contact JID, media references, and embedded GPS coordinates
- Report `encrypted` status if only `.crypt14`/`.crypt12` variants are found (key file required)

### Android Telegram Messages (`extract_telegram`, platform=android)

- Locate `cache4.db` or `cache.db` in `com.telegram.messenger/` or `org.telegram.messenger/`
- Query `messages_v2` or `messages` table for text, timestamp, sender ID, peer ID, and direction

### Android Photo EXIF & GPS (`extract_mobile_photo_exif`, platform=android)

- Run exiftool or Pillow over DCIM directory for GPS coordinates and capture timestamps

### Android WAL/Deleted Message Recovery (`recover_deleted_sqlite_messages`)

- Check for `-wal`/`-journal` alongside `mmssms.db` and `msgstore.db`
- Checkpoint and re-query to surface messages deleted at the application layer

### Android Jailbreak/Root Indicators (`detect_jailbreak_indicators`)

- Search for `su`, `.magisk`, `busybox`, and Superuser config files
- Check `packages.xml` for Magisk, SuperSU, and Superuser package names

### ALEAPP Full Extraction (`run_aleapp`)

- Run ALEAPP if installed against the Android data directory
- Parse `ALEAPP_report.json` for artefact coverage not handled above

---

## Indicators of Interest

- Communication with known C2 infrastructure
- Sideloaded or self-signed applications
- Messaging apps with ephemeral/disappearing messages enabled
- Large file transfers over cellular shortly before or after the incident window
- Device enrolled in MDM but MDM profile recently removed
- GPS data placing device at sensitive locations during the incident window
- Evidence of device rooting or jailbreaking
- WhatsApp/Telegram messages referencing credentials, account numbers, or internal systems
- Contacts or handles not present in the corporate directory
- Flagged or unread emails in the incident window

## Output

```json
{
  "device_model": "iPhone 14 Pro",
  "ios_version": "16.6.1",
  "last_backup": "2024-01-15T08:42:00",
  "installed_apps": 87,
  "sms_count": 1203,
  "contact_count": 412,
  "mail_count": 891,
  "whatsapp_messages": 340,
  "telegram_messages": 0,
  "location_points": 58,
  "photos_with_gps": 22,
  "wal_tables_recovered": ["message"],
  "suspicious_apps": ["AltStore", "Cydia"],
  "findings": []
}
```

# PB-SIFT-021 — Mobile Analysis

**Phase:** Collection  
**Auto-triggered when:** Mobile backup files detected (iTunes backup directories, Android data directories)  
**Specialist:** `mobile`

## Objective

Extract and analyse iOS and Android device artefacts from local backups and acquired data directories to surface user activity, installed applications, communications, and indicators of compromise on mobile devices.

---

## iOS Steps

### Device Metadata (`analyze_ios_backup`, `extract_ios_device_info`)

- Parse `Info.plist` for device name, UDID, product type, iOS version, IMEI, ICCID, phone number, last backup date, encryption status
- Parse `Manifest.db` for installed application domains, file inventory, and backup structure
- Parse `Status.plist` for backup state and full-backup flag
- Cross-reference device identifiers with corporate asset inventory

### Account Inventory (`extract_ios_accounts`)

- Parse `Accounts3.sqlite` (domain: `HomeDomain`, path: `Library/Accounts/Accounts3.sqlite`) for all configured accounts: Apple ID, Google, Exchange, LDAP, CardDAV, CalDAV, iCloud
- Identify accounts not belonging to the corporate domain
- Flag accounts added or removed in the incident window

### SMS and iMessage (`extract_ios_sms`)

- Extract SMS and iMessage records from `sms.db` via `Manifest.db` file ID resolution
- Capture sender handle, message text, timestamp, service (SMS vs iMessage), and direction
- Flag messages deleted at the application layer (absent rows with WAL residue — see WAL recovery step)

### Call History (`extract_ios_call_history`)

- Parse `CallHistory.storedata` for all call records
- Capture number, name, duration, call type, service provider, country code, and direction
- Identify calls to/from numbers absent from the contacts list

### Contacts (`extract_ios_contacts`)

- Parse `AddressBook.sqlitedb` (domain: `HomeDomain`, path: `Library/AddressBook/AddressBook.sqlitedb`)
- Extract first/last name, organisation, all phone numbers (property 3) and email addresses (property 4)
- Cross-reference contact list against SMS handles, call log numbers, and mail senders

### Mail (`extract_ios_mail`)

- Parse `Mail Envelope Index` (domain: `AppDomain-com.apple.mobilemail`, path: `Library/Mail/Envelope Index`)
- Extract subject, sender, date received/sent, read/flagged status, and mailbox folder for up to 500 messages
- Flag unread messages in the incident window and messages flagged or in Trash

### WhatsApp (`extract_whatsapp`, platform=ios)

- Locate `ChatStorage.sqlite` in `AppDomainGroup-group.net.whatsapp.WhatsApp.shared` or `AppDomain-net.whatsapp.WhatsApp`
- Extract message text, timestamp, direction, contact JID, and contact display name via `ZWAMESSAGE`/`ZWACHATSESSION` join
- Note: encrypted backups require prior decryption

### Telegram (`extract_telegram`, platform=ios)

- Search for `postbox.sqlite` or `db_sqlite` in the backup tree
- Extract message rows if schema is accessible; report `encrypted` status if database is locked
- Note: recent Telegram iOS versions encrypt the local database

### Safari History (`extract_ios_safari_history`)

- Extract browsing history and visit counts from `Safari/History.db`
- Identify searches, file downloads, and visits to cloud storage or exfiltration-adjacent services

### Location History (`extract_ios_location`)

- Parse `routined/Local.sqlite` (`ZRTVISIT` table) for significant visited locations with enter/leave timestamps and confidence score
- Parse `Maps/GeoHistory.mapsdata` plist for Apple Maps navigation history
- Flag locations coinciding with the incident window

### Notifications (`extract_ios_notifications`)

- Parse `notification_log` table in `settings.db` for notification records
- Extract app bundle IDs, alert strings, and delivery timestamps
- Flag notifications from messaging or file-transfer apps during the incident window

### Usage Statistics (`extract_ios_usage_stats`)

- Parse app usage databases for screen-time and foreground duration per app
- Identify apps with unusually high usage during the incident window
- Surface apps that were actively used but have since been deleted

### Photo EXIF and GPS (`extract_mobile_photo_exif`, platform=ios)

- Run `exiftool -json -GPS* -DateTimeOriginal -Make -Model -r` over the backup DCIM subtree
- Fall back to Pillow JPEG EXIF parsing if `exiftool` is unavailable
- Surface GPS coordinates, capture timestamps, and device make/model for all photos with location data

### Keychain Credentials (`extract_ios_keychain`)

- Parse `KeychainDomain.plist` from the backup for password items and internet password entries
- Extract service names, account names, and accessible credential metadata (values are not decrypted without the backup password)
- Flag credentials referencing internal systems, VPNs, or corporate email

### HealthKit Data (`extract_ios_health`)

- Parse `HealthExport.db` or `Health.db` for workout records and step/location data
- Correlate GPS-bearing workout routes with the incident timeline
- Flag high-activity periods coinciding with known exfiltration windows

### Jailbreak Indicators (`detect_jailbreak_indicators`)

- Check `Manifest.db` for Cydia, Zebra, Sileo, TrollStore, Dopamine, and p0sixspwn domains
- Flag Cydia preferences in HomeDomain
- Flag absence of passcode (`PasscodeSet = false`)

### WAL / Deleted Message Recovery (`recover_deleted_sqlite_messages`)

- Check for `-wal` and `-journal` files alongside `sms.db`, `CallHistory.storedata`, and `ChatStorage.sqlite`
- Copy database + WAL/SHM to a temp directory and issue `PRAGMA wal_checkpoint(FULL)` to incorporate uncommitted transactions
- Re-query all tables to surface messages deleted at the application layer

### iLEAPP Full Extraction (`run_ileapp`)

- Run iLEAPP if installed (`/opt/ileapp/ileapp.py` or `$PATH`) against the iTunes backup
- Parse `ILEAPP_report.json` for additional artefact coverage not handled by built-in extractors

---

## Android Steps

### Device Metadata (`analyze_android`, `extract_android_device_info`)

- Parse `packages.xml` for installed and recently-uninstalled applications
- Extract device model, Android version, build fingerprint, and serial number from system databases
- Flag sideloaded APKs (not from Play Store) and applications with dangerous permissions
- Inventory databases and shared preferences

### Account Inventory (`extract_android_accounts`)

- Query `accounts.db` for Google and third-party accounts configured on the device
- Extract account type, account name, and authentication token metadata
- Flag accounts not belonging to the corporate domain

### SMS and MMS (`extract_android_sms`)

- Query `mmssms.db` SMS and MMS tables for address, body, timestamp, type (received/sent/draft), and read status

### Call Logs (`extract_android_call_logs`)

- Query `calllog.db` or `contacts2.db` for number, name, duration, type (incoming/outgoing/missed), and geocoded location

### Contacts (`extract_android_contacts`)

- Query `contacts2.db` joining `contacts` and `data` tables for display name, phone numbers, email addresses, and contact frequency

### Email (`extract_android_email`)

- Search for `mailstore.*.db` (Gmail) and extract messages with sender, recipients, subject, snippet, and timestamp
- Fall back to `EmailProviderBody.db` / `EmailProvider.db` (Samsung/AOSP Mail) if Gmail store absent

### WhatsApp (`extract_whatsapp`, platform=android)

- Locate `msgstore.db` in `com.whatsapp/databases/`
- Query `message` table (new schema) or `messages` table (legacy schema) for text, timestamp, direction, contact JID, media references, and embedded GPS coordinates
- Report `encrypted` status if only `.crypt14`/`.crypt12` variants are present (key file required)

### Telegram (`extract_telegram`, platform=android)

- Locate `cache4.db` or `cache.db` in `com.telegram.messenger/` or `org.telegram.messenger/`
- Query `messages_v2` or `messages` table for text, timestamp, sender ID, peer ID, and direction

### Browser History (`extract_android_browser_history`)

- Query Chrome `History`, legacy `browser.db`, and `webview.db` for URLs, titles, visit counts, and timestamps
- Convert Chrome epoch (microseconds since 1601-01-01) to UTC

### Location History (`extract_android_location`)

- Parse Google Takeout `Location History.json` for lat/lon, timestamp, and accuracy
- Query `cache.wifi`, `gps.db`, `location.db`, `cache.cell` for cached location records

### Notifications (`extract_android_notifications`)

- Parse `notification_log` table in `settings.db` for notification records
- Extract app package names, alert text, and delivery timestamps
- Flag notifications from messaging or file-transfer apps during the incident window

### Usage Statistics (`extract_android_usage_stats`)

- Parse `usagestats/` XML files for per-app foreground duration and last-used timestamps
- Identify apps with elevated usage during the incident window
- Surface apps that were used then uninstalled

### Photo EXIF and GPS (`extract_mobile_photo_exif`, platform=android)

- Run exiftool or Pillow over DCIM directory for GPS coordinates and capture timestamps

### Root / Jailbreak Indicators (`detect_jailbreak_indicators`)

- Search for `su`, `.magisk`, `busybox`, and Superuser config files
- Check `packages.xml` for Magisk, SuperSU, and Superuser package names

### WAL / Deleted Message Recovery (`recover_deleted_sqlite_messages`)

- Check for `-wal`/`-journal` alongside `mmssms.db` and `msgstore.db`
- Checkpoint and re-query to surface messages deleted at the application layer

### ALEAPP Full Extraction (`run_aleapp`)

- Run ALEAPP if installed against the Android data directory
- Parse `ALEAPP_report.json` for artefact coverage not handled by built-in extractors

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
- Accounts added that do not belong to the corporate domain
- Keychain entries referencing internal VPN, cloud storage, or email infrastructure
- App usage spikes for file-transfer or exfiltration-capable apps during the incident window
- Notification history showing activity from deleted messaging apps

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
  "notification_records": 1540,
  "usage_stats_apps": 34,
  "accounts_found": ["apple@corp.com", "personal@gmail.com"],
  "keychain_entries": 12,
  "wal_tables_recovered": ["message"],
  "suspicious_apps": ["AltStore", "Cydia"],
  "findings": []
}
```

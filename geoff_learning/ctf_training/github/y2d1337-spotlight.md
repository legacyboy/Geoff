# CyberDefenders: Spotlight Challenge Write-up

## Overview
A MAC OS image forensics challenge focusing on evaluating DFIR skills on MacOS.
- Image Format: .ad1 file (55 MB)
- Tags: MAC Forensics, OSX Forensics, Autopsy, Steganography

## Tools Used
- Mac_apt: Process MAC full disk images and extract metadata.
- DB Browser for SQLite: Analysis of database files.
- Steghide: Hiding/extracting data from image/audio files.
- Plist Explorer: Parsing .plist files.
- FSEventsParser: Parsing FSEvents files from /.fseventsd/.

## Key Findings & Analysis
### System & User Info
- MacOS Version: Located in root\System\Library\CoreServices\SystemVersion.plist.
- User Nodes: Password hints found in /private/var/db/dslocal/nodes/[user].plist.

### Application Analysis
- Safari: Bookmarks located in root\Users\hansel.apricot\Library\Safari/bookmarks.plist.
- Notes: Database located at \root\Users\hansel.apricot\Library\Group Containers\group.com.apple.notes (NoteStore.sqlite-wal).
- iMessage: History stored in chat.db located at Users/username/Library/Messages/.
- Screen Time: Data stored in RMAdminStore-Local.sqlite located in \root\private\var\folders\...\com.apple.ScreenTimeAgent\Store.

### Forensic Artifacts
- Quarantine: Quarantined items found in \root\Users\sneaky\Library\Preferences/com.apple.LaunchServices.QuarantineEventsV2.
- Deleted Files: Checked in root\Users\sneaky\.Trash.
- ZSH History: .zsh_history used to track command-line activity (e.g., installing .dmg files).
- System Event Logs: Analyzed using FSEventsParser on \root\.fseventsd.
- Daily Logs: daily.out file in /private/var/log/ used for disk usage and networking info.

### Steganography
- Found hidden text in AnotherExample.jpg using HxD Editor.
- Used steghide to extract a payload from an image to a text file.

## Flags Summary
- MacOS Version: 10.15
- Hidden Text: flip phone
- Safari Bookmarks Count: 13
- Notes Content: Passwords
- MAC Address: 00:0C:29:C4:65:77
- Quarantine URL: https://futureboy.us/stegano/encode.pl
- Installed Software: silenteye
- Renamed File: GoodExample.jpg
- Screen Time: 20:58
- Password Hint: Family Opinion
- Sudo/Permission Changes: 7
- Screentime/User ID: 213
- Stego Payload: helicopter
- Spotlight Search: term
- UUID: 5BB00259-4F58-4FDE-BC67-C2659BA0A5A4

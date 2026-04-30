# PB-SIFT-029 — Encrypted Container Detection & Recovery

**Phase:** Discovery / Collection
**Auto-triggered when:** Encrypted volumes, BitLocker metadata, VeraCrypt headers, or LUKS partitions detected
**Specialist:** `crypto`

## Objective

Detect, identify, and attempt recovery of encrypted containers and volumes including BitLocker, FileVault (APFS), VeraCrypt, and LUKS. Search for recovery keys and passwords in other evidence, and flag anti-forensics involving encryption.

## Steps

### BitLocker Analysis (`crypto.analyze_bitlocker`)

- Parse BitLocker metadata from NTFS `$BitLocker` or `$LogFile` entries
- Detect recovery keys, password protectors, and TPM/startup key protectors
- Search for `BitLocker Recovery Key` strings across all evidence (`.txt`, `.docx`, emails)
- Extract FVEK (Full Volume Encryption Key) metadata if available
- Check Active Directory or Azure AD for backed-up recovery keys
- Flag systems with BitLocker suspended or disabled after the incident window

### FileVault (APFS Encrypted) Analysis (`crypto.analyze_filevault`)

- Detect APFS encrypted volumes via container header analysis
- Parse `apfs` volume header for encryption state and keybag type
- Search for FileVault recovery keys in macOS `Keychain` backups
- Check for institutional recovery keys (Enterprise/MDM-managed Macs)
- Extract encrypted volume metadata (user count, keybag version)

### VeraCrypt Analysis (`crypto.analyze_veracrypt`)

- Detect VeraCrypt volumes by analyzing partition/volume entropy and header patterns
- Identify hidden volumes by comparing outer volume free space with filesystem usage
- Search for VeraCrypt rescue disks (`.iso` files with rescue metadata)
- Check browser history for `veracrypt.org` or forum searches
- Flag systems with high-entropy files that lack filesystem signatures

### LUKS (Linux Unified Key Setup) Analysis (`crypto.analyze_luks`)

- Detect LUKS headers (magic `LUKS\xba\xbe`) in disk images and partitions
- Parse LUKS metadata: cipher, key size, PBKDF2 iterations, salt
- Extract keyslot usage (how many passwords are configured)
- Search for LUKS passphrases in shell history, password managers, or notes
- Check for LUKS key files (raw binary key files referenced in crypttab)

### Recovery Key / Password Search (`crypto.search_keys`)

- Full-text search all evidence for BitLocker recovery key patterns (`XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX`)
- Search for common password patterns in documents, browser forms, and notes
- Check cloud sync artifacts for password manager databases
- Search registry for cached credentials that may unlock containers
- Extract password hints from OS accounts

### Anti-Forensics Detection (`crypto.detect_encryption_anti_forensics`)

- Detect rapid encryption operations (large files becoming high-entropy)
- Identify ransomware-like encryption patterns vs intentional container creation
- Flag systems where encryption was enabled AFTER incident detection
- Detect volume dismount operations in logs (VSS, macOS `diskutil`, Linux `cryptsetup`)
- Identify evidence of volume deletion (deregistered BitLocker, missing LUKS headers)

## Indicators of Interest

- BitLocker recovery key found in email or chat logs
- FileVault recovery key backed up to unencrypted iCloud
- VeraCrypt hidden volume detected (free space anomaly)
- LUKS header overwritten or corrupted (anti-forensics)
- Encryption enabled after initial compromise
- High-entropy files with no filesystem header (possible encrypted container)
- Multiple LUKS keyslots with only one in use (other passphrase changed)
- Suspicious timing: container dismount right before incident detection
- Password manager database found in unencrypted backup
- Recovery key printed or stored in plaintext on the same system

## Output

```json
{
  "encrypted_volumes": [
    {
      "volume": "\\Device\\HarddiskVolume2",
      "type": "BitLocker",
      "status": "locked",
      "recovery_key_found": true,
      "recovery_key_location": "email_draft.eml",
      "encryption_state": "fully_encrypted"
    },
    {
      "volume": "/dev/sda2",
      "type": "LUKS",
      "status": "locked",
      "keyslots_total": 2,
      "keyslots_active": 1,
      "passphrase_found": false,
      "cipher": "aes-xts-plain64"
    },
    {
      "file": "secret.tc",
      "type": "VeraCrypt",
      "status": "possible_hidden_volume",
      "volume_size": 10737418240,
      "filesystem_used": 2147483648,
      "entropy": 7.98
    }
  ],
  "recovery_keys_found": 1,
  "passwords_found": 0,
  "anti_forensics_indicators": [
    "BitLocker enabled 2 hours after first IOC detection"
  ],
  "findings": []
}
```

## Tools Required

- `bdeinfo` / `bdemount` (libbde) — BitLocker metadata parsing
- `apfs-fuse` / `apfsutil` — APFS encrypted volume detection
- `veracrypt` (CLI) — VeraCrypt volume mounting (non-forensic, for testing)
- `cryptsetup luksDump` — LUKS header parsing
- `ent` / `entcalc` — entropy analysis for hidden volume detection
- `strings` + regex — recovery key pattern matching

## Notes

- Never attempt to brute-force encryption in production — only search for keys/passwords
- VeraCrypt hidden volumes are undetectable with certainty — flag anomalies only
- BitLocker keys may be cached in TPM — requires hardware access for extraction
- LUKS2 (modern) has different header format than LUKS1 — use `cryptsetup` for both
- FileVault keys may be recoverable from memory if system was running when imaged

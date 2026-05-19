# PB-SIFT-037: IoT Device Forensics

**Classification:** SIFT Bot - IoT Device Analysis  
**Objective:** Extract intelligence from consumer IoT device images, configuration files, and cloud-synced artifacts. Covers connected cameras, smart home hubs, voice assistants, and automation platforms.  
**Specialist:** `sleuthkit, strings, registry`

**Trigger Conditions:**
- IoT device images or config dumps found in evidence directory
- IoT device directory naming detected (e.g. arlo, echo, smartthings, wink, ismartalarm)
- Known IoT firmware file signatures (e.g. U-Boot, Android boot image, YAFFS, JFFS2, SquashFS)
- Embedded Linux filesystem found on non-PC/non-server device

---

### Phase 1 — Device Identification & Image Assessment

**Goal:** Identify the IoT device model, firmware version, and image type.

- [ ] **Check directory name:** Scan evidence directory for IoT identifiers — `arlo`, `echo`, `alexa`, `smartthings`, `wink`, `ismartalarm`, `nest`, `ring`, `ecobee`, `philips`, `hue`, `roku`, `chromecast`, `android.*tv`, `apple.*tv`, `raspberry`, `arduino`, `esp8266`, `esp32`
- [ ] **File type identification:** Run `file <device_image>` to determine filesystem type:
    - SquashFS (common firmware format)
    - JFFS2/UBIFS (embedded flash)
    - YAFFS (Android devices)
    - ext2/3/4 (Linux-based hubs)
    - U-Boot header (bootloader)
    - Android sparse image
- [ ] **Firmware extraction:** If SquashFS/JFFS2 detected, use `unsquashfs` or `jefferson` to extract
- [ ] **OS detection:** Identify the underlying OS:
    - OpenWrt (routers, hubs)
    - Yocto/Buildroot (embedded Linux)
    - Android Things
    - RTOS (FreeRTOS, ThreadX)
- [ ] **Firmware version:** Extract version strings from `/etc/version`, `/etc/os-release`, `firmware_version`, or build.prop

**Flag Conditions:**
- [ ] Custom/unknown firmware with no version info — suspicious of tampering
- [ ] Outdated firmware with known CVEs — potential compromise vector
- [ ] Signed firmware with invalid signature — tampered firmware image

---

### Phase 2 — Configuration & Account Analysis

**Goal:** Extract device configuration, cloud accounts, and network settings.

- [ ] **Wireless credentials:** Extract SSID and passphrase from:
    - `wpa_supplicant.conf` (Linux/OpenWrt)
    - `/data/misc/wifi/wpa_supplicant.conf` (Android)
    - `nvram` dump (broadcom routers)
- [ ] **Cloud account tokens:** Search for OAuth tokens, refresh tokens, API keys:
    - Search strings output: `token`, `refresh_token`, `api_key`, `client_secret`, `aws.*key`, `secret`
    - Look for cloud service config files (CloudMQTT, AWS IoT, Azure IoT Hub connections)
- [ ] **Device registration:** Extract:
    - MAC address (network identifier)
    - Device serial number
    - Registration email or username
    - Cloud account ID (Echo/Google Home account linking)
- [ ] **Mobile app pairing:** Extract companion app configuration:
    - OAuth client IDs for mobile app communication
    - Push notification tokens (FCM/APNs)
- [ ] **Network configuration:** Extract:
    - Static IP, DHCP, DNS settings
    - NTP server (timeline correlation)
    - Proxy configuration (potential exfiltration indicator)
- [ ] **Time zone and locale:** Extract time zone setting for accurate timeline correlation

**Flag Conditions:**
- [ ] Wi-Fi credentials to corporate SSID — device on internal network
- [ ] Cloud API tokens present — pivot to cloud logs
- [ ] Unknown/disallowed cloud service endpoints — data exfiltration
- [ ] Static IP configuration — potential command and control infrastructure

---

### Phase 3 — Event & Log Analysis

**Goal:** Reconstruct device activity timeline from logs, events, and embedded databases.

- [ ] **System logs:** Extract from:
    - `logcat` (Android Things)
    - `syslog`, `/var/log/messages` (Linux)
    - `messages`, `log`, `event.log` (OpenWrt)
    - `journald` journal files
- [ ] **Application logs:** Scan for IoT-specific logs:
    - SmartThings: `hub.log`, `device.log`, `automation.log`
    - Echo: `alexa.log`, `voice.log`, `skill.log`
    - Arlo: `camera.log`, `event.log`, `stream.log`
    - Wink: `hub.log`, `device_log.db`
    - iSmartAlarm: `alarm.log`, `sensor.log`
- [ ] **Voice assistant history:** If Echo/Alexa device:
    - Extract `alexa_voice_history.db` or similar
    - Extract voice recordings (if present)
    - Check for smart home voice commands
- [ ] **Sensor event logs:** Extract sensor readings and automation triggers:
    - Motion sensor triggers
    - Door/window open/close events
    - Temperature/humidity readings
    - Camera motion detection events
- [ ] **Camera recordings:** If camera/Arlo device:
    - List recorded video files
    - Check local storage vs. cloud-only recording
    - Extract thumbnails for quick triage
- [ ] **Database analysis:** Open SQLite databases found in:
    - `/data/data/` (Android app data)
    - `/mnt/data/` or `/config/` (hub devices)
    - `event.db`, `history.db`, `sensor_data.db`
    - Query: `SELECT * FROM events ORDER BY timestamp DESC LIMIT 100`

**Flag Conditions:**
- [ ] Logs missing or truncated — potential tampering
- [ ] Unusual sensor events during off-hours — intrusion detection
- [ ] Camera events showing unauthorized access
- [ ] Voice commands to disarm security system
- [ ] Database encryption detected — app data protected

---

### Phase 4 — Cloud & Network Communications Analysis

**Goal:** Identify cloud endpoints, communication patterns, and potential compromise vectors.

- [ ] **Cloud endpoint analysis:** Extract all remote endpoints from device:
    - DNS query analysis (from network logs if available)
    - Hardcoded IPs in firmware binaries
    - MQTT broker addresses (common IoT protocol)
    - WebSocket endpoints (real-time device communication)
- [ ] **Firmware update servers:** Identify OTA update endpoints:
    - Check for `update_server`, `firmware_url`, `ota_server`
    - Compare with known legitimate update servers
- [ ] **Remote access/VPN:** Identify any VPN or remote access configuration:
    - `openvpn`, `wireguard` config files
    - `ssh` keys and authorized hosts
    - Reverse SSH tunnels
- [ ] **TLS certificate analysis:** Check for custom/self-signed certificates:
    - Look in `/etc/ssl/certs/`, `/data/misc/keychain/`
    - Certificate pinning configurations
- [ ] **Bluetooth/Wi-Fi Direct:** Extract BT pairing records and Wi-Fi Direct configuration:
    - Paired device MAC addresses
    - BT class of device (identifies paired phone types)
    - BT keys and link keys

**Flag Conditions:**
- [ ] Unknown/unauthorized cloud endpoints — data exfiltration or C2
- [ ] Custom certificates — potential MITM on device
- [ ] VPN or SSH tunneling — covert communication
- [ ] OTA update URL pointing to non-vendor server — firmware compromise
- [ ] Unknown Bluetooth pairing — physical proximity attack

---

### Phase 5 — Cross-Device & Timeline Correlation

**Goal:** Correlate IoT device activity with user-reported events, other devices, and network traffic.

- [ ] **User activity correlation:**
    - Compare IoT sensor events with user timeline (door unlock, motion detected, alarm triggered)
    - Cross-reference with mobile app activity (if companion app image available)
- [ ] **Network traffic correlation:**
    - Compare IoT device IPs with PCAP data (if available)
    - Look for IoT traffic spikes matching exfiltration playbook indicators
- [ ] **Automation rule analysis:**
    - Extract IFTTT, SmartThings, or Wink automation rules
    - Look for unexpected automation triggers (e.g., "When front door opens, send video to email")
- [ ] **Device timeline construction:**
    - Build device-first timeline from all log sources
    - Merge with host timeline if companion PC/mobile available
    - Identify gaps indicating device off-power or tampering

**Flag Conditions:**
- [ ] Automation rules modified without user knowledge — compromise
- [ ] Sensor events contradicting user alibi
- [ ] Device on during reported off-hours — automated compromise
- [ ] Multiple device failures/restarts around incident date

---

### Phase 6 — Reporting & IOC Extraction

**Goal:** Document IoT findings and extract actionable indicators.

- [ ] **Device profile:** Document:
    - Make, model, firmware version
    - MAC addresses, serial number
    - Cloud accounts linked
    - Network configuration
- [ ] **Timeline:** Generate IoT device activity timeline
- [ ] **IOCs to extract:**
    - IP addresses, domains, URLs (cloud endpoints)
    - OAuth tokens, API keys
    - Wi-Fi credentials
    - TLS certificate hashes
    - Bluetooth MAC addresses (paired devices)
    - Device serial numbers
- [ ] **Correlation findings:**
    - How the IoT device relates to the incident
    - Evidence of compromise (tampered logs, modified automation rules)
    - Data exfiltration indicators via IoT channel

---

## Tools Required
- `file` — filesystem/format identification
- `strings` — string extraction
- `sqlite3` — database analysis
- `unsquashfs` — SquashFS extraction (may not be installed)
- `jefferson` — JFFS2 extraction (may not be installed)
- `mmls`/`fls`/`icat` (SleuthKit) — filesystem exploration
- `objdump`/`readelf` — binary analysis (if deeper firmware analysis needed)

---

## Playbook Wiring
- **Trigger:** IoT device evidence detected during PB-SIFT-000 triage
- **Priority:** After core PB-001 through PB-005, runs in parallel with evidence-type playbooks
- **Re-run:** Always, but Phase 1-3 only if new IoT evidence discovered since last run
- **Playbook depends on:** Phase 1-3 rely on mount (SleuthKit fsstat/fls), Phase 5 on timeline from PB-020

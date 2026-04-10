# PB-SIFT-011: Cloud & SaaS Artifact Analysis Playbook
## Cloud & SaaS Artifact Analysis — Static Image Analysis

**Objective:** High-fidelity detection and analysis of cloud-based data movement, SaaS application abuse, and the theft of cloud authentication tokens using the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Memory Analysis
- [ ] **Sync Client Detection:** Check for cloud sync client processes — flag `onedrive.exe`, `dropbox.exe`, `googledrivesync.exe` running at capture time.
- [ ] **Session Token Audit:** Check for active browser sessions authenticated to M365, Azure, or SaaS platforms — flag session tokens in memory.
- [ ] **Token Material Search:** Flag OAuth or SAML token material in process memory — stolen tokens allow cloud access without credentials.
- [ ] **CLI/Module Usage:** Check command lines — flag Azure CLI (`az`), M365 CLI, or PowerShell modules (`Connect-MsolService`, `Connect-AzureAD`, `Connect-ExchangeOnline`).
- [ ] **Endpoint Connectivity:** Flag any process holding an active connection to Microsoft Graph, Exchange Online, or SharePoint endpoints.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources.
- [ ] **Sync Correlation:** Flag cloud sync client activity correlated with bulk file access — OneDrive sync of sensitive files.
- [ ] **Session Initiation:** Flag Azure AD or M365 PowerShell session initiation timestamps.
- [ ] **Temporal Anomalies:** Flag browser authentication events to cloud platforms outside business hours.
- [ ] **Staging Sync:** Correlate local file staging timestamps with cloud sync activity windows.
- [ ] **Token Cache Activity:** Flag token cache file creation or modification — indicates new cloud authentication session established.

---

### Phase 4 — Disk Artifacts

#### 4.1 — Microsoft 365 & Azure Artifacts
- [ ] **Token Cache Search:** Check for M365 / Azure CLI token caches — flag `%USERPROFILE%\.azure\`, `%USERPROFILE%\.m365\`.
- [ ] **Vault Audit:** Check for cached Exchange or SharePoint credentials in Windows Credential Manager (vault artifacts).
- [ ] **Module Cache:** Flag PowerShell module usage artifacts — `ExchangeOnlineManagement`, `AzureAD`, `MSOnline` in module cache.
- [ ] **Export Detection:** Check for exported M365 data on disk — PST exports, SharePoint downloads, Teams chat exports.
- [ ] **Artifact Search:** Flag `.json` token files or `accessToken` artifacts in user profile or temp directories.
- [ ] **Recon Output:** Check for Entra ID / Azure AD reconnaissance output — `Get-AzureADUser`, `Get-MsolUser` output files.

#### 4.2 — OneDrive & SharePoint Artifacts
- [ ] **Log Analysis:** Check OneDrive sync client logs — `%USERPROFILE%\AppData\Local\Microsoft\OneDrive\logs\`.
- [ ] **Bulk Sync Events:** Flag bulk sync events — large number of files synced in a short window.
- [ ] **Account Audit:** Check `SyncDiagnostics.log` for connected accounts — flag personal accounts syncing corporate data.
- [ ] **SharePoint Access:** Flag SharePoint `_layouts` or document library access in browser history.
- [ ] **Folder Redirection:** Check for OneDrive known folder move artifacts — Desktop, Documents, Pictures redirected to cloud.

#### 4.3 — Teams & Communication Artifacts
- [ ] **Client Artifacts:** Check Teams client artifacts — `%APPDATA%\Microsoft\Teams\` — flag chat logs, shared files, and meeting recordings.
- [ ] **Guest Access:** Flag external user communications in Teams artifacts — guest access conversations.
- [ ] **Sensitive Sharing:** Check for sensitive files shared via Teams to external parties.
- [ ] **Cache Analysis:** Flag Teams token cache — `%APPDATA%\Microsoft\Teams\Cache\` may contain session material.
- [ ] **Export Activity:** Check for bulk message export or screen capture activity correlated with Teams sessions.

#### 4.4 — Browser-Based Cloud Access
- [ ] **History Audit:** Check browser history for M365, Azure Portal, SharePoint, and SaaS platform access.
- [ ] **Admin Access:** Flag access to Azure Portal or Entra ID admin centers from this endpoint.
- [ ] **Cache Scan:** Check browser cache for downloaded cloud-stored documents or configuration exports.
- [ ] **OAuth Consent:** Flag OAuth consent grant pages in browser history — attacker may have authorized a malicious app.
- [ ] **Secret Store Access:** Check for access to cloud-based password managers or secret stores — `vault.bitwarden.com`, `1password.com`.

#### 4.5 — SaaS Application Artifacts
- [ ] **SaaS Client Search:** Check for Salesforce, ServiceNow, or other SaaS client artifacts in browser or app cache.
- [ ] **Secret Storage:** Flag API key or token files stored in user profile or application directories.
- [ ] **Data Exports:** Check for SaaS data exports downloaded to disk — CSV exports, report downloads, bulk record extracts.
- [ ] **Client Audit:** Flag installed SaaS desktop clients and their authentication artifact locations.
- [ ] **Refresh Tokens:** Check for OAuth refresh tokens stored in application config files — long-lived access risk.

#### 4.6 — Cloud Storage & Sync Tools
- [ ] **Cloud Sync Detection:** Flag personal cloud storage clients — Dropbox, Google Drive, Mega, Box installed or run.
- [ ] **Sync Volume Audit:** Check sync logs for volume and destination of synced data.
- [ ] **Rclone Configs:** Flag `rclone` config files pointing to cloud storage destinations — `%APPDATA%\rclone\rclone.conf`.
- [ ] **AzCopy Usage:** Check for `azcopy` usage artifacts — Microsoft's own tool frequently abused for bulk Azure blob exfiltration.
- [ ] **Cross-Cloud Access:** Flag AWS CLI or gcloud credential files in user profile — cross-cloud access from corporate endpoint.

---

### Phase 5 — Event Log Analysis
- [ ] **Cloud PowerShell:** Flag PowerShell connections to cloud endpoints (EID 4103 / 4104) — `Connect-ExchangeOnline`, `Connect-AzureAD`.
- [ ] **CLI Execution:** Flag `azcopy` or Azure CLI execution (EID 4688) — especially with blob storage or export arguments.
- [ ] **Credential Storage:** Flag new credential manager entries (EID 5379 / 5381) — cloud credentials stored during session.
- [ ] **Graph Connectivity:** Flag network connections to Microsoft Graph (`graph.microsoft.com`) from non-standard processes (EID 5156).
- [ ] **External Tenants:** Flag outbound connections to AWS, GCP, or non-corporate Azure tenants.
- [ ] **Cloud Persistence:** Flag scheduled tasks or services invoking cloud CLI tools — automated cloud access persistence.

---

### Phase 6 — YARA Scan
- [ ] **Token Patterns:** Scan for OAuth token patterns in user profile and temp directories — flag Bearer token strings.
- [ ] **Cloud Secrets:** Scan for AWS access key patterns (`AKIA...`) or Azure SAS token strings on disk.
- [ ] **Cloud Tools:** Scan for known cloud exfiltration tool signatures — `azcopy`, `rclone`, `cloudfox`, `stormspotter`.
- [ ] **Module Analysis:** Scan PowerShell script artifacts for cloud enumeration or exfiltration module usage.
- [ ] **Hit Documentation:** Flag any hits with platform, credential type, and location.

---

### Phase 7 — Network IOC Extraction
- [ ] **Endpoint Harvesting:** Extract all cloud platform endpoints accessed — flag non-corporate tenant IDs in M365/Azure URLs.
- [ ] **Shadow IT:** Flag access to shadow IT cloud services — unsanctioned SaaS platforms.
- [ ] **Transfer Volume:** Flag large data transfers to cloud storage endpoints — volume and destination.
- [ ] **Graph API Audit:** Flag Microsoft Graph API calls from non-standard processes or outside business hours.
- [ ] **Cross-Tenant Pivot:** Flag cross-tenant access patterns — corporate credentials used to access external Azure AD tenants.
- [ ] **Intel Enrichment:** Enrich all cloud IOCs against known malicious infrastructure and tenant reputation feeds.

---

### Phase 8 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK:
    - **T1528:** Cloud Account Credential Theft
    - **T1539:** Steal Web Session Cookie
    - **T1619:** Cloud Storage Object Discovery
    - **T1567.002:** Exfiltration to Cloud Storage
    - **T1114.002:** Email Collection — Remote Email
    - **T1114.003:** Email Forwarding Rule
    - **T1550.001:** OAuth Application Abuse
    - **T1526:** Cloud Service Discovery
    - **T1552.005:** Unsecured Credentials — Cloud Instance Metadata
    - **T1078.004:** Valid Accounts — Cloud Accounts
- [ ] **Platform Scope:** Identify which cloud platforms and tenants were accessed or compromised.
- [ ] **Pivot Mapping:** Flag any cross-tenant or cross-platform pivot — attacker moving from endpoint to cloud to SaaS.
- [ ] **Token Risk:** Assess token validity risk — flag any OAuth or session tokens found that may still be active.
- [ ] **Final Output:** Score by severity — output structured findings file for analyst handoff.

---

**⚠️ Analysis Note:** Cloud artifacts on a local image represent only one side of the picture. Findings here should be correlated with cloud-side logs (Entra ID sign-in logs, M365 Unified Audit Log, Azure Monitor) for full fidelity. Flag all cloud IOCs for follow-up cloud log review.

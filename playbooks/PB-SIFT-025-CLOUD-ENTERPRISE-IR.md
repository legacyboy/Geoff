# PB-SIFT-025: Cloud & Enterprise IR Playbook
## Cloud & Enterprise IR — M365 / Azure AD / AWS CloudTrail

**Objective:** Forensic analysis of cloud-based attack activity using Microsoft 365 Unified Audit Log, Azure AD sign-in logs, conditional access bypass artifacts, OAuth abuse indicators, and AWS CloudTrail events.
**Specialist:** `logs`, `browser`, `registry`, `email`, `cloud`, `sleuthkit`
**MITRE Mapping:** T1078.004 (Valid Accounts: Cloud Accounts), T1136.003 (Create Account: Cloud Account), T1528 (Steal Application Access Token), T1550.001 (Pass the Token), T1606 (Forge Web Credentials), T1530 (Data from Cloud Storage)

---

## Phase 1 — M365 Unified Audit Log (UAL)

**Goal:** Extract and triage Microsoft 365 Unified Audit Log records to identify account compromise, privilege abuse, data access, and Business Email Compromise (BEC) indicators.

### 1.1 — UAL Export & Ingestion (`logs.parse_evtx`)
- [ ] Export UAL via `Search-UnifiedAuditLog` PowerShell cmdlet or the Microsoft Purview compliance portal export
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` or direct JSON/CSV parsing for portal exports
- [ ] Confirm coverage: UAL retention is 90 days (standard) or 1 year (E3/E5) — document gaps
- [ ] Validate record types present: `ExchangeAdmin`, `SharePointFileOperation`, `AzureActiveDirectory`, `MicrosoftTeams`, `OneDrive`, `MicrosoftForms`
- [ ] Sort by `CreationTime` to establish chronological event sequence

### 1.2 — Impossible Travel Detection
- [ ] Extract all `UserLoggedIn` and `MailboxLogin` events per user account
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: UserLoggedIn`
- [ ] Calculate time delta between consecutive logins from geographically distant IPs for same account
- [ ] Flag: login from two IPs separated by >1,000 km within <60 minutes — physically impossible travel indicator
- [ ] Correlate flagged IP pairs with ASN and geolocation data
- [ ] Cross-reference with known VPN or proxy exit nodes to reduce false positives

### 1.3 — Privilege Escalation in Azure AD
- [ ] Filter UAL for `AzureActiveDirectory` record type
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: Add member to role`
- [ ] Flag: any `Add member to role` operation — document actor, target account, and role assigned
- [ ] Flag: `Add eligible member to role` (PIM activation — may indicate role hijacking)
- [ ] Flag: `Add application` or `Add service principal` operations by non-admin accounts
- [ ] Flag: `Update user` operations modifying `StrongAuthenticationMethods` (MFA manipulation)

### 1.4 — BEC Inbox Rule & Forwarding Detection
- [ ] Filter UAL for `ExchangeAdmin` record type and mailbox rule operations
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: New-InboxRule, Set-Mailbox`
- [ ] Flag: `Set-Mailbox -ForwardingSmtpAddress` — auto-forward to external address (BEC exfiltration)
- [ ] Flag: `Set-Mailbox -DeliverToMailboxAndForward $true` — silent copy forwarding
- [ ] Flag: `New-InboxRule` with `-ForwardTo`, `-RedirectTo`, or `-DeleteMessage $true` parameters
- [ ] Flag: inbox rules created outside business hours or from unfamiliar IP addresses
- [ ] Extract destination forwarding addresses and pivot to threat intelligence lookups

### 1.5 — Mass File Access in SharePoint
- [ ] Filter UAL for `SharePointFileOperation` record type
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: FileDownloaded`
- [ ] Flag: >100 `FileDownloaded` operations from a single account within 10 minutes
- [ ] Flag: access to document libraries outside the user's normal department or team
- [ ] Flag: `FileAccessed` events on files with HR, Finance, Legal, or Executive in the path
- [ ] Aggregate by user and time window to identify bulk data collection patterns

### 1.6 — OAuth Application Consent Grants
- [ ] Filter UAL for `AzureActiveDirectory` record type — consent operations
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: Add OAuth2PermissionGrant, Consent to application`
- [ ] Flag: `Add OAuth2PermissionGrant` events — documents which permissions were granted to which app
- [ ] Flag: `Consent to application` by non-admin users (user-level OAuth consent — phishing app authorization)
- [ ] Extract `AppId`, `AppDisplayName`, and granted `Scope` values for each consent event
- [ ] Cross-reference app IDs against known malicious OAuth application lists
- [ ] Flag apps with broad permissions (`Mail.Read`, `Files.ReadWrite.All`, `User.ReadWrite.All`) granted by users

### 1.7 — Recon via eDiscovery
- [ ] Filter UAL for `SecurityComplianceCenter` record type
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: SearchCreated, SearchStarted, ExportInitiated`
- [ ] Flag: eDiscovery searches or content searches initiated by non-eDiscovery administrator accounts
- [ ] Flag: keyword searches targeting sensitive content (passwords, credentials, salary, board)
- [ ] Flag: large export operations by accounts not in an authorized investigation role

---

## Phase 2 — Azure AD Sign-In Logs

**Goal:** Analyze Azure AD interactive and non-interactive sign-in logs to identify authentication anomalies, MFA bypass, legacy protocol abuse, and token replay.

### 2.1 — Sign-In Log Export & Ingestion (`logs.parse_evtx`)
- [ ] Export sign-in logs via Azure AD portal or Microsoft Graph API (`/auditLogs/signIns`)
- [ ] **Specialist Method:** `logs.parse_evtx(azure_signin_log_path)` with JSON format parsing
- [ ] Separate interactive sign-ins from non-interactive (service-to-service) sign-ins
- [ ] Confirm log retention coverage — Azure AD sign-in logs retained 30 days (free tier) or 90 days (P1/P2)
- [ ] Document any gaps in coverage and note in chain of custody

### 2.2 — Legacy Authentication Protocol Abuse
- [ ] Filter sign-in logs by `clientAppUsed` field — legacy clients bypass MFA
- [ ] **Specialist Method:** `logs.parse_evtx(azure_signin_log_path)` filtering `clientAppUsed` != `Browser` and != `Mobile Apps and Desktop clients`
- [ ] Flag: sign-ins via `SMTP`, `IMAP4`, `POP3`, `Exchange ActiveSync`, `Exchange Web Services`, `Other clients`
- [ ] Flag: successful legacy auth sign-ins from IPs where modern auth also occurs — parallel session indicator
- [ ] Legacy authentication protocols cannot enforce MFA — successful logins bypass all MFA policies
- [ ] Cross-reference legacy auth source IPs with threat intelligence

### 2.3 — Conditional Access Policy Failures
- [ ] Filter sign-in logs by `conditionalAccessStatus` field
- [ ] **Specialist Method:** `logs.parse_evtx(azure_signin_log_path)` filtering `conditionalAccessStatus: failure`
- [ ] Flag: repeated Conditional Access failures from the same account — policy bypass attempts
- [ ] Flag: failures followed by success shortly after (indicates evasion or policy gap exploitation)
- [ ] Document which Conditional Access policies failed and what conditions were not met
- [ ] Flag: sign-ins with `authenticationRequirement: singleFactorAuthentication` for accounts expected to use MFA

### 2.4 — Risk Events & Risky Users
- [ ] Query Microsoft Identity Protection via Graph API: `riskyUsers`, `riskDetections` endpoints
- [ ] **Specialist Method:** `logs.parse_evtx(azure_signin_log_path)` supplemented with risk detection JSON exports
- [ ] Flag: `anonymizedIPAddress`, `malwareInfectedIPAddress`, `suspiciousInboxManipulationRules`, `unfamiliarFeatures` risk detections
- [ ] Flag: accounts in `atRisk` or `confirmedCompromised` state — document when risk was first detected
- [ ] Correlate risk detection timestamps with UAL events from Phase 1

### 2.5 — Anonymizing Proxy & TOR Sign-Ins
- [ ] Filter sign-in logs by `ipAddress` — cross-reference against TOR exit node lists and known proxy ASNs
- [ ] **Specialist Method:** `logs.parse_evtx(azure_signin_log_path)` combined with IP reputation enrichment
- [ ] Flag: successful sign-ins from TOR exit nodes
- [ ] Flag: successful sign-ins from anonymizing proxies (known VPN/proxy ASNs: AS9009, AS209854, AS60068 etc.)
- [ ] Flag: sign-ins from Hosting/Cloud provider IP ranges not associated with corporate infrastructure (AWS, DO, Vultr lateral use for proxy)

### 2.6 — Token Replay Detection
- [ ] Analyze sign-in logs for same `correlationId` or identical refresh token fingerprints from different source IPs
- [ ] **Specialist Method:** `logs.parse_evtx(azure_signin_log_path)` grouping by `userId` and `tokenIssuedAt`
- [ ] Flag: non-interactive sign-ins using the same token reused from a different IP than original issuance
- [ ] Flag: service principal sign-ins with unusual frequency or from unexpected IP ranges
- [ ] Correlate token issuance timestamps with endpoint browser artifact timestamps (Phase 3)

- [ ] **Azure AD Sign-In Deep Correlation:**
    - **Specialist Method:** `logs.parse_evtx(azure_signin_log_path)` with full field extraction including `deviceDetail`, `location`, `appliedConditionalAccessPolicies`, `authenticationDetails`
    - Cross-correlate `resourceDisplayName` with sensitivity — flag sign-ins to `Exchange Online`, `SharePoint Online`, `Azure Resource Manager`, `Key Vault`
    - Correlate `isInteractive: false` sign-ins with UAL mailbox access events — non-interactive auth feeding mail access is a BEC indicator
    - **Flag as CRITICAL:** Successful sign-ins after multiple Conditional Access failures — policy gap exploitation
    - **Flag as CRITICAL:** Token refresh from IP >500km from original token issuance location
    - **Flag as HIGH:** Legacy auth success followed by immediate mailbox rule creation (automated BEC playbook execution)
- **SANS FOR509 Alignment:** Azure AD sign-in log analysis is **★★★★★** for cloud IR — SANS FOR509 (Enterprise Cloud Forensics) identifies sign-in log correlation with UAL as the primary detection chain for BEC and cloud account takeover. Legacy authentication bypass is the most common MFA evasion technique in cloud environments.

---

## Phase 3 — OAuth & Application Abuse

**Goal:** Identify malicious OAuth application consents, stolen access tokens, and Primary Refresh Token (PRT) theft artifacts.

### 3.1 — Malicious OAuth App Consent Analysis
- [ ] Correlate UAL `Add service principal` events with `Consent to application` events by timestamp and actor
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: Add service principal`
- [ ] Flag: service principal additions from user accounts (non-admin) — illicit consent grant attack
- [ ] Flag: applications registered outside the organization's tenant
- [ ] Extract `servicePrincipalId`, `appId`, and `displayName` for all flagged apps
- [ ] Check app registrations against Microsoft's known malicious app database and threat intelligence

### 3.2 — Application Permission Audit
- [ ] Export Azure AD application permissions via `Get-AzureADServicePrincipal` or Graph API
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` combined with Graph API application export
- [ ] Flag applications with any of the following delegated or application permissions:
  - `Mail.Read`, `Mail.ReadWrite` — email access
  - `Files.ReadWrite.All`, `Sites.ReadWrite.All` — SharePoint/OneDrive full access
  - `User.ReadWrite.All` — user account modification
  - `Directory.ReadWrite.All` — Azure AD directory modification
  - `RoleManagement.ReadWrite.Directory` — role assignment capability
- [ ] Flag applications created within 30 days of incident window with broad permissions

### 3.3 — Endpoint Token Cache Artifacts (`browser.extract_cookies`)
- [ ] Examine endpoint for token cache artifacts at:
  - `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache\` — WAM token broker cache
  - `%APPDATA%\Microsoft\Identity\` — MSAL token cache
  - `%LOCALAPPDATA%\Microsoft\IdentityCache\` — additional identity caches
- [ ] **Specialist Method:** `browser.extract_cookies(profile_path)` for browser-stored tokens; `registry.extract_keys` for identity artifacts
- [ ] Parse WAM cache files — contain refresh tokens for Microsoft services
- [ ] Flag token cache files with modification timestamps during or after incident window

### 3.4 — Browser Token Theft Artifacts (`browser.extract_cookies`)
- [ ] Extract browser credential and cookie stores:
  - Chrome/Edge: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`
  - Chrome/Edge: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies`
  - Chrome/Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies`
- [ ] **Specialist Method:** `browser.extract_cookies(profile_path)` targeting `login.microsoftonline.com` cookies
- [ ] Flag: `ESTSAUTH`, `ESTSAUTHPERSISTENT` cookies for `login.microsoftonline.com` — Azure AD session tokens
- [ ] Flag: cookie access or extraction timestamps near incident window
- [ ] Cross-reference with browser history for attacker reconnaissance of cloud portals

### 3.5 — PRT Theft Indicators (`registry.extract_keys`)
- [ ] Extract device join status artifacts:
  - Run `dsregcmd /status` output (if live system) or parse from memory dump
  - Registry: `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\`
- [ ] **Specialist Method:** `registry.extract_keys(system_hive, "SYSTEM\CurrentControlSet\Control\CloudDomainJoin")`
- [ ] Flag: device not joined to expected Azure AD tenant (device join spoofing)
- [ ] Flag: modifications to PRT-related registry keys during incident window
- [ ] Correlate with Azure AD sign-in logs — PRT theft enables token generation without MFA

---

## Phase 4 — Exchange / M365 Mail Forensics

**Goal:** Investigate mailbox manipulation, forwarding rules, delegation abuse, and Business Email Compromise exfiltration patterns.

### 4.1 — Auto-Forwarding & Inbox Rule Analysis (`email.analyze_pst`)
- [ ] Export mailbox rules via `Get-InboxRule -Mailbox <UPN>` PowerShell or EAC
- [ ] **Specialist Method:** `email.analyze_pst(export_path)` for local PST/OST cache artifacts
- [ ] Flag: any inbox rule redirecting or forwarding to external email addresses
- [ ] Flag: inbox rules with `-DeleteMessage $true` — evidence destruction pattern
- [ ] Flag: rules that move emails to Deleted Items or obscure folders based on keywords (financial, invoice, payment)
- [ ] Flag: rules created at unusual times (outside business hours, concurrent with sign-in anomalies)
- [ ] Document rule creation timestamp from UAL `New-InboxRule` operation

### 4.2 — Delegate Access Abuse
- [ ] Review mailbox delegation grants via `Get-MailboxPermission` and `Get-RecipientPermission`
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: Add-MailboxPermission`
- [ ] Flag: `Add-MailboxPermission -AccessRights FullAccess` grants to external or unexpected accounts
- [ ] Flag: `Add-RecipientPermission -AccessRights SendAs` grants — allows impersonation
- [ ] Flag: `Add-MailboxFolderPermission` granting access to sensitive folders (Inbox, Sent Items)
- [ ] Correlate delegate grants with `MailboxLogin` and `SendAs` UAL operations by the grantee

### 4.3 — Mass Email Deletion (Evidence Destruction)
- [ ] Filter UAL for `SoftDelete`, `HardDelete`, `MoveToDeletedItems` operations
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: SoftDelete, HardDelete`
- [ ] Flag: bulk deletion (>50 items) in a short time window from a single session
- [ ] Flag: deletion of emails containing keywords matching known BEC lures (invoice, payment, wire transfer)
- [ ] Note: Deleted items may be recoverable from Recoverable Items folder if litigation hold is enabled

### 4.4 — Message Trace Analysis
- [ ] Initiate `Start-HistoricalSearch` or query the MessageTrace API for sender/recipient/subject correlation
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` supplemented with MessageTrace export
- [ ] Flag: emails sent from compromised account to external financial or vendor contacts during incident window
- [ ] Flag: emails sent `OnBehalfOf` or `SendAs` another user without authorization
- [ ] Flag: large attachments sent externally from sensitive mailboxes during or after suspicious sign-in

### 4.5 — Local PST/OST Cache Forensics (`email.analyze_pst`)
- [ ] Locate Outlook data files on endpoint:
  - `%LOCALAPPDATA%\Microsoft\Outlook\*.ost`
  - `%USERPROFILE%\Documents\Outlook Files\*.pst`
- [ ] **Specialist Method:** `email.analyze_pst(export_path)` for local cache artifacts
- [ ] Parse OST file for deleted item recovery (Outlook caches deleted items locally)
- [ ] Extract email timestamps, recipients, and attachments from local cache
- [ ] Correlate local email activity with UAL server-side events for completeness

---

## Phase 5 — SharePoint / OneDrive Forensics

**Goal:** Identify bulk data exfiltration, unauthorized sharing, and sensitive label manipulation in SharePoint and OneDrive.

### 5.1 — Bulk File Download Detection
- [ ] Filter UAL for `SharePointFileOperation` with `FileDownloaded` operation
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: FileDownloaded`
- [ ] Aggregate `FileDownloaded` events per user per 10-minute window
- [ ] Flag: >100 file downloads from a single account within 10 minutes — automated exfiltration indicator
- [ ] Extract site URLs and file names to determine sensitivity of accessed data
- [ ] Correlate with impossible travel findings (Phase 1.2) — bulk download from attacker-held session

### 5.2 — External Sharing Link Creation
- [ ] Filter UAL for `AnonymousLinkCreated`, `SecureLinkCreated`, `SharingSet` operations
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: AnonymousLinkCreated`
- [ ] Flag: `AnonymousLinkCreated` — public link with no authentication requirement
- [ ] Flag: `SecureLinkCreated` sharing to external (outside tenant) email addresses
- [ ] Flag: sharing links created for files in HR, Legal, Finance, Executive, or Confidential libraries
- [ ] Document link creation times and recipients for exfiltration timeline

### 5.3 — Sensitivity Label Removal
- [ ] Filter UAL for `SensitivityLabelRemoved`, `SensitivityLabelChanged` operations
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: SensitivityLabelRemoved`
- [ ] Flag: any sensitivity label removal on files — preparation for unauthorized sharing
- [ ] Flag: label downgrade (e.g., Confidential → General) on sensitive documents
- [ ] Correlate label changes with subsequent download or sharing events

### 5.4 — Document Library Access Patterns
- [ ] Analyze `FileAccessed` and `PageViewed` operations across sensitive document libraries
- [ ] **Specialist Method:** `logs.parse_evtx(ual_export_path)` filtering on `Operation: FileAccessed`
- [ ] Flag: access to libraries outside the user's normal department or job function
- [ ] Flag: access to sensitive site collections (HR, Finance, Legal, Board) by non-authorized accounts
- [ ] Build a per-account access heatmap across site collections to identify recon behavior

### 5.5 — OneDrive Local Sync Client Forensics (`cloud.analyze_onedrive`)
- [ ] Locate OneDrive sync artifacts on endpoint:
  - `%USERPROFILE%\OneDrive\` — synced file location
  - `%LOCALAPPDATA%\Microsoft\OneDrive\logs\` — sync client logs
  - `%LOCALAPPDATA%\Microsoft\OneDrive\settings\` — account configuration
- [ ] **Specialist Method:** `cloud.analyze_onedrive(sync_path)` for local endpoint artifacts
- [ ] Parse sync client logs for mass sync operations during incident window
- [ ] Cross-reference with PB-SIFT-030 for full cloud sync artifact methodology
- [ ] Flag: sync client configured to sync organization-wide or all-user libraries (unusual scope)

---

## Phase 6 — AWS CloudTrail (If Applicable)

**Goal:** Analyze AWS CloudTrail logs to detect unauthorized API activity, privilege escalation, data exfiltration, and persistence in AWS environments.

### 6.1 — CloudTrail Log Acquisition & Integrity
- [ ] Locate CloudTrail logs in S3 bucket: `s3://[bucket]/AWSLogs/[account-id]/CloudTrail/[region]/`
- [ ] **Specialist Method:** Direct JSON parsing of CloudTrail log files (gzip-compressed JSON)
- [ ] Verify CloudTrail log file validation: check `DigestFiles` for gaps in coverage
- [ ] Flag: missing time periods in log sequence — potential log tampering or deletion
- [ ] Confirm CloudTrail is enabled for all regions — single-region trails miss global service events
- [ ] Verify CloudTrail S3 bucket MFA delete status and access logging

### 6.2 — High-Value API Call Detection
- [ ] Parse CloudTrail `eventName` fields for high-sensitivity API calls
- [ ] **Specialist Method:** Direct JSON parsing of CloudTrail log files filtering on `eventName`
- [ ] Flag immediately:
  - `GetSecretValue` — Secrets Manager secret access (credentials)
  - `GetObject` — S3 object retrieval (potential data exfiltration)
  - `CreateUser` — new IAM user creation (persistence)
  - `AttachUserPolicy` / `AttachRolePolicy` — permission escalation
  - `CreateAccessKey` — new programmatic credential creation (persistence)
  - `PutBucketPolicy` — S3 bucket policy modification (data exposure)
  - `StopLogging` — CloudTrail disabled (anti-forensics indicator — CRITICAL)
  - `DeleteTrail` — CloudTrail deleted (CRITICAL)
- [ ] Correlate high-value API calls with their `sourceIPAddress` and `userAgent` fields

### 6.3 — Privilege Escalation Chain Detection
- [ ] Analyze CloudTrail for IAM privilege escalation chains
- [ ] **Specialist Method:** Direct JSON parsing of CloudTrail log files building `userIdentity` → permission chains
- [ ] Flag: `CreateRole` + `AttachRolePolicy` + `AssumeRole` chains — privilege escalation via role assumption
- [ ] Flag: `PutUserPolicy` / `PutGroupPolicy` — inline policy attachment bypassing managed policy monitoring
- [ ] Flag: `AddUserToGroup` adding accounts to groups with `AdministratorAccess`
- [ ] Flag: `PassRole` actions enabling privilege escalation via services (EC2, Lambda, ECS)
- [ ] Document full escalation chain: initial `userIdentity.arn` → final assumed role ARN

### 6.4 — Data Exfiltration via S3
- [ ] Analyze S3 `GetObject` events for bulk access patterns
- [ ] **Specialist Method:** Direct JSON parsing of CloudTrail log files aggregating `GetObject` by `userIdentity.arn` and time window
- [ ] Flag: >1,000 `GetObject` calls in a single hour from one identity
- [ ] Flag: `GetObject` calls from IPs outside expected geographic range for the account
- [ ] Flag: bucket cross-account replication configuration changes (`PutBucketReplication`)
- [ ] Correlate S3 access logs (if enabled) with CloudTrail for byte-level transfer confirmation

### 6.5 — Persistence Mechanisms
- [ ] Scan CloudTrail for AWS-specific persistence patterns
- [ ] **Specialist Method:** Direct JSON parsing of CloudTrail log files filtering persistence-relevant event names
- [ ] Flag: `CreateUser` — new IAM user (persistent access account)
- [ ] Flag: `CreateAccessKey` for existing users — new programmatic credentials
- [ ] Flag: `CreateLoginProfile` / `UpdateLoginProfile` — console access addition
- [ ] Flag: Lambda function creation (`CreateFunction`) or update (`UpdateFunctionCode`) — backdoor execution
- [ ] Flag: `CreateScheduledAction` (AWS Auto Scaling) or CloudWatch Events rules pointing to Lambda
- [ ] Flag: `AssumeRoleWithWebIdentity` using stolen identity tokens from external IdP

### 6.6 — CloudTrail Integrity & Anti-Forensics
- [ ] Verify CloudTrail log file validation digest chain is unbroken
- [ ] **Specialist Method:** Direct JSON parsing of CloudTrail digest files — validate SHA-256 hashes of log files
- [ ] Flag: any `StopLogging`, `DeleteTrail`, or `UpdateTrail` (disabling validation) events
- [ ] Flag: S3 bucket policy changes on the logging bucket enabling public access
- [ ] Flag: GuardDuty `DisassociateFromMasterAccount` or `DeleteDetector` — disabling threat detection
- [ ] Note: Even if CloudTrail is deleted, events may be preserved in EventBridge, SIEM, or S3 access logs

---

## Phase 7 — Cross-Platform Correlation

**Goal:** Correlate cloud-layer events with endpoint artifacts to build a complete attack timeline spanning identity, cloud, and endpoint layers.

### 7.1 — Cloud Sign-In to Endpoint Login Correlation
- [ ] Extract Azure AD sign-in timestamps from Phase 2 and correlate with Windows Security Event ID 4624
- [ ] **Specialist Method:** `logs.parse_evtx(security_evtx, event_ids=[4624, 4625])` cross-referenced with Azure AD log timestamps
- [ ] Match source IP from Azure AD sign-in to workstation IP in domain logon events
- [ ] Flag: Azure AD interactive logon without corresponding endpoint session — session cookie theft indicator
- [ ] Flag: simultaneous Azure AD session and endpoint session from different IPs for same account

### 7.2 — UAL Exfiltration Events vs. Endpoint MFT Timeline
- [ ] Correlate SharePoint `FileDownloaded` timestamps from Phase 5 with endpoint MFT file creation timestamps
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting user Downloads, Desktop, and temp paths
- [ ] Flag: files matching UAL-exfiltrated filenames appearing in local Downloads folders
- [ ] Flag: staging directories (zip archives, RAR files) created shortly after bulk SharePoint access
- [ ] Cross-reference with `plaso.create_timeline` for unified timestamp correlation

### 7.3 — OAuth Token Theft Timeline Correlation
- [ ] Align Phase 3 browser cookie extraction timestamps with Phase 2 token replay sign-ins
- [ ] **Specialist Method:** `browser.extract_cookies(profile_path)` timestamp extraction correlated with Azure AD `tokenIssuedAt`
- [ ] Flag: browser cookie modification timestamps preceding anomalous non-interactive sign-ins by <5 minutes
- [ ] Correlate browser history access to `login.microsoftonline.com` with identity protection risk detections

### 7.4 — Cloud Persistence to Endpoint Execution Timeline
- [ ] Map cloud-layer persistence (forwarding rules, rogue OAuth apps, new IAM users) to endpoint execution artifacts
- [ ] **Specialist Method:** `plaso.create_timeline(evidence_paths)` incorporating cloud log timestamps
- [ ] Correlate UAL `New-InboxRule` timestamps with endpoint PowerShell execution artifacts (Prefetch, Script Block Logs)
- [ ] Flag: PowerShell execution on endpoint immediately preceding cloud configuration changes — attacker scripting cloud modifications locally
- [ ] Build unified kill-chain timeline: Initial Access → Cloud Credential Theft → Cloud Persistence → Data Exfiltration

### 7.5 — AWS + Azure Cross-Cloud Correlation (If Applicable)
- [ ] Correlate CloudTrail `sourceIPAddress` with Azure AD sign-in `ipAddress` for same attacker IP
- [ ] **Specialist Method:** Direct JSON parsing of both CloudTrail and Azure AD sign-in logs with IP-pivot analysis
- [ ] Flag: same source IP appearing in both AWS and Azure/M365 logs — attacker operating across cloud platforms
- [ ] Correlate timing of AWS `CreateAccessKey` with Azure AD `Add service principal` — systematic credential creation

---

## Phase 8 — Scoring & Output

**Goal:** Prioritize findings for analyst handoff and incident response escalation.

- [ ] **Severity Matrix:**
  - **Critical:** Successful OAuth consent grant to malicious app with Mail.Read/Files.ReadWrite.All; confirmed token replay from different IP/geolocation; BEC forwarding rule active; AWS CloudTrail disabled or deleted; impossible travel sign-in with confirmed subsequent data access; Azure AD Global Administrator role assigned to unauthorized account
  - **High:** Legacy authentication success bypassing MFA; bulk SharePoint download (>100 files); external sharing links on sensitive documents; AWS `CreateUser` + `CreateAccessKey` for unknown identity; Conditional Access bypass confirmed; mass email deletion following sign-in anomaly
  - **Medium:** Single suspicious sign-in without confirmed follow-on activity; sensitivity label removal without confirmed exfiltration; inbox rule forwarding to internal but unexpected address; AWS `AssumeRole` from unexpected source
  - **Low:** Failed sign-in attempts without success; benign legacy auth from known app; standard administrative eDiscovery searches

- [ ] **MITRE ATT&CK Mapping:**
  - T1078.004 — Valid Accounts: Cloud Accounts
  - T1136.003 — Create Account: Cloud Account
  - T1528 — Steal Application Access Token
  - T1550.001 — Use Alternate Authentication Material: Application Access Token
  - T1550.004 — Use Alternate Authentication Material: Web Session Cookie
  - T1606.001 — Forge Web Credentials: Web Cookies
  - T1606.002 — Forge Web Credentials: SAML Tokens
  - T1530 — Data from Cloud Storage
  - T1114.003 — Email Collection: Email Forwarding Rule
  - T1098.001 — Account Manipulation: Additional Cloud Credentials
  - T1098.002 — Account Manipulation: Additional Email Delegate Permissions
  - T1098.003 — Account Manipulation: Additional Cloud Roles
  - T1566.002 — Phishing: Spearphishing Link (OAuth consent phishing)
  - T1539 — Steal Web Session Cookie
  - T1537 — Transfer Data to Cloud Account
  - T1020 — Automated Exfiltration
  - T1087.004 — Account Discovery: Cloud Account

- [ ] **Structured Output:** JSON with per-account finding summaries, flagged operations with timestamps, source IPs, affected resources, and severity scores
- [ ] **Analyst Handoff:** Bundle UAL exports, Azure AD sign-in JSON, CloudTrail logs, browser artifact extracts, and endpoint timeline for senior analyst review

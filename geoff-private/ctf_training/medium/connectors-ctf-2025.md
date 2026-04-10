# Connectors CTF 2025 — DFIR Challenges

## Document Analysis: Invoice_Q1–2021.doc
- **Malicious Document:** Contains macros and embedded scripts.
- **Macro Name:** PROJECT.AYAIQ5.AUTOOPEN (found in vbaData.xml).
- **Malicious Payload:** 
  - Base64 encoded JavaScript in document.xml.
  - **C2 Domain:** 5that6[.]com
  - **Payload File:** aZe4I.tmp (saved to C:\programdata\aZe4I.tmp)
  - **Execution Utility:** regsvr32
- **Analysis Technique:** Extraction of .doc as zip, analysis of XML files, and Base64 decoding via CyberChef.

## Disk Image Analysis (image.ad1)
- **User Profile:** tarok
- **Artifacts:** 
  - **UsrClass.dat:** Investigated for ShellBags.
  - **ShellBags:** BagMRU keys analyzed using Eric Zimmerman's ShellBags Explorer (required dumping UsrClass.dat.LOG1).

## Firefox & MetaMask Recovery
- **Browser:** Firefox
- **Evidence:** 
  - Firefox history (places.sqlite) showed searches for "metamask" and guides on recovering seed phrases.
  - MetaMask extension located at: C:\Users\Wh1pl4sh\AppData\Roaming\Mozilla\Firefox\fvdbjn8o.default-release\storage\default\moz-extension+++9d43d20e-c6b8-4b71-b6ad-5a503dedc147
  - Encrypted vault database: .../idb/3117620802mpeutkacmaabs-k.sqlite
- **Decryption Process:**
  - Used **MetaMask Vault Decryptor**.
  - Password recovery via **DPAPI**:
    - Masterkey file: AppData\Roaming\Microsoft\Protect\S-1-5-21-2430665207-3300790704-3908932582-1001\a3ef4996-d3ea-422c-9de1-62931c21fb47
    - User SID: S-1-5-21-2430665207-3300790704-3908932582-1001
    - Tool: DPAPImk2john to extract hash for cracking.
    - Recovered Password: iloveyou2
- **Result:** Decrypted vault to retrieve the Secret Backup Phrase.

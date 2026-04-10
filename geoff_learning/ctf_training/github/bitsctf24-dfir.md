# BITSCTF 24 DFIR Challenges Write-up

## Overview
Investigation of a compromise involving memory dumps, AD1 images, and PCAP files. Tools used: Volatility 3, FTK Imager, and Wireshark.

## Key Challenges & Findings

### 1. Password Recovery
- **Method:** Used windows.hashdump plugin in Volatility 3 to extract NTLM hashes from the memory dump.
- **Finding:** Cracked the hash to find the user password.

### 2. Initial Access & CVE Analysis
- **Vector:** User downloaded a malicious zip archive and an executable (lottery.exe).
- **Attack Technique:** Concealing malicious code within an archive using masquerading file formats (weaponized archive).
- **Software Vulnerability:** WinRAR zero-day exploit.
- **CVE:** CVE-2023-38831

### 3. Keylogging & HID Data Analysis
- **Artifact:** keylog.pcapng (USB keyboard traffic).
- **Analysis:** 
  - Exported HID data from USB packets to CSV.
  - Used the PUK tool to decode the HID keystrokes.
- **Finding:** Recovered a secret SOS message typed by the user.

### 4. TLS Decryption & Network Traffic
- **Artifacts:** PCAP file and a TLS key file extracted from the Desktop.
- **Method:** Imported the key file into Wireshark (Edit > Preferences > Protocols > TLS) to decrypt the traffic.
- **Finding:** Identified HTTP2 packets. Discovered a Pastebin link containing the flag after filtering for Pastebin traffic.

### 5. Ransomware Analysis (lottery.exe)
- **Tooling:** 
  - pyinstxtractor to extract content from the PyInstaller-packed executable.
  - uncompyle6 to decompile lottery.pyc.
- **Ransomware Logic:** 
  - Generates a random 32-byte key.
  - Uses AES-CBC encryption with a hardcoded IV: b'urfuckedmogambro'.
  - Saves the key in a temporary file (C:\Users\MogamBro\AppData\Local\Temp\).
- **Recovery:** Found the key in temporary file tmpd1tif_2a, converted it to hex, and decrypted the secret.png.enc file.

### 6. Email Analysis & Steganography
- **Artifacts:** Outlook email files in Documents.
- **Phishing:** One email was a lottery phishing attempt directing the user to the malicious zip/exe.
- **Steganography:** Another email contained "spammy" text that appeared random.
- **Tool:** Used SpamMimic decoder to reveal the hidden message and the flag.

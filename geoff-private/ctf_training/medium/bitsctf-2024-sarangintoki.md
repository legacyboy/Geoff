# BITSCTF 2024 Writeup - SaranGintoki

## Challenge 1: GEDCOM Analysis
- Artifact: .ged file.
- Tool: drawmyfamilytree.co.uk / Family Tree Builder.
- Method: Search for keywords like "murder", "killed". Cross-verified birth dates and living status of suspects.
- Flag: BITSCTF{Henriette}

## Challenge 2: WinRAR Exploit
- Method: Volatility analysis identified WinRAR as the vulnerable software.
- CVE: CVE-2023-38831.
- Flag: BITSCTF{CVE-2023-38831}

## Challenge 3: USB Keystroke Recovery
- Artifact: keylog.pcapng.
- Tool: Wireshark / Python script.
- Filter: usb.transfer_type == 0x01 && usb.dst == "host" && !(usb.capdata == 00:00:00:00:00:00:00:00)
- Flag: BITSCTF{I_7h1nk_th3y_4Re_k3yl0991ng_ME!}

## Challenge 4: Email Analysis & SpamMimic
- Artifact: Email files.
- Finding: One email contained a payload, the other appeared as a spam message.
- Tool: SpamMimic decoder.
- Flag: BITSCTF{sp4m_2_ph1sh_U}

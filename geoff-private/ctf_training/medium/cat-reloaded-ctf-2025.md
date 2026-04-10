# CAT Reloaded CTF — CATF 2025–DFIR Challenges

## Challenge 1: Index of Secrets
- **Objective:** Fetch Windows search database.
- **Path:** C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
- **Tool:** Win Search DB Analyzer
- **Finding:** flag.txt.txt at C:\Users\wh1pl4sh\Desktop\flag.txt.txt
- **Flag:** CATF{ESE_DB_F0r3ns1cs}

## Challenge 2: Loser
- **Objective:** Investigate disk for game crack logs.
- **Path:** C\Windows\AppCompat\pca
- **Files:** PcaAppLaunchDic.txt, PcaGeneralDb0.txt, PcaGeneralDb1.txt
- **Flag Construction:** Path + run status + last execution time.
- **Flag:** CATF{C:\Users\t0orf3n\AppData\Local\Temp\GreenHell.crack.exe_3_2025-07-12 13:34:17.726}

## Challenge 3: Dead Icons Speak
- **Objective:** Recover flag from icon/thumbnail cache.
- **Path:** C:\Users\<user>\AppData\Local\Microsoft\Windows\Explorer\iconcache_xx.db
- **Tool:** Thumbcache Viewer
- **Finding:** Flag found in iconcache_256.db. Also found 'flagstealer.exe' on wh1pl4sh's desktop via FTK Imager and MPLog-20250704-153812.log.
- **Flag:** CATF{flagstealer.exe:thumbn41l_pwn}

## Challenge 4: Erased Traces
- **Objective:** Recover 4 deleted files and combine them.
- **Tools:** FTK Imager, Arsenal Image Mounter, Disk Drill, HxD.
- **Method:** Carved 4 files (CAT1-CAT4). Identified as parts of a single PDF.
- **Command to combine:** Get-Content CAT1, CAT2, CAT3, CAT4 -Encoding Byte -ReadCount 0 | Set-Content combined.pdf -Encoding Byte
- **Flag:** CATF{whip1@!}

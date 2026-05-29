#!/usr/bin/env python3
"""Check M57 downloads, start investigation when complete."""
import subprocess, sys, time

def ssh(cmd):
    return subprocess.run(["ssh", "-p", "2222", "-o", "BatchMode=yes",
                           "sansforensics@localhost", cmd],
                          capture_output=True, text=True, timeout=60)

# 1. Ensure NAS is mounted
ssh("sudo mount /mnt/nas 2>/dev/null || true")

# 2. Check wgets
result = ssh("ps aux | grep wget | grep -v grep | wc -l")
wgets = int(result.stdout.strip() or 0)

if wgets > 0:
    print(f"{wgets} wgets still running - not yet")
    sys.exit(0)

# 3. Ensure Geoff is running
result = ssh("curl -s -m 5 http://localhost:8080/health 2>/dev/null || echo 'DOWN'")
if "DOWN" in result.stdout:
    print("Geoff was down - starting it...")
    ssh("cd /home/sansforensics/Geoff && nohup ./scripts/run_geoff.sh > /tmp/geoff.log 2>&1 &")
    time.sleep(30)

# 4. Start investigation
print("Starting M57 Patents investigation...")
result = ssh("curl -s -X POST http://localhost:8080/find-evil "
             "-H 'Content-Type: application/json' "
             "-d '{\"evidence_dir\": \"/mnt/nas/m57-patents\"}'")
print(result.stdout)

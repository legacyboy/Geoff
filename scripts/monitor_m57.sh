#!/bin/bash
# Monitor M57 investigation - auto-restart on crash
JOB_ID="fe-0a628c9db914"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

RESULT=$(ssh -p 2222 -o BatchMode=yes -o ConnectTimeout=15 sansforensics@localhost "curl -s -m 10 'http://localhost:8080/find-evil/status/$JOB_ID'" 2>/dev/null)

if [ -z "$RESULT" ]; then
    echo "[$TIMESTAMP] Geoff API unreachable - restarting Geoff"
    ssh -p 2222 -o BatchMode=yes sansforensics@localhost 'fuser -k 8080/tcp 2>/dev/null; sleep 2; cd /home/sansforensics/Geoff && find . -name __pycache__ -exec rm -rf {} + 2>/dev/null && nohup python3 src/geoff_integrated.py > /tmp/geoff.log 2>&1 &' 2>/dev/null
    sleep 45
    JOB=$(ssh -p 2222 -o BatchMode=yes sansforensics@localhost "curl -s -m 10 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/mnt/nas/m57-patents\"}'" 2>/dev/null)
    NEW_ID=$(echo "$JOB" | python3 -c "import sys,json; d=json.load(sys.stdin) if sys.stdin.read(1) else {}; print(d.get('job_id','fe-unknown'))" 2>/dev/null)
    if [ -n "$NEW_ID" ]; then
        sed -i "s/JOB_ID=.*/JOB_ID=\"$NEW_ID\"/" "$0"
        echo "[$TIMESTAMP] Auto-restarted: $NEW_ID"
    fi
    exit 0
fi

STATUS=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null)
PLAYBOOK=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('current_playbook','?'))" 2>/dev/null)
STEP=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('current_step','?'))" 2>/dev/null)
ELAPSED=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('elapsed_seconds',0))" 2>/dev/null)
PROGRESS=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('progress_pct',0))" 2>/dev/null)
ERROR=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('error',''))" 2>/dev/null)

echo "[$TIMESTAMP] $STATUS | $PLAYBOOK/$STEP | ${ELAPSED}s | ${PROGRESS}%"

# Auto-heal on crash
if [ "$STATUS" = "complete" ] && [ -n "$ERROR" ]; then
    echo "[$TIMESTAMP] CRASHED: $ERROR - restarting investigation"
    ssh -p 2222 -o BatchMode=yes sansforensics@localhost 'fuser -k 8080/tcp 2>/dev/null; sleep 2; cd /home/sansforensics/Geoff && find . -name __pycache__ -exec rm -rf {} + 2>/dev/null && nohup python3 src/geoff_integrated.py > /tmp/geoff.log 2>&1 &' 2>/dev/null
    sleep 50
    JOB=$(ssh -p 2222 -o BatchMode=yes sansforensics@localhost "curl -s -m 10 -X POST http://localhost:8080/find-evil -H 'Content-Type: application/json' -d '{\"evidence_dir\": \"/mnt/nas/m57-patents\"}'" 2>/dev/null)
    NEW_ID=$(echo "$JOB" | python3 -c "import sys,json; d=json.load(sys.stdin) if sys.stdin.read(1) else {}; print(d.get('job_id','fe-unknown'))" 2>/dev/null)
    if [ -n "$NEW_ID" ]; then
        sed -i "s/JOB_ID=.*/JOB_ID=\"$NEW_ID\"/" "$0"
        echo "[$TIMESTAMP] Auto-healed: $NEW_ID"
    fi
fi

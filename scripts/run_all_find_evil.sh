#!/bin/bash
# Run Find Evil on all evidence directories sequentially
# Uses local models (deepseek-r1:32b, qwen2.5-coder:14b, qwen2.5:14b)
set -e

BASE_URL="http://localhost:8080"
EVIDENCE_BASE="/home/sansforensics/evidence-storage/evidence"

# All evidence directories (excluding solutions)
CASES=(
    "hacking-case"
    "data-leakage-case"
    "rhino-hunt"
    "registry-forensics"
    "memory-images"
    "mobile-android13"
    "mobile-android14"
    "mobile-chipoff"
    "mobile-ios16"
    "mobile-ios17"
)

echo "=== Find Evil Runner ==="
echo "Starting at: $(date)"
echo "Evidence base: $EVIDENCE_BASE"
echo "Cases: ${#CASES[@]}"
echo ""

# Verify Geoff is running
if ! curl -s "$BASE_URL/" > /dev/null 2>&1; then
    echo "ERROR: Geoff is not running on $BASE_URL"
    exit 1
fi

echo "Geoff is running. Starting Find Evil runs..."
echo ""

for CASE in "${CASES[@]}"; do
    EVIDENCE_PATH="$EVIDENCE_BASE/$CASE"
    
    if [ ! -d "$EVIDENCE_PATH" ]; then
        echo "SKIP: $CASE - directory not found"
        continue
    fi
    
    echo "============================================"
    echo "Starting Find Evil: $CASE"
    echo "Path: $EVIDENCE_PATH"
    echo "Time: $(date)"
    echo "============================================"
    
    # Start Find Evil job (no auth required)
    RESPONSE=$(curl -s -X POST "$BASE_URL/find-evil" \
        -H "Content-Type: application/json" \
        -d "{\"evidence_dir\": \"$EVIDENCE_PATH\"}")
    
    JOB_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('job_id',''))" 2>/dev/null || echo "")
    
    if [ -z "$JOB_ID" ]; then
        echo "ERROR: Failed to start job for $CASE"
        echo "Response: $RESPONSE"
        continue
    fi
    
    echo "Job ID: $JOB_ID"
    
    # Poll for completion (max 2 hours per case)
    MAX_WAIT=7200
    ELAPSED=0
    INTERVAL=30
    
    while [ $ELAPSED -lt $MAX_WAIT ]; do
        sleep $INTERVAL
        ELAPSED=$((ELAPSED + INTERVAL))
        
        STATUS=$(curl -s "$BASE_URL/find-evil/status/$JOB_ID" 2>/dev/null)
        
        JOB_STATUS=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
        PROGRESS=$(echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('progress',''), d.get('steps_completed',''), '/', d.get('steps_total',''))" 2>/dev/null || echo "")
        
        echo "  [$CASE] Status: $JOB_STATUS | Progress: $PROGRESS | Elapsed: ${ELAPSED}s"
        
        if [ "$JOB_STATUS" = "completed" ] || [ "$JOB_STATUS" = "complete" ]; then
            echo "COMPLETED: $CASE"
            break
        elif [ "$JOB_STATUS" = "failed" ] || [ "$JOB_STATUS" = "error" ]; then
            echo "FAILED: $CASE"
            break
        fi
    done
    
    if [ $ELAPSED -ge $MAX_WAIT ]; then
        echo "TIMEOUT: $CASE (exceeded ${MAX_WAIT}s)"
    fi
    
    echo ""
done

echo "============================================"
echo "All Find Evil runs complete."
echo "Finished at: $(date)"
echo "============================================"
#!/usr/bin/env bash
# Geoff Continuous QA - Simulates scenarios and records shortcomings
# Runs every 15 minutes via cron
# Usage: bash /home/claw/.openclaw/workspace/projects/Geoff/scripts/qa_runner.sh

QA_FILE="/home/claw/.openclaw/workspace/projects/Geoff/QA_RESULTS.md"
SSH="ssh -p 2222 sansforensics@localhost"
CURL="curl -s -m 120"
GEOFF="http://localhost:8080"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')

# Pick a random scenario type
SCENARIOS=(
  "single_dd_image"
  "e01_segments"
  "empty_directory"
  "missing_evidence"
  "path_traversal"
  "command_injection"
  "chat_forensic_question"
  "chat_tool_request"
  "individual_specialist"
  "concurrent_jobs"
  "report_analysis"
  "edge_case_non_image"
  "allowlist_bypass"
)

SCENARIO=${SCENARIOS[$RANDOM % ${#SCENARIOS[@]}]}

echo "" >> "$QA_FILE"
echo "---" >> "$QA_FILE"
echo "## QA Run: $TIMESTAMP — Scenario: $SCENARIO" >> "$QA_FILE"

run_and_record() {
  local name="$1" cmd="$2"
  local result
  result=$(eval "$cmd" 2>&1)
  local exit_code=$?
  echo "### $name" >> "$QA_FILE"
  echo "- **Command:** \`$cmd\`" >> "$QA_FILE"
  echo "- **Exit code:** $exit_code" >> "$QA_FILE"
  echo "- **Result:** ${result:0:500}" >> "$QA_FILE"
  echo "" >> "$QA_FILE"
  echo "$result"
}

case "$SCENARIO" in
  single_dd_image)
    # Pick a random DD image
    IMAGE=$($SSH "ls /home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.00*" 2>/dev/null | shuf -n 1)
    if [ -n "$IMAGE" ]; then
      run_and_record "Find Evil on single DD image" \
        "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"$(dirname $IMAGE)\\\"}'\""
    else
      echo "- **SKIPPED:** No DD images found" >> "$QA_FILE"
    fi
    ;;

  e01_segments)
    E01_DIR="/home/sansforensics/evidence-storage/evidence/data-leakage-case"
    run_and_record "Find Evil on E01 segments" \
      "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"$E01_DIR\\\"}'\""
    ;;

  empty_directory)
    $SSH "mkdir -p /tmp/qa_empty_$RANDOM" 2>/dev/null
    run_and_record "Find Evil on empty directory" \
      "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"/tmp/qa_empty_*\\\"}'\""
    ;;

  missing_evidence)
    run_and_record "Find Evil on non-existent path" \
      "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"/nonexistent/path/xyz123\\\"}'\""
    ;;

  path_traversal)
    run_and_record "Path traversal attempt" \
      "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"../../../etc/passwd\\\"}'\""
    run_and_record "Path traversal via run-tool" \
      "$SSH \"$CURL -X POST $GEOFF/run-tool -H 'Content-Type: application/json' -d '{\\\"module\\\": \\\"sleuthkit\\\", \\\"function\\\": \\\"list_files\\\", \\\"params\\\": {\\\"image\\\": \\\"/etc/shadow\\\"}}'\""
    ;;

  command_injection)
    run_and_record "Command injection in evidence_dir" \
      "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"/tmp; cat /etc/passwd\\\"}'\""
    run_and_record "Command injection via pipe" \
      "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"/tmp | id\\\"}'\""
    ;;

  chat_forensic_question)
    QUESTIONS=(
      "What artifacts indicate persistence on Windows?"
      "How do I detect timestomping?"
      "What is the difference between mmls and fsstat?"
      "Explain the MITRE ATT&CK kill chain"
      "What IOCs should I look for in a ransomware case?"
    )
    Q="${QUESTIONS[$RANDOM % ${#QUESTIONS[@]}]}"
    run_and_record "Chat: forensic question" \
      "$SSH \"$CURL -X POST $GEOFF/chat -H 'Content-Type: application/json' -d '{\\\"message\\\": \\\"$Q\\\"}'\""
    ;;

  chat_tool_request)
    run_and_record "Chat: tool request" \
      "$SSH \"$CURL -X POST $GEOFF/chat -H 'Content-Type: application/json' -d '{\\\"message\\\": \\\"Run mmls on the hacking case evidence\\\"}'\""
    ;;

  individual_specialist)
    # Test a random specialist method
    METHODS=("analyze_partition_table" "analyze_filesystem" "list_files" "list_deleted" "list_files_mactime")
    IMAGES=$($SSH "ls /home/sansforensics/evidence-storage/evidence/hacking-case/SCHARDT.001" 2>/dev/null)
    METHOD="${METHODS[$RANDOM % ${#METHODS[@]}]}"
    if [ -n "$IMAGES" ]; then
      if [ "$METHOD" = "analyze_partition_table" ]; then
        PARAMS="{\\\"disk_image\\\": \\\"$IMAGES\\\"}"
      else
        PARAMS="{\\\"image\\\": \\\"$IMAGES\\\", \\\"offset\\\": 0}"
      fi
      run_and_record "Specialist: sleuthkit.$METHOD" \
        "$SSH \"$CURL -X POST $GEOFF/run-tool -H 'Content-Type: application/json' -d '{\\\"module\\\": \\\"sleuthkit\\\", \\\"function\\\": \\\"$METHOD\\\", \\\"params\\\": $PARAMS}'\""
    fi
    ;;

  concurrent_jobs)
    # Start 3 find-evil jobs simultaneously
    run_and_record "Concurrent job 1 (hacking case)" \
      "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"/home/sansforensics/evidence-storage/evidence/hacking-case\\\"}'\""
    run_and_record "Concurrent job 2 (data leakage)" \
      "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"/home/sansforensics/evidence-storage/evidence/data-leakage-case\\\"}'\""
    run_and_record "Concurrent job 3 (full evidence dir)" \
      "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"/home/sansforensics/evidence-storage/evidence\\\"}'\""
    ;;

  report_analysis)
    # Find and analyze the most recent report
    LATEST=$($SSH "find /home/sansforensics/evidence-storage/cases/ -name 'find_evil_report.json' -newer /tmp -type f 2>/dev/null | head -1")
    if [ -n "$LATEST" ]; then
      run_and_record "Report analysis" \
        "$SSH \"python3 -c \\\"
import json
with open('$LATEST') as f:
    r = json.load(f)
print(f'Severity: {r.get(\\\"severity\\\",\\\"?\\\")}')
print(f'Steps: {r.get(\\\"steps_completed\\\",0)} ok, {r.get(\\\"steps_failed\\\",0)} fail')
print(f'device_map: {len(r.get(\\\"device_map\\\",{}))} entries')
print(f'user_map: {len(r.get(\\\"user_map\\\",{}))} entries')
print(f'Narrative: {\\\"yes\\\" if r.get(\\\"narrative_report_path\\\") else \\\"MISSING\\\"}')
print(f'Playbooks: {r.get(\\\"playbooks_total\\\",0)}')
\\\"\""
    else
      echo "- **SKIPPED:** No recent reports found" >> "$QA_FILE"
    fi
    ;;

  edge_case_non_image)
    $SSH "echo 'this is not an image' > /tmp/fake_evidence_$RANDOM.img" 2>/dev/null
    run_and_record "Find Evil on non-image file" \
      "$SSH \"$CURL -X POST $GEOFF/find-evil -H 'Content-Type: application/json' -d '{\\\"evidence_dir\\\": \\\"/tmp\\\"}'\""
    ;;

  allowlist_bypass)
    # Try various dangerous tools
    run_and_record "Allowlist: bash bypass" \
      "$SSH \"$CURL -X POST $GEOFF/run-tool -H 'Content-Type: application/json' -d '{\\\"module\\\": \\\"sleuthkit\\\", \\\"function\\\": \\\"list_files\\\", \\\"params\\\": {\\\"image\\\": \\\"/etc/passwd\\\", \\\"tool\\\": \\\"bash\\\", \\\"args\\\": [\\\"-c\\\", \\\"id\\\"]}}'\""
    run_and_record "Allowlist: python bypass" \
      "$SSH \"$CURL -X POST $GEOFF/run-tool -H 'Content-Type: application/json' -d '{\\\"module\\\": \\\"sleuthkit\\\", \\\"function\\\": \\\"list_files\\\", \\\"params\\\": {\\\"image\\\": \\\"/etc/passwd\\\", \\\"tool\\\": \\\"python3\\\", \\\"args\\\": [\\\"-c\\\", \\\"import os; os.system('id')\\\"]}}'\""
    ;;

esac

# Always check if Geoff is still responsive
HEALTH=$($SSH "$CURL -o /dev/null -w '%{http_code}' $GEOFF/" 2>/dev/null)
if [ "$HEALTH" != "200" ]; then
  echo "### ⚠️ GEOFF HEALTH CHECK FAILED" >> "$QA_FILE"
  echo "- HTTP status: $HEALTH" >> "$QA_FILE"
  echo "- Attempting restart..." >> "$QA_FILE"
  $SSH "pkill -f 'python src/geoff_integrated.py' 2>/dev/null; sleep 2; cd /home/sansforensics/Geoff && source venv/bin/activate && set -a && source .env && set +a && nohup python src/geoff_integrated.py > /tmp/geoff_restart.log 2>&1 &" 2>/dev/null
  sleep 5
  NEW_HEALTH=$($SSH "$CURL -o /dev/null -w '%{http_code}' $GEOFF/" 2>/dev/null)
  echo "- Restart result: HTTP $NEW_HEALTH" >> "$QA_FILE"
fi

echo "QA run complete: $TIMESTAMP — $SCENARIO"
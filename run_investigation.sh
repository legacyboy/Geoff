#!/bin/bash
# Run investigation with automatic resume
# Usage: ./run_investigation.sh <investigation_id> [step|run|status]

INVESTIGATION_ID="${1:-3EB03F77A9E6E641FCD2FE}"
ACTION="${2:-run}"

echo "=========================================="
echo "INVESTIGATION RUNNER: $INVESTIGATION_ID"
echo "Action: $ACTION"
echo "=========================================="

# Run the planner
python3 investigation_planner.py "$INVESTIGATION_ID" "$ACTION"

echo ""
echo "Investigation state saved to: investigation_${INVESTIGATION_ID}_state.json"
echo "Resume anytime with: ./run_investigation.sh $INVESTIGATION_ID"

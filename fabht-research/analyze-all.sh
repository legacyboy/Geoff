#!/bin/bash
# Thorough Chrome vulnerability analysis
# Analyzes all critical components

SAMPLES_DIR="/home/claw/.openclaw/workspace/fabht-research/samples-thorough"
FINDINGS_DIR="/home/claw/.openclaw/workspace/fabht-research/findings"

mkdir -p "$FINDINGS_DIR"

echo "=== CHROME VRP THOROUGH ANALYSIS ==="
echo "Date: $(date)"
echo ""

for file in "$SAMPLES_DIR"/*.cc; do
    filename=$(basename "$file")
    echo "Analyzing: $filename"
    
    # Run deepseek-v3.2 analysis
    ollama run deepseek-v3.2:cloud "Analyze this Chromium source file for vulnerabilities:

File: $filename

Look for:
1. Memory safety issues (UAF, buffer overflow, integer overflow)
2. Type confusion bugs
3. Logic errors in security-critical paths
4. Improper input validation
5. Race conditions

Code (first 200 lines):
$(head -200 "$file")

Report any findings with:
- Vulnerability type
- Severity (Critical/High/Medium/Low)
- Location in code
- Whether exploitable" 2>/dev/null > "$FINDINGS_DIR/analysis-${filename%.cc}.txt"
    
    echo "  -> Saved to analysis-${filename%.cc}.txt"
done

echo ""
echo "Analysis complete. Review findings in: $FINDINGS_DIR/"

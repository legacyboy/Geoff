#!/bin/bash
# Start Claude Code for vulnerability research on Chromium

cd ~/chromium/src 2>/dev/null || cd /home/claw/.openclaw/workspace

# Claude will analyze the codebase
claude "You are a vulnerability researcher analyzing Chromium source for exploitable bugs. 

Your task:
1. Review the V8 TurboFan compiler code in src/compiler/
2. Look for type confusion, UAF, and logic errors in JIT compilation
3. Check src/parsing/ for parser vulnerabilities
4. Analyze src/heap/ for GC bugs

Focus on finding real exploitable vulnerabilities that could lead to RCE.
Save your findings to ~/chromium/findings/claude-analysis.txt

Start by listing the most security-critical files in src/compiler/" \
| tee /home/claw/.openclaw/workspace/claude-research/session.log

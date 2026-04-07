# DFIR CTF Learning Task for Geoff

## Objective
Process DFIR CTF challenges and writeups to extract lessons, techniques, and patterns. Feed these to Geoff's learning system.

## Sources to Process
1. https://prankstar99.medium.com/cat-reloaded-ctf-catf-2025-dfir-challenges-ff403f100504
2. https://medium.com/@LoaySalah/connectors-ctf-2025-dfir-challenges-6d66c31cce9a
3. https://mahmoud-shaker.gitbook.io/dfir-notes/tnkr.2-challenge-eg-ctf-2025-forensics-write-up
4. https://github.com/warlocksmurf/onlinectf-writeups/blob/main/BITSCTF24/dfir.md
5. https://cellebrite.com/en/i-beg-to-dfir-episode-30-decoding-ctf-2024/
6. https://0xsh3rl0ck.github.io/ctf-writeup/Africa-DFIR-2021-CTF-Week-2/
7. https://medium.com/@ahmedkhalifa8474hh/ctf-cit-dfir-write-ups-494e4fc00f13
8. https://medium.com/@SaranGintoki/bits-ctf-2024-writeup-eecc3c1a9219
9. https://github.com/teambi0s/bi0sCTF
10. https://github.com/tim-barc/ctf_writeups
11. https://github.com/Mohammadalmousawe/Cyberdefenders-LABs-Write-UP
12. https://github.com/Haalloobim/Cyber-Defender-Labs-WriteUp
13. https://github.com/Panagiotis-INS/Cyber-Defenders
14. https://github.com/th3c0rt3x/CyberDefenders
15. https://github.com/1d8/ctf
16. https://github.com/Y2d1337/CyberDefenders.org
17. https://aboutdfir.com/education/challenges-ctfs/
18. https://ctftime.org/
19. https://tthtlc.wordpress.com/2021/06/08/top-100-forensics-writeups/

## For Each Source:
1. Fetch and read the content
2. Extract key DFIR techniques and methodologies
3. Identify tools used and their applications
4. Note common attack patterns and indicators
5. Document lessons learned and "gotchas"
6. Extract specific command examples
7. Identify memory forensics techniques
8. Note network analysis methods
9. Document disk forensics approaches
10. Extract file system analysis techniques

## Output Format
For each processed source, append to `/home/claw/.openclaw/workspace/memory/dfir_learning_2026-04-05.md`:

```markdown
## Source: [URL]
### Key Techniques
- [Technique 1]
- [Technique 2]

### Tools Used
- [Tool]: [Purpose]

### Lessons Learned
- [Lesson 1]
- [Lesson 2]

### Commands/Examples
```
[Command]
```

### Geoff Application
- How this applies to future investigations
```

## Critical Rules
- DO NOT stop if a URL fails — move to next
- DO NOT wait for user approval — process continuously
- If content is too large, extract key sections
- Focus on actionable techniques Geoff can use
- Prioritize memory forensics and network analysis lessons

## Status Tracking
Track progress at `/home/claw/.openclaw/workspace/memory/dfir_learning_progress.json`:
{
  "started": "2026-04-05T19:06:00Z",
  "sources_total": 19,
  "sources_processed": 0,
  "last_processed": null,
  "errors": []
}

# SANS Holiday Hack Challenge 2025 - Reconnaissance Summary

## Executive Summary
The SANS Holiday Hack Challenge 2025 "Revenge of the Gnome(s)" is a sophisticated browser-based CTF platform. Initial reconnaissance reveals a React SPA with WebSocket communication, multiple game areas, and a complex challenge system.

## Key Discoveries

### 1. Site Architecture
- **URL**: https://2025.holidayhackchallenge.com/
- **Type**: React Single Page Application with Redux state management
- **WebSocket**: wss://2025.holidayhackchallenge.com/ws (for real-time features)
- **Auth**: External OAuth via account.counterhack.com

### 2. Game World Structure
The challenge features a virtual world with multiple locations:
- **entry** - Starting area
- **city** - Main city area (37 references in code)
- **hotel** - Hotel location
- **train** - Transportation area
- **elfhouse** - Elf residence
- **grotto** - Grotto location
- **island** - Island area
- **santa** - Santa-related areas (23 references)

### 3. Challenge System Components
- **Badge System**: Tracks achievements, hints, items, objectives, tokens
- **Terminals**: Interactive challenge access points
- **NPCs**: Dialog system for hints and story
- **Treasure Chests**: Additional challenge mechanics
- **Objectives**: Main challenge tracking

### 4. Interesting Findings
From code analysis, discovered potential easter eggs/references:
- `DENNIS_NEDRY` - Jurassic Park reference (character)
- `MAGIC_WORD` - Game mechanic
- `GOT_COINS` - Scoring system
- Various action types and game state constants

### 5. API Endpoints
- `/ws` - WebSocket for real-time communication
- `/api/` - API root (requires auth)
- Various static asset endpoints for images, audio, video

### 6. Authentication Requirements
To access challenges, need to:
1. Register at https://account.counterhack.com?ref=hhc25
2. Complete profile setup (avatar, country, etc.)
3. Accept Terms of Service
4. Authenticate via OAuth callback

## Current Status
**Blocked**: Cannot access challenge content without authentication. The site is a React SPA that requires:
- Valid session token
- WebSocket connection with auth
- Profile completion

## Recommendation
To proceed with solving challenges, we need:
1. Valid credentials for account.counterhack.com
2. OR manual navigation through a browser with JavaScript execution

## Files Created
- `/notes/recon.md` - Technical reconnaissance notes
- `/notes/found_endpoints.md` - Endpoint documentation
- `/reports/initial_recon_report.md` - Detailed technical report
- `/reports/recon_summary.md` - This summary
- `/loot/` - Directory for flags (empty)

## Tools Available for Further Work
Once authenticated, can use:
- curl/wget for HTTP requests
- Python with requests/BeautifulSoup
- WebSocket clients
- Standard Kali Linux pentesting tools
- Browser automation if needed

## Challenge Topics Expected
Per task description, challenges cover:
- IOCs, SUDO, forensics, networking
- Nmap, cURL, IDOR, POCs
- Java deserialization, quantum computing
- Reverse engineering, SQL injection
- Linux Privilege Escalation
- Web Application pentesting

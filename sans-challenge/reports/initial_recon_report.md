# SANS Holiday Hack Challenge 2025 - Initial Reconnaissance Report

## Executive Summary
The SANS Holiday Hack Challenge 2025 "Revenge of the Gnome(s)" is a sophisticated browser-based CTF platform built as a React single-page application (SPA). It features a virtual world where participants navigate through various locations, interact with NPCs, and solve security challenges.

## Site Architecture

### Core Technology Stack
- **Frontend**: React SPA with Redux state management
- **Communication**: WebSocket (wss://2025.holidayhackchallenge.com/ws)
- **Authentication**: External OAuth via account.counterhack.com
- **Styling**: CSS with custom 3D rendering for game world

### Key URLs
| Resource | URL |
|----------|-----|
| Main Site | https://2025.holidayhackchallenge.com/ |
| WebSocket | wss://2025.holidayhackchallenge.com/ws |
| Auth Portal | https://account.counterhack.com?ref=hhc25 |
| Main JS Bundle | /js/main/christmasmagic.js |
| Music | https://www.holidayhackchallenge.com/2025/music/ |

## Game World Structure

### Locations Discovered
1. **entry** - Starting area (appears 20 times in code)
2. **city** - Main city area with buildings (37 references)
3. **hotel** - Hotel location (8 references)
4. **train** - Train/transportation area
5. **elfhouse** - Elf residence
6. **grotto** - Grotto location
7. **island** - Island area
8. **workshop** areas
9. **santa** - Santa-related areas (23 references)

### Building Types Found
- townhall, hotel, retroshop, apartments
- convenience store, datacenter
- booths: microsoft, sans, swag, google, rsac, amazon

## Challenge System

### Badge System Components
- `badgeachievement` - Achievement tracking
- `badgehint` - Hints for challenges
- `badgeitem` - Item collection
- `badgeobjective` - Objective completion
- `badgeproxmark` - Proxmark-related
- `badgetoken` - Token collection
- `badgetokenadmin` - Admin tokens

### Challenge Types Mentioned
- Terminal-based challenges (iframes)
- NPC dialog challenges
- Treasure chest challenges
- Location-based objectives

### Key UI Routes
```
/                      - Home/entry
/badge                 - Badge/profile
/badge?section=home    - Home section
/badge?section=map    - Map view
/badge?section=objective - Objectives
/badge?section=talk   - Talks section
/badge?section=conversation - NPC conversations
```

## Authentication Requirements

### Registration Flow
1. Users must register at account.counterhack.com
2. Account requires: email, username, password
3. Country selection (GDPR compliance)
4. Terms of Service acceptance
5. Optional: GDPR document acceptance

### Session Management
- Uses "chimney" token for authentication
- WebSocket connections require valid session
- Avatar customization available

## Features Discovered

### Game Features
- **3D Isometric View**: Camera with rotation controls
- **NPC Interaction**: Dialog system with voice acting
- **Multiplayer**: Real-time player presence via WebSocket
- **Chat System**: Area chat and private whispers
- **Inventory/Items**: Collectible items system
- **Progress Tracking**: Token-based achievement system

### Technical Features
- **Audio**: Sound effects and music system
- **Video**: Embedded YouTube talks
- **3D Assets**: Custom rendered rooms and objects
- **Mobile Support**: Touch/pointer event handling

## Security Observations

### Access Controls
- API endpoints return 403 without authentication
- WebSocket requires upgrade and authentication
- Static assets (images, audio) have directory listing disabled

### Potential Attack Vectors (to explore)
1. WebSocket message injection
2. Challenge iframe sandbox escape
3. NPC dialog/command injection
4. Token/cookie manipulation
5. API endpoint enumeration

## Tools and Resources Available

### Challenge Topics Mentioned
Based on the task description, challenges cover:
- IOCs (Indicators of Compromise)
- SUDO privilege escalation
- Forensics
- Networking (Nmap, cURL)
- IDOR vulnerabilities
- POCs (Proof of Concept)
- Java deserialization
- Quantum computing
- Reverse engineering
- SQL Injection
- Linux Privilege Escalation
- Web Application pentesting

## Next Steps Required

### Immediate Needs
1. **Authentication**: Need valid credentials to access challenges
2. **Account Creation**: Register at account.counterhack.com
3. **Avatar Setup**: Customize player avatar

### Exploration Plan
1. Navigate the virtual world map
2. Interact with NPCs for challenge hints
3. Access terminals for technical challenges
4. Complete objectives and collect tokens
5. Solve micro-challenges (10-15 min each)
6. Attempt capstone challenges

## Files Created
- `/notes/recon.md` - Initial reconnaissance notes
- `/notes/found_endpoints.md` - Discovered endpoints
- `/reports/initial_recon_report.md` - This report

## Loot/Flags Directory
Created `/loot/` directory for storing flags and credentials as they are discovered.

## Conclusion
The SANS Holiday Hack Challenge 2025 is a feature-rich, gamified CTF platform. It requires authentication to access challenges, but the reconnaissance phase has successfully mapped out the application structure, identified key components, and prepared the groundwork for systematic challenge solving.

**Status**: Awaiting authentication credentials to proceed with challenge access.

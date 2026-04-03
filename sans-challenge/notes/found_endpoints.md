# Discovered Endpoints and Resources

## Main Site
- **URL**: https://2025.holidayhackchallenge.com/

## WebSocket
- **Endpoint**: /ws (WebSocket connection)

## External Resources
- https://account.counterhack.com?ref=hhc25 (Authentication)
- https://www.holidayhackchallenge.com/2025/music (Music)
- https://www.youtube.com/embed (Video embeds)

## File Structure
- `/js/main/christmasmagic.js` - Main React application bundle
- `/data/gdpr.js` - Country data
- `/data/condata.js` - Country/region mapping
- `/css/all.css` - Stylesheets
- `/images/` - Image assets
- `/video/` - Video assets
- `/audio/` - Audio assets

## Key Findings from JS Analysis
1. **Game Mode**: Supports "ctf" mode (Capture The Flag)
2. **Badge System**: Multiple badge types (objective, hint, item, token, etc.)
3. **NPCs**: Dialog system with multiple NPCs
4. **Scenes**: Different areas/rooms (city, hotel, train, etc.)
5. **Terminals**: Interactive terminals for challenges
6. **Challenges**: Challenge URL system for external challenges
7. **WebSocket**: Real-time communication for multiplayer aspects

## Routes Found
- `/` - Home/entry
- `/badge` - Badge/profile view
- `/badge?section=home` - Home section
- `/badge?section=map` - Map view
- `/badge?section=objective` - Objectives
- `/badge?section=talk` - Talks section

## Authentication
- Requires registration at account.counterhack.com
- Uses chimney token for authentication
- Session-based authentication

## To Do
- Need to register/login to access challenges
- WebSocket connection requires authentication
- Badge system tracks progress

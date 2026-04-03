# SANS Holiday Hack Challenge 2025 - Reconnaissance

## Site Structure
- **URL:** https://2025.holidayhackchallenge.com/
- **Type:** Single-page React application
- **Theme:** "Revenge of the Gnome(s)"

## Resources Found
1. **Main JS:** `/js/main/christmasmagic.js` - React application bundle
2. **GDPR Data:** `/data/gdpr.js` - Country data for registration
3. **Country Data:** `/data/condata.js` - Country/region mapping
4. **CSS:** `/main.cd05c409c9dcab5d26b5.css`

## Initial Observations
- The site loads a React SPA (Single Page Application)
- Content is rendered dynamically via JavaScript
- No direct HTML content for challenges visible without JS execution
- Likely requires authentication/registration to access challenges

## Next Steps
1. Need to explore the JavaScript bundle for API endpoints
2. Check for challenge data in the JS files
3. Look for hidden endpoints or files
